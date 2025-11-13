"""
vocalyx-api/app.py
Point d'entrée principal de l'API centrale
"""

import logging
import asyncio
import aioredis
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import Config
from database import Base, engine
from celery_app import celery_app, get_celery_stats

from api.endpoints import router as api_router, auth_router, admin_router, ws_router
# --- CORRECTION ---
from api.websocket_manager import ConnectionManager, manager
# --- FIN CORRECTION ---
from logging_config import setup_logging, setup_colored_logging

# Initialiser la configuration
config = Config()

# Configurer le logging
if config.log_colored:
    logger = setup_colored_logging(
        log_level=config.log_level,
        log_file=config.log_file_path if config.log_file_enabled else None
    )
else:
    logger = setup_logging(
        log_level=config.log_level,
        log_file=config.log_file_path if config.log_file_enabled else None
    )

# Créer toutes les tables
Base.metadata.create_all(bind=engine)

# --- TÂCHES DE FOND (WEBSOCKETS) ---

async def redis_pubsub_listener(redis_sub, manager: ConnectionManager):
    """Tâche de fond: Écoute Redis Pub/Sub et diffuse aux WebSockets."""
    try:
        await redis_sub.subscribe("vocalyx_updates")
        logger.info("📡 Abonné au canal Redis 'vocalyx_updates'")
        async for message in redis_sub.listen():
            if message["type"] == "message":
                logger.info("📬 Message Pub/Sub reçu, diffusion...")
                await manager.broadcast({"type": "transcription_update"})
    except asyncio.CancelledError:
        logger.info("🛑 Tâche Pub/Sub annulée.")
    except Exception as e:
        logger.error(f"❌ Erreur critique Pub/Sub: {e}", exc_info=True)
    finally:
        logger.info("Redis Pub/Sub listener arrêté.")

async def periodic_worker_stats(app_state, manager: ConnectionManager):
    """Tâche de fond: Polling des stats workers et diffusion aux WebSockets."""
    while True:
        try:
            logger.debug("📊 Polling des stats workers...")
            
            # get_celery_stats() est synchrone, l'exécuter dans un thread
            stats = await asyncio.to_thread(get_celery_stats)
            
            await manager.broadcast({
                "type": "worker_stats",
                "data": stats
            })
            
            await asyncio.sleep(5) # Polling toutes les 5 secondes (côté serveur)
            
        except asyncio.CancelledError:
            logger.info("🛑 Tâche de stats workers annulée.")
            break
        except Exception as e:
            logger.error(f"❌ Erreur Polling Stats Workers: {e}", exc_info=True)
            await asyncio.sleep(15) # Attendre plus longtemps en cas d'erreur


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestion du cycle de vie de l'application"""
    # --- Startup ---
    logger.info("🚀 Démarrage de Vocalyx API")
    logger.info(f"📊 Database: {config.database_url.split('@')[-1]}")
    logger.info(f"📮 Redis Broker: {config.redis_url}")
    logger.info(f"📁 Upload Directory: {config.upload_dir}")
    
    # Initialiser Redis pour Pub/Sub
    try:
        redis_pub = await aioredis.from_url(config.redis_url)
        redis_sub_conn = await aioredis.from_url(config.redis_url)
        redis_sub = redis_sub_conn.pubsub()
        
        app.state.redis_pub = redis_pub
        
        # Démarrer les tâches de fond
        app.state.pubsub_task = asyncio.create_task(
            redis_pubsub_listener(redis_sub, manager)
        )
        app.state.worker_stats_task = asyncio.create_task(
            periodic_worker_stats(app.state, manager)
        )
        
    except Exception as e:
        logger.error(f"❌ Échec de connexion à Redis (aioredis): {e}")
        app.state.redis_pub = None
        app.state.pubsub_task = None
        app.state.worker_stats_task = None

    # Stocker la config dans app.state pour accès dans les endpoints
    app.state.config = config
    app.state.celery = celery_app
    app.state.ws_manager = manager
    
    yield
    
    # --- Shutdown ---
    logger.info("🛑 Arrêt de Vocalyx API")
    if app.state.pubsub_task:
        app.state.pubsub_task.cancel()
    if app.state.worker_stats_task:
        app.state.worker_stats_task.cancel()
        
    if app.state.redis_pub:
        await app.state.redis_pub.close()
    if redis_sub_conn:
        await redis_sub_conn.close()
    
    logger.info("Tâches de fond arrêtées.")

# Créer l'application FastAPI
app = FastAPI(
    title="Vocalyx API",
    description="API centrale pour la gestion des transcriptions audio",
    version="2.1.0-websocket", # Version mise à jour
    contact={
        "name": "Guilhem RICHARD",
        "email": "guilhem.l.richard@gmail.com"
    },
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configuration CORS (pour permettre les appels depuis le Dashboard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inclure les routes API
app.include_router(api_router, prefix="/api")
# Inclure les routes d'authentification
app.include_router(auth_router, prefix="/api", tags=["Authentication"])
# Inclure les routes de gestion admin
app.include_router(admin_router, prefix="/api")
# Inclure les routes WebSocket
app.include_router(ws_router, tags=["WebSocket"])

@app.get("/", tags=["Root"])
def root():
    """Page d'accueil de l'API"""
    return {
        "service": "vocalyx-api",
        "version": "2.0.0",
        "status": "operational",
        "documentation": "/docs"
    }

@app.get("/health", tags=["System"])
def health_check():
    """Endpoint de santé pour les orchestrateurs (Kubernetes, Docker, etc.)"""
    return {
        "status": "healthy",
        "service": "vocalyx-api",
        "database": "connected",  # Pourrait être vérifié dynamiquement
        "redis": "connected"       # Pourrait être vérifié dynamiquement
    }

if __name__ == "__main__":
    import uvicorn
    from logging_config import get_uvicorn_log_config
    
    log_config = get_uvicorn_log_config(log_level=config.log_level)
    
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_config=log_config
    )