"""
vocalyx-api/app.py
Point d'entrée principal de l'API centrale
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import Config
from database import Base, engine
from celery_app import celery_app

from api.endpoints import router as api_router, auth_router, admin_router
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

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestion du cycle de vie de l'application"""
    # --- Startup ---
    logger.info("🚀 Démarrage de Vocalyx API")
    logger.info(f"📊 Database: {config.database_url.split('@')[-1]}")  # Log sans credentials
    logger.info(f"📮 Redis Broker: {config.redis_url}")
    logger.info(f"📁 Upload Directory: {config.upload_dir}")
    
    # Stocker la config dans app.state pour accès dans les endpoints
    app.state.config = config
    app.state.celery = celery_app
    
    yield
    
    # --- Shutdown ---
    logger.info("🛑 Arrêt de Vocalyx API")

# Créer l'application FastAPI
app = FastAPI(
    title="Vocalyx API",
    description="API centrale pour la gestion des transcriptions audio",
    version="2.0.0",
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