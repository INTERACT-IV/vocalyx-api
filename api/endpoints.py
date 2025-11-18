"""
vocalyx-api/api/endpoints.py
Endpoints de l'API centrale
"""

import uuid
import logging
import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import (
    APIRouter, Depends, File, HTTPException, Query, 
    UploadFile, Form, status, Request, WebSocket, WebSocketDisconnect
)
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from database import User
from api import auth, schemas

from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, exc, or_

from jose import JWTError, jwt

from database import Transcription, Project, User, SessionLocal
from api.dependencies import (
    get_db, verify_project_key, verify_internal_key, verify_admin_key,
    get_user_from_websocket
)
from api.schemas import (
    TranscriptionResponse, TranscriptionCreate, TranscriptionUpdate,
    ProjectResponse, ProjectCreate, ProjectDetails,
    TranscriptionCountResponse, TaskStatusResponse
)
from celery_app import transcribe_audio_task, get_task_status, cancel_task, get_celery_stats

from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from api import auth, schemas

logger = logging.getLogger(__name__)
router = APIRouter()
auth_router = APIRouter()
ws_router = APIRouter()

admin_router = APIRouter(
    tags=["Admin Management"],
    dependencies=[Depends(auth.get_current_admin_user)]
)

# ============================================================================
# NOUVELLES FONCTIONS HELPERS (PARTAGÉES)
# ============================================================================

def _load_user_with_projects(db: Session, user_id: str) -> User:
    return (
        db.query(User)
        .options(joinedload(User.projects))
        .filter(User.id == user_id)
        .first()
    )


def _get_allowed_project_names(db: Session, current_user: User) -> Optional[List[str]]:
    if current_user.is_admin:
        return None
    user = _load_user_with_projects(db, current_user.id)
    if not user:
        return []
    return [project.name for project in user.projects]


async def get_dashboard_state(filters: dict, allowed_projects: Optional[List[str]] = None) -> dict:
    """
    Fonction helper pour récupérer l'état complet du dashboard.
    Exécute les requêtes bloquantes (DB, Celery) dans des threads.
    """
    logger.info(f"-> get_dashboard_state: Démarrage avec filtres: {filters}")
    
    page = filters.get("page", 1)
    limit = filters.get("limit", 25)
    status = filters.get("status")
    project = filters.get("project")
    search = filters.get("search")
    
    offset = (page - 1) * limit
    
    db = SessionLocal() 
    logger.info("-> get_dashboard_state: Session DB créée.")

    def get_db_data_sync():
        """Fonction synchrone à exécuter dans un thread"""
        try:
            logger.info("-> get_db_data_sync: Démarrage...")
            filtered_query = db.query(Transcription)
            if allowed_projects is not None:
                if not allowed_projects:
                    logger.info("-> get_db_data_sync: Aucun projet autorisé, retour à vide.")
                    return {
                        "transcription_count": {
                            "total_filtered": 0,
                            "pending": 0, "processing": 0, "done": 0, "error": 0, "total_global": 0
                        },
                        "transcriptions": [],
                        "db_worker_stats": {}
                    }
                if project and project not in allowed_projects:
                    logger.info("-> get_db_data_sync: Projet non autorisé demandé.")
                    return {
                        "transcription_count": {
                            "total_filtered": 0,
                            "pending": 0, "processing": 0, "done": 0, "error": 0, "total_global": 0
                        },
                        "transcriptions": [],
                        "db_worker_stats": {}
                    }
                filtered_query = filtered_query.filter(Transcription.project_name.in_(allowed_projects))

            if status:
                filtered_query = filtered_query.filter(Transcription.status == status)
            if project:
                filtered_query = filtered_query.filter(Transcription.project_name == project)
            if search:
                search_term = f"%{search}%"
                filtered_query = filtered_query.filter(
                    or_(
                        Transcription.id.ilike(search_term),
                        Transcription.file_path.ilike(search_term),
                        Transcription.text.ilike(search_term)
                    )
                )
            
            logger.info("-> get_db_data_sync: Exécution de la requête .count()...")
            total_filtered = filtered_query.count()
            logger.info(f"-> get_db_data_sync: .count() terminé. Total: {total_filtered}")

            logger.info("-> get_db_data_sync: Exécution de la requête group_by(status)...")
            grouped_counts_db = db.query(
                Transcription.status,
                func.count(Transcription.id)
            ).group_by(Transcription.status).all()
            logger.info("-> get_db_data_sync: group_by(status) terminé.")
            
            count_result = {
                "total_filtered": total_filtered,
                "pending": 0, "processing": 0, "done": 0, "error": 0, "total_global": 0
            }
            for s, count in grouped_counts_db:
                if s in count_result:
                    count_result[s] = count
                    count_result["total_global"] += count

            logger.info("-> get_db_data_sync: Exécution de la requête principale (limit/offset)...")
            transcriptions_db = filtered_query.order_by(
                Transcription.created_at.desc()
            ).limit(limit).offset(offset).all()
            logger.info("-> get_db_data_sync: Requête principale terminée.")
            
            transcription_list = [t.to_dict() for t in transcriptions_db]

            logger.info("-> get_db_data_sync: Exécution de la requête stats_db_par_worker...")
            db_stats_query = db.query(
                Transcription.worker_id,
                func.sum(Transcription.duration).label('total_audio_s'),
                func.sum(Transcription.processing_time).label('total_processing_s')
            ).filter(
                Transcription.worker_id != None,
                Transcription.status == 'done'
            )
            if allowed_projects is not None:
                db_stats_query = db_stats_query.filter(Transcription.project_name.in_(allowed_projects))
            db_stats_query = db_stats_query.group_by(
                Transcription.worker_id
            ).all()
            logger.info("-> get_db_data_sync: Requête stats_db_par_worker terminée.")

            db_stats_dict = {
                row.worker_id: {
                    'total_audio_processed_s': row.total_audio_s or 0,
                    'total_processing_time_s': row.total_processing_s or 0
                }
                for row in db_stats_query
            }
            
            logger.info("-> get_db_data_sync: Terminé avec succès.")
            return {
                "transcription_count": count_result,
                "transcriptions": transcription_list,
                "db_worker_stats": db_stats_dict
            }
        except Exception as e:
            logger.error(f"-> get_db_data_sync: Erreur DB: {e}", exc_info=True)
            return {"transcription_count": {}, "transcriptions": []}
        finally:
            logger.info("-> get_db_data_sync: Fermeture de la session DB.")
            db.close() 

    logger.info("-> get_dashboard_state: Lancement de get_celery_stats dans un thread...")
    stats_task = asyncio.to_thread(get_celery_stats)
    
    logger.info("-> get_dashboard_state: Lancement de get_db_data_sync dans un thread...")
    db_task = asyncio.to_thread(get_db_data_sync)

    logger.info("-> get_dashboard_state: Attente de asyncio.gather (Celery + DB)...")
    try:
        worker_stats_result, db_data_result = await asyncio.gather(stats_task, db_task)
        logger.info("-> get_dashboard_state: asyncio.gather terminé.")
    except Exception as e:
        logger.error(f"-> get_dashboard_state: Erreur lors de asyncio.gather: {e}", exc_info=True)
        if db.is_active:
            db.close()
        raise

    # Fusionner les stats DB dans les stats Celery
    logger.info("-> get_dashboard_state: Fusion des stats DB et Celery...")
    if worker_stats_result.get('stats') and db_data_result.get('db_worker_stats'):
        db_stats_map = db_data_result['db_worker_stats']
        for worker_name, worker_data in worker_stats_result['stats'].items():
            simple_name = worker_name.split('@')[0]
            if simple_name in db_stats_map:
                worker_data['db_stats'] = db_stats_map[simple_name]
            else:
                # S'assurer que 'db_stats' existe toujours
                worker_data['db_stats'] = {
                    'total_audio_processed_s': 0,
                    'total_processing_time_s': 0
                }
    logger.info("-> get_dashboard_state: Fusion terminée.")

    # Combiner les résultats
    logger.info("-> get_dashboard_state: Combinaison des résultats...")
    return {
        "worker_stats": worker_stats_result,
        "transcription_count": db_data_result["transcription_count"],
        "transcriptions": db_data_result["transcriptions"]
    }

# ============================================================================
# WEBSOCKET ENDPOINT (MODIFIÉ)
# ============================================================================

@ws_router.websocket("/ws/updates")
async def websocket_endpoint(websocket: WebSocket):
    """
    ✅ VERSION FINALE: Endpoint WebSocket sans aucune dépendance FastAPI
    Tout est géré manuellement à l'intérieur de la fonction
    """
    logger.info("=" * 70)
    logger.info("WebSocket: 🔌 Nouvelle connexion entrante")
    logger.info("=" * 70)
    
    # ✅ ÉTAPE 1: ACCEPTER LA CONNEXION IMMÉDIATEMENT
    try:
        await websocket.accept()
        logger.info("WebSocket: ✅ Connexion acceptée (accept() réussi)")
    except Exception as e:
        logger.error(f"WebSocket: ❌ Échec de accept(): {e}", exc_info=True)
        return
    
    # Créer une session DB manuelle
    db = SessionLocal()
    manager = websocket.app.state.ws_manager
    user = None
    
    try:
        # ✅ ÉTAPE 2: Récupérer le token
        token = websocket.query_params.get("token")
        logger.info(f"WebSocket: Token présent: {token is not None}")
        
        if token is None:
            logger.warning("WebSocket: ❌ Aucun token fourni")
            await websocket.send_json({"type": "error", "message": "Authentication required"})
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        
        logger.debug(f"WebSocket: Token (premiers caractères): {token[:30]}...")
        
        # ✅ ÉTAPE 3: Décoder le JWT
        try:
            logger.info("WebSocket: 🔐 Décodage du JWT...")
            payload = jwt.decode(token, auth.JWT_SECRET_KEY, algorithms=[auth.JWT_ALGORITHM])
            username: str = payload.get("sub")
            
            if username is None:
                logger.warning("WebSocket: ❌ 'sub' manquant dans le JWT")
                await websocket.send_json({"type": "error", "message": "Invalid token format"})
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
            
            logger.info(f"WebSocket: ✅ Token décodé avec succès. Username: '{username}'")
            
        except JWTError as e:
            logger.error(f"WebSocket: ❌ Erreur JWT: {e}")
            await websocket.send_json({"type": "error", "message": f"Invalid or expired token: {str(e)}"})
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        
        # ✅ ÉTAPE 4: Vérifier l'utilisateur dans la DB
        logger.info(f"WebSocket: 🔍 Recherche de l'utilisateur '{username}' dans la DB...")
        user = db.query(User).filter(User.username == username).first()
        
        if user is None:
            logger.warning(f"WebSocket: ❌ Utilisateur '{username}' non trouvé dans la DB")
            await websocket.send_json({"type": "error", "message": "User not found"})
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        
        logger.info(f"WebSocket: ✅✅✅ Client '{user.username}' AUTHENTIFIÉ AVEC SUCCÈS !")
        allowed_projects = _get_allowed_project_names(db, user)
        
        # ✅ ÉTAPE 5: Enregistrer dans le manager
        await manager.connect(websocket)
        logger.info(f"WebSocket: ✅ Client '{user.username}' ajouté au ConnectionManager")
        
        # ✅ ÉTAPE 6: Envoyer l'état initial
        try:
            logger.info(f"WebSocket: 📊 Récupération de l'état initial du dashboard...")
            default_filters = {"page": 1, "limit": 25, "status": None, "project": None, "search": None}
            initial_state = await get_dashboard_state(default_filters, allowed_projects=allowed_projects)
            
            logger.info(f"WebSocket: 📤 Envoi de l'état initial à '{user.username}'...")
            await websocket.send_json({"type": "initial_dashboard_state", "data": initial_state})
            logger.info(f"WebSocket: ✅ État initial envoyé avec succès !")

        except Exception as e:
            logger.error(f"WebSocket: ❌ Erreur lors de l'envoi de l'état initial: {e}", exc_info=True)
            await websocket.send_json({"type": "error", "message": "Failed to load initial state"})
        
        # ✅ ÉTAPE 7: Boucle keep-alive
        logger.info(f"WebSocket: ♾️  Entrée dans la boucle keep-alive pour '{user.username}'")
        while True:
            try:
                data = await websocket.receive_json()
                logger.debug(f"WebSocket: Message JSON reçu de '{user.username}': {data.get('type')}")
                
                if data.get("type") == "get_dashboard_state":
                    payload = data.get("payload", {})
                    logger.info(f"WebSocket: Demande 'get_dashboard_state' reçue avec payload: {payload}")
                    
                    # Récupérer l'état filtré
                    filtered_state = await get_dashboard_state(payload, allowed_projects=allowed_projects)
                    
                    logger.info("WebSocket: État filtré récupéré. Envoi au client...")
                    await websocket.send_json({"type": "dashboard_state_update", "data": filtered_state})
                    logger.info("WebSocket: État filtré envoyé au client.")
            except WebSocketDisconnect:
                logger.info(f"WebSocket: 👋 Client '{user.username}' déconnecté proprement")
                break
            except Exception as e:
                logger.warning(f"WebSocket: ⚠️ Erreur dans la boucle keep-alive: {e}")
                break
        
    except WebSocketDisconnect:
        logger.info("WebSocket: 👋 Déconnexion détectée (WebSocketDisconnect)")
    except Exception as e:
        logger.error(f"WebSocket: ❌ Erreur critique: {e}", exc_info=True)
        try:
            await websocket.send_json({"type": "error", "message": "Internal server error"})
        except:
            logger.warning("WebSocket: Impossible d'envoyer le message d'erreur (connexion fermée)")
    finally:
        # ✅ ÉTAPE 8: Nettoyage
        username_log = user.username if user else "Client inconnu"
        logger.info(f"WebSocket: 🧹 Nettoyage des ressources pour '{username_log}'...")
        db.close()
        manager.disconnect(websocket)
        logger.info("WebSocket: ✅ Connexion fermée et nettoyée")
        logger.info("=" * 70)


# ============================================================================
# AUTHENTIFICATION
# ============================================================================

@auth_router.post("/auth/token", response_model=schemas.Token, tags=["Authentication"])
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db)
):
    """
    Fournit un token JWT en échange de username/password
    """
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=auth.JWT_EXPIRE_MINUTES)
    token_data = {
        "sub": user.username,
        "is_admin": user.is_admin 
    }
    access_token = auth.create_access_token(
        data=token_data, expires_delta=access_token_expires
    )

    # Mettre à jour la dernière connexion
    user.last_login_at = datetime.utcnow()
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/admin/admin-api-key", response_model=ProjectDetails, tags=["Admin"])
def get_admin_api_key(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    """
    [JWT Protégé] Récupère les détails (et la clé) du projet admin
    """
    config = request.app.state.config
    
    if current_user.username != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
        
    admin_project = db.query(Project).filter(Project.name == config.admin_project_name).first()
    if not admin_project:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Admin project '{config.admin_project_name}' not found"
        )
    
    return admin_project.to_dict_with_key()

# ============================================================================
# GESTION DES UTILISATEURS (NOUVEAU)
# ============================================================================

@admin_router.post("/admin/users", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    user_in: schemas.UserCreate, 
    db: Session = Depends(get_db)
):
    """
    [Admin] Crée un nouvel utilisateur (admin ou normal).
    """
    existing_user = db.query(User).filter(User.username == user_in.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{user_in.username}' already exists"
        )
    
    hashed_password = auth.get_password_hash(user_in.password)
    
    new_user = User(
        username=user_in.username,
        hashed_password=hashed_password,
        is_admin=user_in.is_admin
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    logger.info(f"Admin created new user: {new_user.username} (is_admin={new_user.is_admin})")
    return new_user

@admin_router.get("/admin/users", response_model=List[schemas.UserResponse])
def list_users(db: Session = Depends(get_db)):
    """
    [Admin] Liste tous les utilisateurs et leurs projets associés.
    """
    users = db.query(User).options(
        joinedload(User.projects)
    ).order_by(User.username).all()
    
    return users

@admin_router.post("/admin/users/assign-project", response_model=schemas.UserResponse)
def assign_project_to_user(
    link_in: schemas.UserProjectLink, 
    db: Session = Depends(get_db)
):
    """
    [Admin] Associe un projet à un utilisateur.
    """
    user = db.query(User).options(joinedload(User.projects)).filter(User.id == link_in.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    project = db.query(Project).filter(Project.id == link_in.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project not in user.projects:
        user.projects.append(project)
        db.commit()
        db.refresh(user)
        logger.info(f"Assigned project '{project.name}' to user '{user.username}'")
    
    return user

@admin_router.post("/admin/users/remove-project", response_model=schemas.UserResponse)
def remove_project_from_user(
    link_in: schemas.UserProjectLink, 
    db: Session = Depends(get_db)
):
    """
    [Admin] Dissocie un projet d'un utilisateur.
    """
    user = db.query(User).options(joinedload(User.projects)).filter(User.id == link_in.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    project = db.query(Project).filter(Project.id == link_in.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project in user.projects:
        user.projects.remove(project)
        db.commit()
        db.refresh(user)
        logger.info(f"Removed project '{project.name}' from user '{user.username}'")
    
    return user

@admin_router.put("/admin/users/{user_id}/password")
def update_user_password(
    user_id: str, 
    password_in: schemas.UserPasswordUpdate, 
    db: Session = Depends(get_db)
):
    """
    [Admin] Réinitialise le mot de passe d'un utilisateur.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    user.hashed_password = auth.get_password_hash(password_in.password)
    db.commit()
    logger.info(f"Admin reset password for user: {user.username}")
    
    return {"status": "password updated", "user_id": user_id}

@admin_router.delete("/admin/users/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db)):
    """
    [Admin] Supprime un utilisateur.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if user.username == "admin":
        raise HTTPException(status_code=403, detail="Cannot delete default admin user")
        
    db.delete(user)
    db.commit()
    logger.info(f"Admin deleted user: {user.username}")
    
    return {"status": "user deleted", "user_id": user_id}

# ============================================================================
# PROJETS
# ============================================================================

@router.post("/projects", response_model=ProjectDetails, status_code=status.HTTP_201_CREATED, tags=["Projects"])
def create_project(
    project: ProjectCreate,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_admin_key)
):
    """Crée un nouveau projet (nécessite la clé admin)"""
    new_project = Project(name=project.name)
    db.add(new_project)
    
    try:
        db.commit()
        db.refresh(new_project)
        logger.info(f"✅ Project '{new_project.name}' created")
        return new_project.to_dict_with_key()
    except exc.IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Project '{project.name}' already exists"
        )
    except Exception as e:
        db.rollback()
        logger.error(f"Error creating project: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create project: {str(e)}"
        )

@router.get("/user/projects", response_model=List[ProjectDetails], tags=["Projects"])
def list_user_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    """
    Liste les projets accessibles pour l'utilisateur courant (avec clés API).
    - Admins récupèrent l'intégralité des projets.
    - Les utilisateurs standard ne voient que les projets qui leur sont assignés.
    """
    if current_user.is_admin:
        projects = db.query(Project).order_by(Project.created_at.desc()).all()
    else:
        user = _load_user_with_projects(db, current_user.id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        projects = list(user.projects)
    
    return [p.to_dict_with_key() for p in projects]


@router.get("/user/me", response_model=schemas.UserResponse, tags=["Users"])
def get_user_profile(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    """Retourne le profil de l'utilisateur courant."""
    user = _load_user_with_projects(db, current_user.id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.get("/projects", response_model=List[ProjectResponse], tags=["Projects"])
def list_projects(
    db: Session = Depends(get_db),
    _: bool = Depends(verify_admin_key)
):
    """Liste tous les projets (nécessite la clé admin)"""
    projects = db.query(Project).order_by(Project.created_at.desc()).all()
    return [p.to_dict() for p in projects]

@router.get("/projects/{project_name}", response_model=ProjectDetails, tags=["Projects"])
def get_project(
    project_name: str,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_admin_key)
):
    """Récupère les détails d'un projet avec sa clé API (nécessite la clé admin)"""
    project = db.query(Project).filter(Project.name == project_name).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{project_name}' not found"
        )
    return project.to_dict_with_key()

# ============================================================================
# TRANSCRIPTIONS - CRÉATION
# ============================================================================

@router.post("/transcriptions", response_model=TranscriptionResponse, status_code=status.HTTP_201_CREATED, tags=["Transcriptions"])
async def create_transcription(
    request: Request,
    file: UploadFile = File(...),
    project_name: str = Form(...),
    use_vad: bool = Form(True),
    project: Project = Depends(verify_project_key),
    db: Session = Depends(get_db)
):
    """
    Crée une nouvelle transcription (nécessite la clé API du projet).
    Upload le fichier et enqueue une tâche Celery.
    PUBLIE une mise à jour sur Redis.
    """
    config = request.app.state.config
    
    # 1. Validation du fichier
    content = await file.read()
    
    max_size_bytes = config.max_file_size_mb * 1024 * 1024
    if len(content) > max_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds {config.max_file_size_mb}MB limit"
        )
    
    filename = file.filename or "upload.bin"
    extension = Path(filename).suffix.lstrip('.').lower()
    if extension not in config.allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type '{extension}' not allowed. Allowed: {config.allowed_extensions}"
        )
    
    # 2. Sauvegarder le fichier
    transcription_id = str(uuid.uuid4())
    safe_filename = f"{transcription_id}_{filename}"
    file_path = config.upload_dir / safe_filename
    
    try:
        with open(file_path, "wb") as f:
            f.write(content)
    except Exception as e:
        logger.error(f"Failed to save file: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save uploaded file"
        )
    
    # 3. Créer l'entrée en base de données
    transcription = Transcription(
        id=transcription_id,
        status="pending",
        project_name=project.name,
        file_path=str(file_path),
        vad_enabled=1 if use_vad else 0,
        created_at=datetime.utcnow()
    )
    db.add(transcription)
    
    try:
        db.commit()
        db.refresh(transcription)
    except Exception as e:
        db.rollback()
        file_path.unlink(missing_ok=True)
        logger.error(f"Database error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create database entry"
        )
    
    # 4. Envoyer la tâche à Celery
    try:
        task = transcribe_audio_task.delay(transcription_id)
        
        transcription.celery_task_id = task.id
        db.commit()
        
        # --- AJOUT PUBLISH REDIS ---
        redis_pub = request.app.state.redis_pub
        if redis_pub:
            await redis_pub.publish("vocalyx_updates", "new_transcription")
        # --- FIN AJOUT ---
            
        logger.info(f"[{transcription_id}] Transcription created for project '{project.name}' | Task: {task.id}")
        
        return transcription.to_dict()
        
    except Exception as e:
        logger.error(f"Failed to enqueue Celery task: {e}")
        transcription.status = "error"
        transcription.error_message = f"Failed to enqueue task: {str(e)}"
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enqueue transcription task"
        )

# ============================================================================
# TRANSCRIPTIONS - LECTURE
# ============================================================================

@router.get("/transcriptions", response_model=List[TranscriptionResponse], tags=["Transcriptions"])
def list_transcriptions(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    status: Optional[str] = Query(None),
    project: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _: bool = Depends(verify_internal_key)
):
    """
    Liste les transcriptions avec pagination et filtres.
    Endpoint interne (nécessite X-Internal-Key)
    """
    query = db.query(Transcription)
    
    if status:
        query = query.filter(Transcription.status == status)
    if project:
        query = query.filter(Transcription.project_name == project)
    if search:
        query = query.filter(Transcription.text.ilike(f"%{search}%"))
    
    offset = (page - 1) * limit
    transcriptions = query.order_by(
        Transcription.created_at.desc()
    ).limit(limit).offset(offset).all()
    
    return [t.to_dict() for t in transcriptions]

@router.get("/transcriptions/count", response_model=TranscriptionCountResponse, tags=["Transcriptions"])
def count_transcriptions(
    status: Optional[str] = Query(None),
    project: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _: bool = Depends(verify_internal_key)
):
    """
    Compte les transcriptions avec filtres et retourne les stats globales.
    Endpoint interne (nécessite X-Internal-Key)
    """
    filtered_query = db.query(Transcription)
    if status:
        filtered_query = filtered_query.filter(Transcription.status == status)
    if project:
        filtered_query = filtered_query.filter(Transcription.project_name == project)
    if search:
        filtered_query = filtered_query.filter(Transcription.text.ilike(f"%{search}%"))
    
    total_filtered = filtered_query.count()
    
    grouped_counts = db.query(
        Transcription.status,
        func.count(Transcription.id)
    ).group_by(Transcription.status).all()
    
    result = {
        "total_filtered": total_filtered,
        "pending": 0,
        "processing": 0,
        "done": 0,
        "error": 0,
        "total_global": 0
    }
    
    for s, count in grouped_counts:
        if s in result:
            result[s] = count
            result["total_global"] += count
    
    return result

@router.get("/transcriptions/{transcription_id}", response_model=TranscriptionResponse, tags=["Transcriptions"])
def get_transcription(
    transcription_id: str,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_internal_key)
):
    """
    Récupère une transcription par son ID.
    Endpoint interne (nécessite X-Internal-Key)
    """
    transcription = db.query(Transcription).filter(
        Transcription.id == transcription_id
    ).first()
    
    if not transcription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transcription '{transcription_id}' not found"
        )
    
    return transcription.to_dict()


@router.get("/user/transcriptions", response_model=List[TranscriptionResponse], tags=["Transcriptions"])
def list_user_transcriptions(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    status: Optional[str] = Query(None),
    project: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    """
    Liste les transcriptions auxquelles l'utilisateur courant peut accéder.
    """
    query = db.query(Transcription)
    allowed_projects = _get_allowed_project_names(db, current_user)
    if allowed_projects is not None:
        if not allowed_projects:
            return []
        query = query.filter(Transcription.project_name.in_(allowed_projects))
    
    if status:
        query = query.filter(Transcription.status == status)
    if project:
        if allowed_projects is not None and project not in allowed_projects:
            return []
        query = query.filter(Transcription.project_name == project)
    if search:
        query = query.filter(Transcription.text.ilike(f"%{search}%"))
    
    offset = (page - 1) * limit
    transcriptions = query.order_by(
        Transcription.created_at.desc()
    ).limit(limit).offset(offset).all()
    
    return [t.to_dict() for t in transcriptions]


@router.get("/user/transcriptions/count", response_model=TranscriptionCountResponse, tags=["Transcriptions"])
def count_user_transcriptions(
    status: Optional[str] = Query(None),
    project: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    """
    Compte les transcriptions accessibles à l'utilisateur courant.
    """
    allowed_projects = _get_allowed_project_names(db, current_user)
    if allowed_projects is not None and not allowed_projects:
        return {
            "total_filtered": 0,
            "pending": 0,
            "processing": 0,
            "done": 0,
            "error": 0,
            "total_global": 0
        }
    
    filtered_query = db.query(Transcription)
    if allowed_projects is not None:
        filtered_query = filtered_query.filter(Transcription.project_name.in_(allowed_projects))
    if status:
        filtered_query = filtered_query.filter(Transcription.status == status)
    if project:
        if allowed_projects is not None and project not in allowed_projects:
            return {
                "total_filtered": 0,
                "pending": 0,
                "processing": 0,
                "done": 0,
                "error": 0,
                "total_global": 0
            }
        filtered_query = filtered_query.filter(Transcription.project_name == project)
    if search:
        filtered_query = filtered_query.filter(Transcription.text.ilike(f"%{search}%"))
    
    total_filtered = filtered_query.count()
    
    grouped_counts = filtered_query.with_entities(
        Transcription.status,
        func.count(Transcription.id)
    ).group_by(Transcription.status).all()
    
    result = {
        "total_filtered": total_filtered,
        "pending": 0,
        "processing": 0,
        "done": 0,
        "error": 0,
        "total_global": 0
    }
    
    for s, count in grouped_counts:
        if s in result:
            result[s] = count
            result["total_global"] += count
    
    return result


@router.get("/user/transcriptions/{transcription_id}", response_model=TranscriptionResponse, tags=["Transcriptions"])
def get_user_transcription(
    transcription_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    """
    Récupère une transcription si l'utilisateur y a accès.
    """
    transcription = db.query(Transcription).filter(
        Transcription.id == transcription_id
    ).first()
    
    if not transcription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transcription '{transcription_id}' not found"
        )
    
    allowed_projects = _get_allowed_project_names(db, current_user)
    if allowed_projects is not None and transcription.project_name not in allowed_projects:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access to this transcription is forbidden"
        )
    
    return transcription.to_dict()

# ============================================================================
# TRANSCRIPTIONS - MISE À JOUR (pour les workers)
# ============================================================================

@router.patch("/transcriptions/{transcription_id}", response_model=TranscriptionResponse, tags=["Transcriptions"])
async def update_transcription(
    transcription_id: str,
    update: TranscriptionUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_internal_key)
):
    """
    Met à jour une transcription (utilisé par les workers).
    Endpoint interne (nécessite X-Internal-Key).
    PUBLIE une mise à jour sur Redis.
    """
    transcription = db.query(Transcription).filter(
        Transcription.id == transcription_id
    ).first()
    
    if not transcription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transcription '{transcription_id}' not found"
        )
    
    update_data = update.dict(exclude_unset=True)
    
    for key, value in update_data.items():
        if hasattr(transcription, key):
            setattr(transcription, key, value)
    
    if update.status in ["done", "error"] and not transcription.finished_at:
        transcription.finished_at = datetime.utcnow()
    
    try:
        db.commit()
        db.refresh(transcription)
        
        # --- AJOUT PUBLISH REDIS ---
        redis_pub = request.app.state.redis_pub
        if redis_pub:
            await redis_pub.publish("vocalyx_updates", f"update_{transcription_id}")
        # --- FIN AJOUT ---
            
        logger.info(f"[{transcription_id}] Updated: {update_data}")
        return transcription.to_dict()
    except Exception as e:
        db.rollback()
        logger.error(f"Error updating transcription: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update transcription"
        )

# ============================================================================
# TRANSCRIPTIONS - SUPPRESSION
# ============================================================================

@router.delete("/transcriptions/{transcription_id}", tags=["Transcriptions"])
async def delete_transcription(
    transcription_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_internal_key)
):
    """
    Supprime une transcription et son fichier audio.
    Endpoint interne (nécessite X-Internal-Key).
    PUBLIE une mise à jour sur Redis.
    """
    transcription = db.query(Transcription).filter(
        Transcription.id == transcription_id
    ).first()
    
    if not transcription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transcription '{transcription_id}' not found"
        )
    
    if transcription.file_path:
        try:
            file_path = Path(transcription.file_path)
            if file_path.exists():
                file_path.unlink()
                logger.info(f"[{transcription_id}] File deleted: {file_path.name}")
        except Exception as e:
            logger.warning(f"[{transcription_id}] Failed to delete file: {e}")
    
    db.delete(transcription)
    db.commit()
    
    # --- AJOUT PUBLISH REDIS ---
    redis_pub = request.app.state.redis_pub
    if redis_pub:
        await redis_pub.publish("vocalyx_updates", "delete_transcription")
    # --- FIN AJOUT ---
    
    logger.info(f"[{transcription_id}] Transcription deleted")
    
    return {
        "status": "deleted",
        "id": transcription_id
    }

# ============================================================================
# WORKERS & CELERY
# ============================================================================

@router.get("/workers", tags=["Workers"])
def list_workers(
    db: Session = Depends(get_db),
    _: bool = Depends(verify_internal_key)
):
    """
    Liste les workers Celery actifs et leurs statistiques.
    Endpoint interne (nécessite X-Internal-Key).
    Calcule également les stats depuis la DB.
    """
    stats = get_celery_stats() 
    
    try:
        # ✅ REQUÊTE SQL : Calculer les stats par worker depuis la DB
        db_stats_query = db.query(
            Transcription.worker_id,
            func.sum(Transcription.duration).label('total_audio_s'),
            func.sum(Transcription.processing_time).label('total_processing_s'),
            func.count(Transcription.id).label('total_jobs')
        ).filter(
            Transcription.worker_id != None,
            Transcription.status == 'done'
        ).group_by(
            Transcription.worker_id
        ).all()

        # Convertir en dictionnaire
        db_stats_dict = {}
        for row in db_stats_query:
            db_stats_dict[row.worker_id] = {
                'total_audio_processed_s': float(row.total_audio_s or 0),
                'total_processing_time_s': float(row.total_processing_s or 0),
                'total_jobs_completed': int(row.total_jobs or 0)
            }
        
        logger.info(f"📊 Stats DB calculées pour {len(db_stats_dict)} workers: {db_stats_dict}")
        
        # ✅ INJECTION : Injecter les stats DB dans les stats Celery
        if stats.get('stats'):
            for worker_name, worker_data in stats['stats'].items():
                # Extraire le nom simple du worker (ex: "worker-01@host" -> "worker-01")
                simple_name = worker_name.split('@')[0]
                
                if simple_name in db_stats_dict:
                    worker_data['db_stats'] = db_stats_dict[simple_name]
                    logger.debug(f"  ✅ Stats DB injectées pour {simple_name}: {db_stats_dict[simple_name]}")
                else:
                    # Worker sans stats DB (nouveau ou aucune tâche terminée)
                    worker_data['db_stats'] = {
                        'total_audio_processed_s': 0.0,
                        'total_processing_time_s': 0.0,
                        'total_jobs_completed': 0
                    }
                    logger.debug(f"  ℹ️ Aucune stat DB pour {simple_name}, valeurs par défaut")

    except Exception as e:
        logger.error(f"❌ Erreur lors du calcul des stats DB: {e}", exc_info=True)
        # En cas d'erreur, mettre des valeurs par défaut
        if stats.get('stats'):
            for worker_name, worker_data in stats['stats'].items():
                worker_data['db_stats'] = {
                    'total_audio_processed_s': 0.0,
                    'total_processing_time_s': 0.0,
                    'total_jobs_completed': 0
                }

    logger.info(f"📤 Envoi des stats workers avec DB stats: {len(stats.get('stats', {}))} workers")
    return stats

# ============================================================================
# TÂCHES
# ============================================================================

@router.get("/tasks/{task_id}", response_model=TaskStatusResponse, tags=["Tasks"])
def get_task(
    task_id: str,
    _: bool = Depends(verify_internal_key)
):
    """
    Récupère le statut d'une tâche Celery.
    Endpoint interne (nécessite X-Internal-Key)
    """
    return get_task_status(task_id)

@router.post("/tasks/{task_id}/cancel", tags=["Tasks"])
def cancel_task_endpoint(
    task_id: str,
    _: bool = Depends(verify_internal_key)
):
    """
    Annule une tâche Celery.
    Endpoint interne (nécessite X-Internal-Key)
    """
    return cancel_task(task_id)