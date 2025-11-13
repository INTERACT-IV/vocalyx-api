"""
vocalyx-api/api/endpoints.py
Endpoints de l'API centrale
"""

import uuid
import logging
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
from sqlalchemy import func, exc

from database import Transcription, Project, User
from api.dependencies import (
    get_db, verify_project_key, verify_internal_key, verify_admin_key,
    get_user_from_websocket
)
from api.schemas import (
    TranscriptionResponse, TranscriptionCreate, TranscriptionUpdate,
    ProjectResponse, ProjectCreate, ProjectDetails,
    TranscriptionCountResponse, TaskStatusResponse
)
# --- CORRECTION : Ré-importer get_celery_stats ---
from celery_app import transcribe_audio_task, get_task_status, cancel_task, get_celery_stats
# --- FIN CORRECTION ---

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
# WEBSOCKET ENDPOINT
# ============================================================================

@ws_router.websocket("/ws/updates")
async def websocket_endpoint(
    websocket: WebSocket,
    user: User = Depends(get_user_from_websocket) # Authentification
):
    """
    Endpoint WebSocket. Authentifie l'utilisateur via le cookie
    et l'ajoute au pool de connexions.
    """
    manager = websocket.app.state.ws_manager
    await manager.connect(websocket)
    
    try:
        # Envoyer les données initiales dès la connexion
        # (L'API pollera en interne et enverra les stats)
        logger.info(f"Client WebSocket {user.username} authentifié et connecté.")
        
        while True:
            # Boucle "keep-alive"
            # Nous ne recevons rien, nous ne faisons qu'envoyer.
            await websocket.receive_text()
            # On pourrait gérer des messages entrants ici si besoin
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info(f"Client WebSocket {user.username} déconnecté.")
    except Exception as e:
        manager.disconnect(websocket)
        logger.error(f"Erreur WebSocket: {e}", exc_info=True)


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
        db_stats_query = db.query(
            Transcription.worker_id,
            func.sum(Transcription.duration).label('total_audio_s'),
            func.sum(Transcription.processing_time).label('total_processing_s')
        ).filter(
            Transcription.worker_id != None,
            Transcription.status == 'done'
        ).group_by(
            Transcription.worker_id
        ).all()

        db_stats_dict = {
            row.worker_id: {
                'total_audio_processed_s': row.total_audio_s or 0,
                'total_processing_time_s': row.total_processing_s or 0
            }
            for row in db_stats_query
        }
        
        if stats.get('stats'):
            for worker_name, worker_data in stats['stats'].items():
                simple_name = worker_name.split('@')[0]
                if simple_name in db_stats_dict:
                    worker_data['db_stats'] = db_stats_dict[simple_name]
                else:
                    worker_data['db_stats'] = {
                        'total_audio_processed_s': 0,
                        'total_processing_time_s': 0
                    }

    except Exception as e:
        logger.error(f"Erreur lors de la récupération des stats DB: {e}")

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