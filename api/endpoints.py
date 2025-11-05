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
    UploadFile, Form, status, Request
)
from sqlalchemy.orm import Session
from sqlalchemy import func, exc

from api.api.database import Transcription, Project
from api.dependencies import (
    get_db, verify_project_key, verify_internal_key, verify_admin_key
)
from api.schemas import (
    TranscriptionResponse, TranscriptionCreate, TranscriptionUpdate,
    ProjectResponse, ProjectCreate, ProjectDetails,
    TranscriptionCountResponse, TaskStatusResponse
)
from celery_app import transcribe_audio_task, get_celery_stats, get_task_status, cancel_task

logger = logging.getLogger(__name__)
router = APIRouter()

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
    """
    config = request.app.state.config
    
    # 1. Validation du fichier
    content = await file.read()
    
    # Taille
    max_size_bytes = config.max_file_size_mb * 1024 * 1024
    if len(content) > max_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size exceeds {config.max_file_size_mb}MB limit"
        )
    
    # Extension
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
        # Supprimer le fichier uploadé
        file_path.unlink(missing_ok=True)
        logger.error(f"Database error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create database entry"
        )
    
    # 4. Envoyer la tâche à Celery
    try:
        task = transcribe_audio_task.delay(transcription_id)
        
        # Mettre à jour avec le task_id
        transcription.celery_task_id = task.id
        db.commit()
        
        logger.info(f"[{transcription_id}] Transcription created for project '{project.name}' | Task: {task.id}")
        
        return transcription.to_dict()
        
    except Exception as e:
        logger.error(f"Failed to enqueue Celery task: {e}")
        # La transcription existe en DB mais n'a pas été enqueueée
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
    
    # Filtres
    if status:
        query = query.filter(Transcription.status == status)
    if project:
        query = query.filter(Transcription.project_name == project)
    if search:
        query = query.filter(Transcription.text.ilike(f"%{search}%"))
    
    # Pagination
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
    # Requête filtrée
    filtered_query = db.query(Transcription)
    if status:
        filtered_query = filtered_query.filter(Transcription.status == status)
    if project:
        filtered_query = filtered_query.filter(Transcription.project_name == project)
    if search:
        filtered_query = filtered_query.filter(Transcription.text.ilike(f"%{search}%"))
    
    total_filtered = filtered_query.count()
    
    # Stats globales par statut
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
def update_transcription(
    transcription_id: str,
    update: TranscriptionUpdate,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_internal_key)
):
    """
    Met à jour une transcription (utilisé par les workers).
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
    
    # Appliquer les mises à jour
    update_data = update.dict(exclude_unset=True)
    
    for key, value in update_data.items():
        if hasattr(transcription, key):
            setattr(transcription, key, value)
    
    # Si le statut passe à "done" ou "error", mettre à jour finished_at
    if update.status in ["done", "error"] and not transcription.finished_at:
        transcription.finished_at = datetime.utcnow()
    
    try:
        db.commit()
        db.refresh(transcription)
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
def delete_transcription(
    transcription_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_internal_key)
):
    """
    Supprime une transcription et son fichier audio.
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
    
    # Supprimer le fichier audio
    if transcription.file_path:
        try:
            file_path = Path(transcription.file_path)
            if file_path.exists():
                file_path.unlink()
                logger.info(f"[{transcription_id}] File deleted: {file_path.name}")
        except Exception as e:
            logger.warning(f"[{transcription_id}] Failed to delete file: {e}")
    
    # Supprimer de la base de données
    db.delete(transcription)
    db.commit()
    
    logger.info(f"[{transcription_id}] Transcription deleted")
    
    return {
        "status": "deleted",
        "id": transcription_id
    }

# ============================================================================
# WORKERS & CELERY
# ============================================================================

@router.get("/workers", tags=["Workers"])
def list_workers(_: bool = Depends(verify_internal_key)):
    """
    Liste les workers Celery actifs et leurs statistiques.
    Endpoint interne (nécessite X-Internal-Key)
    """
    stats = get_celery_stats()
    return stats

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