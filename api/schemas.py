"""
vocalyx-api/api/schemas.py
Schémas Pydantic pour la validation et la sérialisation
"""

from typing import Optional, List, Any
from pydantic import BaseModel, Field
from datetime import datetime

# ============================================================================
# PROJETS
# ============================================================================

class ProjectCreate(BaseModel):
    """Schéma pour créer un projet"""
    name: str = Field(..., min_length=3, max_length=50)

class ProjectResponse(BaseModel):
    """Schéma pour retourner un projet (sans la clé API)"""
    id: str
    name: str
    created_at: Optional[str] = None

    class Config:
        from_attributes = True

class ProjectDetails(ProjectResponse):
    """Schéma pour retourner un projet avec sa clé API"""
    api_key: str

# ============================================================================
# TRANSCRIPTIONS
# ============================================================================

class TranscriptionCreate(BaseModel):
    """Schéma pour créer une transcription"""
    project_name: str
    use_vad: bool = True

class TranscriptionUpdate(BaseModel):
    """Schéma pour mettre à jour une transcription (par les workers)"""
    status: Optional[str] = None
    worker_id: Optional[str] = None
    language: Optional[str] = None
    processing_time: Optional[float] = None
    duration: Optional[float] = None
    text: Optional[str] = None
    segments: Optional[str] = None  # JSON stringifié
    error_message: Optional[str] = None
    segments_count: Optional[int] = None

class TranscriptionResponse(BaseModel):
    """Schéma pour retourner une transcription"""
    id: str
    status: str
    project_name: Optional[str] = None
    worker_id: Optional[str] = None
    celery_task_id: Optional[str] = None
    file_path: Optional[str] = None
    language: Optional[str] = None
    processing_time: Optional[float] = None
    duration: Optional[float] = None
    text: Optional[str] = None
    segments: Optional[List[dict]] = None
    error_message: Optional[str] = None
    segments_count: Optional[int] = None
    vad_enabled: Optional[bool] = None
    created_at: Optional[str] = None
    finished_at: Optional[str] = None

class TranscriptionCountResponse(BaseModel):
    """Schéma pour les statistiques de transcriptions"""
    total_filtered: int
    pending: int
    processing: int
    done: int
    error: int
    total_global: int

# ============================================================================
# TÂCHES CELERY
# ============================================================================

class TaskStatusResponse(BaseModel):
    """Schéma pour le statut d'une tâche Celery"""
    task_id: str
    status: str  # PENDING, STARTED, SUCCESS, FAILURE, RETRY
    result: Optional[Any] = None
    info: Optional[Any] = None

# ============================================================================
# UTILISATEURS
# ============================================================================

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

    is_admin: bool = False

class UserResponse(UserBase):
    id: str
    created_at: Optional[str] = None

    is_admin: bool
    projects: List[ProjectResponse] = []

    class Config:
        from_attributes = True # Pydantic v2
        # orm_mode = True # Pydantic v1

# ============================================================================
# AUTHENTIFICATION
# ============================================================================

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserProjectLink(BaseModel):
    """Schéma pour lier un utilisateur et un projet"""
    user_id: str
    project_id: str

class UserPasswordUpdate(BaseModel):
    """Schéma pour mettre à jour un mot de passe"""
    password: str = Field(..., min_length=4)