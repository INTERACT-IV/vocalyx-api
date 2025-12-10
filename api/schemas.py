"""
vocalyx-api/api/schemas.py
Schémas Pydantic pour la validation et la sérialisation
"""

from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field, field_serializer
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
    created_at: Optional[datetime] = None

    # ✅ AJOUT : Sérialiseur pour convertir datetime en string ISO
    @field_serializer('created_at')
    def serialize_created_at(self, dt: Optional[datetime], _info):
        if dt is None:
            return None
        return dt.isoformat()

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
    whisper_model: Optional[str] = Field(
        default="small",
        description="Modèle Whisper à utiliser: tiny, base, small, medium, large-v3-turbo"
    )

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
    enrichment_status: Optional[str] = None
    enrichment_worker_id: Optional[str] = None
    enrichment_data: Optional[str] = None  # JSON stringifié
    enrichment_error: Optional[str] = None
    enrichment_processing_time: Optional[float] = None

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
    diarization_enabled: Optional[bool] = None
    enrichment_requested: Optional[bool] = None
    whisper_model: Optional[str] = None
    enrichment_status: Optional[str] = None
    enrichment_worker_id: Optional[str] = None
    enrichment_data: Optional[Dict[str, Any]] = None
    enrichment_error: Optional[str] = None
    enrichment_processing_time: Optional[float] = None
    llm_model: Optional[str] = None
    enrichment_prompts: Optional[Dict[str, str]] = None
    text_correction: Optional[bool] = None  # Correction du texte (orthographe, grammaire) - option séparée
    enriched_text: Optional[str] = None  # Texte corrigé si text_correction=true
    enhanced_text: Optional[str] = None  # Texte enrichi avec métadonnées (JSON stringifié) - généré par défaut si enrichment=true
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
    created_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    is_admin: bool
    projects: List[ProjectResponse] = Field(default_factory=list)

    # ✅ AJOUT : Sérialiseur pour convertir datetime en string ISO
    @field_serializer('created_at')
    def serialize_created_at(self, dt: Optional[datetime], _info):
        if dt is None:
            return None
        return dt.isoformat()

    @field_serializer('last_login_at')
    def serialize_last_login_at(self, dt: Optional[datetime], _info):
        if dt is None:
            return None
        return dt.isoformat()

    class Config:
        from_attributes = True

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