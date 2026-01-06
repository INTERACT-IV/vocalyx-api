"""
Entité Transcription - Modèle métier pour les transcriptions
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum


class TranscriptionStatus(str, Enum):
    """Statut d'une transcription"""
    PENDING = "pending"
    PROCESSING = "processing"
    TRANSCRIBED = "transcribed"  # Transcription terminée, en attente d'enrichissement
    DONE = "done"
    ERROR = "error"


@dataclass
class Transcription:
    """Entité Transcription du domaine"""
    id: str
    project_name: str
    status: TranscriptionStatus
    file_path: Optional[str] = None
    worker_id: Optional[str] = None
    celery_task_id: Optional[str] = None
    language: Optional[str] = None
    processing_time: Optional[float] = None
    duration: Optional[float] = None
    text: Optional[str] = None
    segments: Optional[List[Dict[str, Any]]] = None
    error_message: Optional[str] = None
    segments_count: Optional[int] = None
    vad_enabled: bool = False
    diarization_enabled: bool = False
    enrichment_requested: bool = False
    whisper_model: str = "small"
    enrichment_status: Optional[str] = None
    enrichment_worker_id: Optional[str] = None
    enrichment_data: Optional[Dict[str, Any]] = None
    enrichment_error: Optional[str] = None
    enrichment_processing_time: Optional[float] = None
    llm_model: Optional[str] = None
    enrichment_prompts: Optional[Dict[str, str]] = None
    text_correction: bool = False  # Correction du texte (orthographe, grammaire) - option séparée
    enriched_text: Optional[str] = None  # Texte corrigé si text_correction=true
    enhanced_text: Optional[str] = None  # Texte enrichi avec métadonnées (JSON stringifié) - généré par défaut si enrichment=true
    created_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Validation de l'entité"""
        if not self.project_name:
            raise ValueError("Project name cannot be empty")
        if isinstance(self.status, str):
            self.status = TranscriptionStatus(self.status)
    
    def mark_as_processing(self, worker_id: str) -> None:
        """Marque la transcription comme en cours de traitement"""
        self.status = TranscriptionStatus.PROCESSING
        self.worker_id = worker_id
    
    def mark_as_done(
        self,
        text: str,
        segments: List[Dict[str, Any]],
        language: str,
        duration: float,
        processing_time: float
    ) -> None:
        """Marque la transcription comme terminée avec ses résultats"""
        self.status = TranscriptionStatus.DONE
        self.text = text
        self.segments = segments
        self.language = language
        self.duration = duration
        self.processing_time = processing_time
        self.segments_count = len(segments)
        self.finished_at = datetime.utcnow()
    
    def mark_as_error(self, error_message: str) -> None:
        """Marque la transcription comme échouée"""
        self.status = TranscriptionStatus.ERROR
        self.error_message = error_message
        self.finished_at = datetime.utcnow()
    
    def is_completed(self) -> bool:
        """Vérifie si la transcription est terminée (succès ou erreur)"""
        return self.status in [TranscriptionStatus.DONE, TranscriptionStatus.ERROR]

