"""
TranscriptionService - Service applicatif pour la gestion des transcriptions
"""

import logging
import json
from typing import List, Optional, Dict, Any
from pathlib import Path
from domain.entities.transcription import Transcription, TranscriptionStatus
from domain.repositories.transcription_repository import TranscriptionRepository

logger = logging.getLogger(__name__)


class TranscriptionService:
    """Service pour la gestion des transcriptions"""
    
    def __init__(self, transcription_repository: TranscriptionRepository):
        self.transcription_repository = transcription_repository
    
    def create_transcription(
        self,
        transcription_id: str,
        project_name: str,
        file_path: str,
        whisper_model: str = "small",
        use_vad: bool = True,
        use_diarization: bool = False
    ) -> Transcription:
        """Crée une nouvelle transcription"""
        from datetime import datetime
        
        transcription = Transcription(
            id=transcription_id,
            project_name=project_name,
            status=TranscriptionStatus.PENDING,
            file_path=file_path,
            whisper_model=whisper_model,
            vad_enabled=use_vad,
            diarization_enabled=use_diarization,
            created_at=datetime.utcnow()
        )
        
        return self.transcription_repository.save(transcription)
    
    def get_transcription(self, transcription_id: str) -> Optional[Transcription]:
        """Récupère une transcription par son ID"""
        return self.transcription_repository.find_by_id(transcription_id)
    
    def list_transcriptions(
        self,
        page: int = 1,
        limit: int = 25,
        status: Optional[str] = None,
        project_name: Optional[str] = None,
        search: Optional[str] = None,
        allowed_projects: Optional[List[str]] = None
    ) -> List[Transcription]:
        """Liste les transcriptions avec filtres et pagination"""
        return self.transcription_repository.find_all(
            page=page,
            limit=limit,
            status=status,
            project_name=project_name,
            search=search,
            allowed_projects=allowed_projects
        )
    
    def count_transcriptions(
        self,
        status: Optional[str] = None,
        project_name: Optional[str] = None,
        search: Optional[str] = None,
        allowed_projects: Optional[List[str]] = None
    ) -> Dict[str, int]:
        """Compte les transcriptions avec filtres"""
        return self.transcription_repository.count(
            status=status,
            project_name=project_name,
            search=search,
            allowed_projects=allowed_projects
        )
    
    def update_transcription_status(
        self,
        transcription_id: str,
        status: TranscriptionStatus,
        worker_id: Optional[str] = None,
        error_message: Optional[str] = None
    ) -> Transcription:
        """Met à jour le statut d'une transcription"""
        transcription = self.get_transcription(transcription_id)
        if not transcription:
            raise ValueError(f"Transcription '{transcription_id}' not found")
        
        transcription.status = status
        if worker_id:
            transcription.worker_id = worker_id
        if error_message:
            transcription.error_message = error_message
        
        return self.transcription_repository.save(transcription)
    
    def update_transcription_result(
        self,
        transcription_id: str,
        text: str,
        segments: List[Dict[str, Any]],
        language: str,
        duration: float,
        processing_time: float
    ) -> Transcription:
        """Met à jour les résultats d'une transcription terminée"""
        transcription = self.get_transcription(transcription_id)
        if not transcription:
            raise ValueError(f"Transcription '{transcription_id}' not found")
        
        transcription.mark_as_done(
            text=text,
            segments=segments,
            language=language,
            duration=duration,
            processing_time=processing_time
        )
        
        return self.transcription_repository.save(transcription)
    
    def delete_transcription(self, transcription_id: str) -> None:
        """Supprime une transcription et son fichier audio"""
        transcription = self.get_transcription(transcription_id)
        if not transcription:
            raise ValueError(f"Transcription '{transcription_id}' not found")
        
        # Supprimer le fichier audio si existe
        if transcription.file_path:
            try:
                file_path = Path(transcription.file_path)
                if file_path.exists():
                    file_path.unlink()
                    logger.info(f"[{transcription_id}] File deleted: {file_path.name}")
            except Exception as e:
                logger.warning(f"[{transcription_id}] Failed to delete file: {e}")
        
        # Supprimer la transcription
        self.transcription_repository.delete(transcription_id)
    
    def get_worker_stats(self, allowed_projects: Optional[List[str]] = None) -> Dict[str, Dict[str, float]]:
        """Récupère les statistiques par worker"""
        return self.transcription_repository.get_worker_stats(allowed_projects)

