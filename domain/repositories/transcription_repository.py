"""
Interface TranscriptionRepository - Définit les opérations d'accès aux données pour Transcription
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from domain.entities.transcription import Transcription


class TranscriptionRepository(ABC):
    """Interface pour le repository des transcriptions"""
    
    @abstractmethod
    def find_by_id(self, transcription_id: str) -> Optional[Transcription]:
        """Trouve une transcription par son ID"""
        pass
    
    @abstractmethod
    def find_all(
        self,
        page: int = 1,
        limit: int = 25,
        status: Optional[str] = None,
        project_name: Optional[str] = None,
        search: Optional[str] = None,
        allowed_projects: Optional[List[str]] = None
    ) -> List[Transcription]:
        """Trouve toutes les transcriptions avec filtres et pagination"""
        pass
    
    @abstractmethod
    def count(
        self,
        status: Optional[str] = None,
        project_name: Optional[str] = None,
        search: Optional[str] = None,
        allowed_projects: Optional[List[str]] = None
    ) -> Dict[str, int]:
        """Compte les transcriptions avec filtres"""
        pass
    
    @abstractmethod
    def save(self, transcription: Transcription) -> Transcription:
        """Sauvegarde une transcription (création ou mise à jour)"""
        pass
    
    @abstractmethod
    def delete(self, transcription_id: str) -> None:
        """Supprime une transcription"""
        pass
    
    @abstractmethod
    def get_worker_stats(self, allowed_projects: Optional[List[str]] = None) -> Dict[str, Dict[str, float]]:
        """Récupère les statistiques par worker"""
        pass

