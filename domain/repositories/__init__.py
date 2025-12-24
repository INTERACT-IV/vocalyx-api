"""
Repositories - Interfaces pour l'accès aux données
"""

from domain.repositories.user_repository import UserRepository
from domain.repositories.project_repository import ProjectRepository
from domain.repositories.transcription_repository import TranscriptionRepository

__all__ = [
    "UserRepository",
    "ProjectRepository",
    "TranscriptionRepository"
]
