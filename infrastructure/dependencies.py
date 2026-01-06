"""
Dépendances FastAPI pour l'injection de services
"""

from typing import Generator
from sqlalchemy.orm import Session
from fastapi import Depends

from infrastructure.database.session import SessionLocal
from infrastructure.database.repositories import (
    SQLAlchemyUserRepository,
    SQLAlchemyProjectRepository,
    SQLAlchemyTranscriptionRepository
)
from infrastructure.security.password_hasher import PasswordHasher
from infrastructure.security.jwt_service import JWTService
from application.services.user_service import UserService
from application.services.project_service import ProjectService
from application.services.transcription_service import TranscriptionService
from config import Config

config = Config()


def get_db() -> Generator[Session, None, None]:
    """Dépendance pour obtenir une session de base de données"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_user_repository(db: Session = Depends(get_db)) -> SQLAlchemyUserRepository:
    """Dépendance pour obtenir le UserRepository"""
    return SQLAlchemyUserRepository(db)


def get_project_repository(db: Session = Depends(get_db)) -> SQLAlchemyProjectRepository:
    """Dépendance pour obtenir le ProjectRepository"""
    return SQLAlchemyProjectRepository(db)


def get_transcription_repository(db: Session = Depends(get_db)) -> SQLAlchemyTranscriptionRepository:
    """Dépendance pour obtenir le TranscriptionRepository"""
    return SQLAlchemyTranscriptionRepository(db)


def get_password_hasher() -> PasswordHasher:
    """Dépendance pour obtenir le PasswordHasher"""
    return PasswordHasher()


def get_jwt_service() -> JWTService:
    """Dépendance pour obtenir le JWTService"""
    return JWTService(
        secret_key=config.jwt_secret_key,
        algorithm=config.jwt_algorithm,
        expire_minutes=config.jwt_expire_minutes
    )


def get_user_service(
    user_repository: SQLAlchemyUserRepository = Depends(get_user_repository),
    password_hasher: PasswordHasher = Depends(get_password_hasher)
) -> UserService:
    """Dépendance pour obtenir le UserService"""
    return UserService(user_repository, password_hasher)


def get_project_service(
    project_repository: SQLAlchemyProjectRepository = Depends(get_project_repository)
) -> ProjectService:
    """Dépendance pour obtenir le ProjectService"""
    return ProjectService(project_repository)


def get_transcription_service(
    transcription_repository: SQLAlchemyTranscriptionRepository = Depends(get_transcription_repository)
) -> TranscriptionService:
    """Dépendance pour obtenir le TranscriptionService"""
    return TranscriptionService(transcription_repository)

