"""
Modèles SQLAlchemy - Réimplémentation des modèles depuis database.py
"""

import uuid
import secrets
import string
import logging
from datetime import datetime
from sqlalchemy import (
    Column, String, Float, Text, Enum, DateTime, Integer, Boolean, Table, ForeignKey
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

from config import Config

config = Config()
logger = logging.getLogger(__name__)

Base = declarative_base()


def generate_api_key():
    """Génère une clé d'API sécurisée au format vk_XXXXX"""
    alphabet = string.ascii_letters + string.digits
    return 'vk_' + ''.join(secrets.choice(alphabet) for _ in range(32))


# Table d'association User-Project
user_project_association = Table(
    'user_project_association',
    Base.metadata,
    Column('user_id', String, ForeignKey('users.id'), primary_key=True),
    Column('project_id', String, ForeignKey('projects.id'), primary_key=True)
)


class ProjectModel(Base):
    """Modèle SQLAlchemy pour les projets"""
    __tablename__ = "projects"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, index=True, nullable=False)
    api_key = Column(String, unique=True, index=True, default=generate_api_key)
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship(
        "UserModel",
        secondary=user_project_association,
        back_populates="projects"
    )


class UserModel(Base):
    """Modèle SQLAlchemy pour les utilisateurs"""
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_admin = Column(Boolean, default=False, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    
    projects = relationship(
        "ProjectModel",
        secondary=user_project_association,
        back_populates="users"
    )


class TranscriptionModel(Base):
    """Modèle SQLAlchemy pour les transcriptions"""
    __tablename__ = "transcriptions"
    
    id = Column(String, primary_key=True, index=True)
    status = Column(
        Enum("pending", "processing", "transcribed", "done", "error", name="transcription_status"),
        default="pending",
        index=True
    )
    
    # Identifiants
    project_name = Column(String, index=True, nullable=False)
    worker_id = Column(String, nullable=True, index=True)
    celery_task_id = Column(String, nullable=True, index=True)
    
    # Fichier
    file_path = Column(String, nullable=True)
    
    # Résultats de transcription
    language = Column(String, nullable=True)
    processing_time = Column(Float, nullable=True)
    duration = Column(Float, nullable=True)
    text = Column(Text, nullable=True)
    segments = Column(Text, nullable=True)  # JSON stringifié
    error_message = Column(Text, nullable=True)
    segments_count = Column(Integer, nullable=True)
    
    # Options
    vad_enabled = Column(Integer, default=0)
    diarization_enabled = Column(Integer, default=0)
    enrichment_requested = Column(Integer, default=0)
    whisper_model = Column(String, nullable=True, default="small")
    
    # Enrichissement
    enrichment_status = Column(
        Enum("pending", "processing", "done", "error", name="enrichment_status"),
        default="pending",
        nullable=True,
        index=True
    )
    enrichment_worker_id = Column(String, nullable=True, index=True)
    enrichment_data = Column(Text, nullable=True)  # JSON stringifié
    enrichment_error = Column(Text, nullable=True)
    enrichment_processing_time = Column(Float, nullable=True)  # Temps de traitement de l'enrichissement
    llm_model = Column(String, nullable=True)  # Modèle LLM utilisé
    enrichment_prompts = Column(Text, nullable=True)  # JSON avec les prompts personnalisés
    text_correction = Column(Integer, default=0)  # Correction du texte (orthographe, grammaire) - option séparée
    enriched_text = Column(Text, nullable=True)  # Texte corrigé si text_correction=true
    enhanced_text = Column(Text, nullable=True)  # Texte enrichi avec métadonnées (JSON stringifié) - généré par défaut si enrichment=true
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    finished_at = Column(DateTime, nullable=True)

