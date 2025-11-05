"""
vocalyx-api/database.py
Configuration de la base de données et modèles SQLAlchemy
"""

import uuid
import secrets
import string
import logging
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Float, Text, Enum, DateTime, Integer, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from config import Config

config = Config()
logger = logging.getLogger(__name__)

Base = declarative_base()

# Créer le moteur de base de données
engine = create_engine(
    config.database_url,
    pool_pre_ping=True,  # Vérifie la connexion avant utilisation
    pool_size=10,        # Taille du pool de connexions
    max_overflow=20      # Connexions supplémentaires autorisées
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def generate_api_key():
    """Génère une clé d'API sécurisée au format vk_XXXXX"""
    alphabet = string.ascii_letters + string.digits
    return 'vk_' + ''.join(secrets.choice(alphabet) for _ in range(32))

class Project(Base):
    """Modèle pour les projets et leurs clés d'API"""
    __tablename__ = "projects"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, index=True, nullable=False)
    api_key = Column(String, unique=True, index=True, default=generate_api_key)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convertit l'objet en dictionnaire (sans la clé API)"""
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
    
    def to_dict_with_key(self):
        """Convertit l'objet en dictionnaire (avec la clé API)"""
        return {
            "id": self.id,
            "name": self.name,
            "api_key": self.api_key,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

class Transcription(Base):
    """Modèle pour les transcriptions audio"""
    __tablename__ = "transcriptions"
    
    id = Column(String, primary_key=True, index=True)
    status = Column(
        Enum("pending", "processing", "done", "error", name="transcription_status"),
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
    enrichment_requested = Column(Integer, default=1)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    finished_at = Column(DateTime, nullable=True)
    
    def to_dict(self):
        """Convertit l'objet en dictionnaire"""
        import json
        
        segments_list = None
        if self.segments:
            try:
                segments_list = json.loads(self.segments)
            except:
                pass
        
        return {
            "id": self.id,
            "status": self.status,
            "project_name": self.project_name,
            "worker_id": self.worker_id,
            "celery_task_id": self.celery_task_id,
            "language": self.language,
            "processing_time": float(self.processing_time) if self.processing_time else None,
            "duration": float(self.duration) if self.duration else None,
            "text": self.text,
            "segments": segments_list,
            "error_message": self.error_message,
            "segments_count": self.segments_count,
            "vad_enabled": bool(self.vad_enabled),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }

def get_or_create_project(db: Session, project_name: str) -> Project:
    """
    Récupère un projet par son nom. S'il n'existe pas, le crée.
    """
    if not project_name:
        raise ValueError("Le nom du projet ne peut pas être vide")
    
    project = db.query(Project).filter(Project.name == project_name).first()
    
    if project:
        logger.info(f"Projet '{project_name}' trouvé.")
        return project
    
    logger.warning(f"Projet '{project_name}' non trouvé. Création...")
    
    new_project = Project(name=project_name)
    db.add(new_project)
    try:
        db.commit()
        db.refresh(new_project)
        logger.info(f"✅ Projet '{new_project.name}' créé avec la clé: {new_project.api_key[:6]}...")
        return new_project
    except Exception as e:
        db.rollback()
        logger.error(f"Erreur lors de la création du projet: {e}")
        raise

def init_db():
    """Initialise la base de données (crée les tables et le projet admin)"""
    Base.metadata.create_all(bind=engine)
    logger.info("✅ Tables de base de données créées")
    
    # Créer le projet admin si nécessaire
    db = SessionLocal()
    try:
        admin_project = get_or_create_project(db, config.admin_project_name)
        logger.info(f"✅ Projet admin '{admin_project.name}' prêt")
    finally:
        db.close()