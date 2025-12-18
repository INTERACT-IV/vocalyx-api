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
from sqlalchemy import Table, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext

from config import Config

config = Config()
logger = logging.getLogger(__name__)

Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def get_password_hash(password):
    return pwd_context.hash(password)

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

user_project_association = Table(
    'user_project_association',
    Base.metadata,
    Column('user_id', String, ForeignKey('users.id'), primary_key=True),
    Column('project_id', String, ForeignKey('projects.id'), primary_key=True)
)

class Project(Base):
    """Modèle pour les projets et leurs clés d'API"""
    __tablename__ = "projects"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, index=True, nullable=False)
    api_key = Column(String, unique=True, index=True, default=generate_api_key)
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship(
        "User",
        secondary=user_project_association,
        back_populates="projects"
    )
    
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
    
class User(Base):
    """Modèle pour les utilisateurs du Dashboard"""
    __tablename__ = "users"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    is_admin = Column(Boolean, default=False, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    
    projects = relationship(
        "Project",
        secondary=user_project_association,
        back_populates="users"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None
        }

class Transcription(Base):
    """Modèle pour les transcriptions audio"""
    __tablename__ = "transcriptions"
    
    id = Column(String, primary_key=True, index=True)
    status = Column(
        Enum("pending", "queued", "processing", "transcribed", "done", "error", name="transcription_status"),
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
    whisper_model = Column(String, nullable=True, default="small")  # Modèle Whisper utilisé
    
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
    queued_at = Column(DateTime, nullable=True)  # ✅ NOUVEAU : Quand la tâche a été envoyée à Celery
    processing_start_time = Column(DateTime, nullable=True)  # ✅ NOUVEAU : Quand le worker a commencé le traitement
    processing_end_time = Column(DateTime, nullable=True)  # ✅ NOUVEAU : Quand le worker a terminé le traitement
    finished_at = Column(DateTime, nullable=True)
    
    # Métriques de performance
    queue_wait_time = Column(Float, nullable=True)  # ✅ NOUVEAU : Temps d'attente dans la file (secondes)
    
    def to_dict(self):
        """Convertit l'objet en dictionnaire"""
        import json
        
        segments_list = None
        if self.segments:
            try:
                segments_list = json.loads(self.segments)
            except:
                pass
        
        enrichment_data_dict = None
        if self.enrichment_data:
            try:
                enrichment_data_dict = json.loads(self.enrichment_data)
            except:
                pass
        
        enrichment_prompts_dict = None
        if self.enrichment_prompts:
            try:
                enrichment_prompts_dict = json.loads(self.enrichment_prompts)
            except:
                pass
        
        return {
            "id": self.id,
            "status": self.status,
            "project_name": self.project_name,
            "worker_id": self.worker_id,
            "celery_task_id": self.celery_task_id,
            
            "file_path": self.file_path,
            
            "language": self.language,
            "processing_time": float(self.processing_time) if self.processing_time else None,
            "duration": float(self.duration) if self.duration else None,
            "text": self.text,
            "segments": segments_list,
            "error_message": self.error_message,
            "segments_count": self.segments_count,
            "vad_enabled": bool(self.vad_enabled),
            "diarization_enabled": bool(self.diarization_enabled),
            "enrichment_requested": bool(self.enrichment_requested),
            "whisper_model": self.whisper_model,
            "enrichment_status": self.enrichment_status,
            "enrichment_worker_id": self.enrichment_worker_id,
            "enrichment_data": enrichment_data_dict,
            "enrichment_error": self.enrichment_error,
            "enrichment_processing_time": float(self.enrichment_processing_time) if self.enrichment_processing_time else None,
            "llm_model": self.llm_model,
            "enrichment_prompts": enrichment_prompts_dict,
            "text_correction": bool(self.text_correction) if hasattr(self, 'text_correction') else False,
            "enriched_text": self.enriched_text if hasattr(self, 'enhanced_text') else None,
            "enhanced_text": self.enhanced_text if hasattr(self, 'enhanced_text') else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "queued_at": self.queued_at.isoformat() if hasattr(self, 'queued_at') and self.queued_at else None,  # ✅ NOUVEAU
            "processing_start_time": self.processing_start_time.isoformat() if hasattr(self, 'processing_start_time') and self.processing_start_time else None,  # ✅ NOUVEAU
            "processing_end_time": self.processing_end_time.isoformat() if hasattr(self, 'processing_end_time') and self.processing_end_time else None,  # ✅ NOUVEAU
            "queue_wait_time": float(self.queue_wait_time) if hasattr(self, 'queue_wait_time') and self.queue_wait_time else None,  # ✅ NOUVEAU
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
    """Initialise la base de données (crée les tables et le projet admin)
    Utilise les nouveaux services de la clean architecture
    """
    # Utiliser les nouveaux modules
    try:
        from infrastructure.database.init_db import init_db as init_db_new
        init_db_new()
    except ImportError:
        # Fallback sur l'ancienne méthode si les nouveaux modules ne sont pas disponibles
        Base.metadata.create_all(bind=engine)
        logger.warning("✅ Tables de base de données créées")
        
        # Créer le projet admin si nécessaire
        db = SessionLocal()
        try:
            # 1. Gérer le projet Admin
            admin_project = get_or_create_project(db, config.admin_project_name)
            logger.warning(f"✅ Projet admin '{admin_project.name}' prêt")
            logger.warning("==================================================================")
            logger.warning(f"🔑 Clé API Admin ({admin_project.name}): {admin_project.api_key}")
            logger.warning("Copiez cette clé pour l'utiliser dans le dashboard (SI PAS DE LOGIN)")
            logger.warning("==================================================================")

            # 2. Gérer l'utilisateur Admin
            admin_user = db.query(User).filter(User.username == "admin").first()
            if not admin_user:
                logger.warning("Utilisateur 'admin' non trouvé. Création...")
                admin_password_hash = get_password_hash("admin")
                new_admin_user = User(
                    username="admin",
                    hashed_password=admin_password_hash,
                    is_admin=True
                )
                db.add(new_admin_user)
                db.commit()
                logger.warning("✅ Utilisateur 'admin' créé avec le mot de passe 'admin'")
            else:
                logger.warning("✅ Utilisateur 'admin' déjà existant.")
            
        finally:
            db.close()

def get_db():
    """Dépendance pour obtenir une session de base de données"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()