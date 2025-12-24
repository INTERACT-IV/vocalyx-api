"""
Initialisation de la base de données
"""

import logging
from infrastructure.database.session import engine, SessionLocal
from infrastructure.database.models import Base
from infrastructure.database.repositories import (
    SQLAlchemyUserRepository,
    SQLAlchemyProjectRepository
)
from infrastructure.security.password_hasher import PasswordHasher
from application.services.user_service import UserService
from application.services.project_service import ProjectService
from config import Config

config = Config()
logger = logging.getLogger(__name__)


def init_db():
    """Initialise la base de données (crée les tables et le projet admin)"""
    # Créer les tables
    Base.metadata.create_all(bind=engine)
    logger.info("✅ Tables de base de données créées")
    
    # Créer la session
    db = SessionLocal()
    try:
        # Services
        password_hasher = PasswordHasher()
        user_repository = SQLAlchemyUserRepository(db)
        project_repository = SQLAlchemyProjectRepository(db)
        user_service = UserService(user_repository, password_hasher)
        project_service = ProjectService(project_repository)
        
        # 1. Gérer le projet Admin
        admin_project = project_service.get_or_create(config.admin_project_name)
        logger.info(f"✅ Projet admin '{admin_project.name}' prêt")
        logger.info("=" * 70)
        logger.info(f"🔑 Clé API Admin ({admin_project.name}): {admin_project.api_key}")
        logger.info("Copiez cette clé pour l'utiliser dans le dashboard (SI PAS DE LOGIN)")
        logger.info("=" * 70)
        
        # 2. Gérer l'utilisateur Admin
        admin_user = user_service.get_user_by_username("admin")
        if not admin_user:
            logger.info("Utilisateur 'admin' non trouvé. Création...")
            admin_user = user_service.create_user("admin", "admin", is_admin=True)
            logger.info("✅ Utilisateur 'admin' créé avec le mot de passe 'admin'")
        else:
            logger.info("✅ Utilisateur 'admin' déjà existant.")
        
    finally:
        db.close()

