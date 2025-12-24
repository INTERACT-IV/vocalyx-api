"""
ProjectService - Service applicatif pour la gestion des projets
"""

import logging
import secrets
import string
from typing import List, Optional
from domain.entities.project import Project
from domain.repositories.project_repository import ProjectRepository

logger = logging.getLogger(__name__)


class ProjectService:
    """Service pour la gestion des projets"""
    
    def __init__(self, project_repository: ProjectRepository):
        self.project_repository = project_repository
    
    def generate_api_key(self) -> str:
        """Génère une clé API sécurisée"""
        alphabet = string.ascii_letters + string.digits
        api_key = 'vk_' + ''.join(secrets.choice(alphabet) for _ in range(32))
        return api_key
    
    def create_project(self, name: str) -> Project:
        """Crée un nouveau projet avec une clé API générée"""
        # Vérifier si le projet existe déjà
        existing_project = self.project_repository.find_by_name(name)
        if existing_project:
            raise ValueError(f"Project '{name}' already exists")
        
        # Générer une clé API
        api_key = self.generate_api_key()
        
        # Créer l'entité
        from datetime import datetime
        import uuid
        project = Project(
            id=str(uuid.uuid4()),
            name=name,
            api_key=api_key,
            created_at=datetime.utcnow()
        )
        
        # Sauvegarder
        return self.project_repository.save(project)
    
    def get_project(self, project_id: str) -> Optional[Project]:
        """Récupère un projet par son ID"""
        return self.project_repository.find_by_id(project_id)
    
    def get_project_by_name(self, name: str) -> Optional[Project]:
        """Récupère un projet par son nom"""
        return self.project_repository.find_by_name(name)
    
    def get_all_projects(self) -> List[Project]:
        """Récupère tous les projets"""
        return self.project_repository.find_all()
    
    def get_user_projects(self, user_id: str) -> List[Project]:
        """Récupère tous les projets associés à un utilisateur"""
        return self.project_repository.find_by_user_id(user_id)
    
    def verify_api_key(self, project_name: str, api_key: str) -> Project:
        """Vérifie qu'une clé API correspond à un projet"""
        project = self.project_repository.find_by_name(project_name)
        if not project:
            raise ValueError(f"Project '{project_name}' not found")
        
        if not project.verify_api_key(api_key):
            raise ValueError("Invalid API key for this project")
        
        return project
    
    def assign_to_user(self, project_id: str, user_id: str) -> None:
        """Associe un projet à un utilisateur"""
        self.project_repository.assign_to_user(project_id, user_id)
    
    def remove_from_user(self, project_id: str, user_id: str) -> None:
        """Dissocie un projet d'un utilisateur"""
        self.project_repository.remove_from_user(project_id, user_id)
    
    def get_or_create(self, name: str) -> Project:
        """Récupère un projet ou le crée s'il n'existe pas"""
        project = self.project_repository.find_by_name(name)
        if project:
            return project
        
        logger.info(f"Project '{name}' not found. Creating...")
        return self.create_project(name)

