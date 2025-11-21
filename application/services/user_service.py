"""
UserService - Service applicatif pour la gestion des utilisateurs
"""

import logging
from typing import List, Optional
from domain.entities.user import User
from domain.repositories.user_repository import UserRepository
from infrastructure.security.password_hasher import PasswordHasher

logger = logging.getLogger(__name__)


class UserService:
    """Service pour la gestion des utilisateurs"""
    
    def __init__(self, user_repository: UserRepository, password_hasher: PasswordHasher):
        self.user_repository = user_repository
        self.password_hasher = password_hasher
    
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authentifie un utilisateur avec son nom d'utilisateur et mot de passe"""
        user = self.user_repository.find_by_username(username)
        if not user:
            logger.warning(f"Authentication failed: User '{username}' not found")
            return None
        
        if not self.password_hasher.verify(password, user.hashed_password):
            logger.warning(f"Authentication failed: Invalid password for user '{username}'")
            return None
        
        logger.info(f"Authentication success: User '{username}' authenticated")
        return user
    
    def create_user(self, username: str, password: str, is_admin: bool = False) -> User:
        """Crée un nouvel utilisateur"""
        # Vérifier si l'utilisateur existe déjà
        existing_user = self.user_repository.find_by_username(username)
        if existing_user:
            raise ValueError(f"Username '{username}' already exists")
        
        # Hacher le mot de passe
        hashed_password = self.password_hasher.hash(password)
        
        # Créer l'entité
        from datetime import datetime
        import uuid
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            hashed_password=hashed_password,
            is_admin=is_admin,
            created_at=datetime.utcnow()
        )
        
        # Sauvegarder
        return self.user_repository.save(user)
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Récupère un utilisateur par son ID"""
        return self.user_repository.find_by_id(user_id)
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Récupère un utilisateur par son nom d'utilisateur"""
        return self.user_repository.find_by_username(username)
    
    def get_all_users(self) -> List[User]:
        """Récupère tous les utilisateurs"""
        return self.user_repository.find_all()
    
    def get_user_with_projects(self, user_id: str) -> Optional[User]:
        """Récupère un utilisateur avec ses projets associés"""
        return self.user_repository.find_with_projects(user_id)
    
    def update_password(self, user_id: str, new_password: str) -> User:
        """Met à jour le mot de passe d'un utilisateur"""
        user = self.user_repository.find_by_id(user_id)
        if not user:
            raise ValueError(f"User '{user_id}' not found")
        
        user.hashed_password = self.password_hasher.hash(new_password)
        return self.user_repository.save(user)
    
    def update_last_login(self, user: User) -> User:
        """Met à jour la date de dernière connexion"""
        user.update_last_login()
        return self.user_repository.save(user)
    
    def delete_user(self, user_id: str) -> None:
        """Supprime un utilisateur"""
        user = self.user_repository.find_by_id(user_id)
        if not user:
            raise ValueError(f"User '{user_id}' not found")
        
        if user.username == "admin":
            raise ValueError("Cannot delete default admin user")
        
        self.user_repository.delete(user_id)

