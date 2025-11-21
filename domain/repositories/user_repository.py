"""
Interface UserRepository - Définit les opérations d'accès aux données pour User
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from domain.entities.user import User


class UserRepository(ABC):
    """Interface pour le repository des utilisateurs"""
    
    @abstractmethod
    def find_by_id(self, user_id: str) -> Optional[User]:
        """Trouve un utilisateur par son ID"""
        pass
    
    @abstractmethod
    def find_by_username(self, username: str) -> Optional[User]:
        """Trouve un utilisateur par son nom d'utilisateur"""
        pass
    
    @abstractmethod
    def find_all(self) -> List[User]:
        """Retourne tous les utilisateurs"""
        pass
    
    @abstractmethod
    def save(self, user: User) -> User:
        """Sauvegarde un utilisateur (création ou mise à jour)"""
        pass
    
    @abstractmethod
    def delete(self, user_id: str) -> None:
        """Supprime un utilisateur"""
        pass
    
    @abstractmethod
    def find_with_projects(self, user_id: str) -> Optional[User]:
        """Trouve un utilisateur avec ses projets associés"""
        pass

