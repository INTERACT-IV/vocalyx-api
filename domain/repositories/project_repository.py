"""
Interface ProjectRepository - Définit les opérations d'accès aux données pour Project
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from domain.entities.project import Project


class ProjectRepository(ABC):
    """Interface pour le repository des projets"""
    
    @abstractmethod
    def find_by_id(self, project_id: str) -> Optional[Project]:
        """Trouve un projet par son ID"""
        pass
    
    @abstractmethod
    def find_by_name(self, name: str) -> Optional[Project]:
        """Trouve un projet par son nom"""
        pass
    
    @abstractmethod
    def find_by_api_key(self, api_key: str) -> Optional[Project]:
        """Trouve un projet par sa clé API"""
        pass
    
    @abstractmethod
    def find_all(self) -> List[Project]:
        """Retourne tous les projets"""
        pass
    
    @abstractmethod
    def save(self, project: Project) -> Project:
        """Sauvegarde un projet (création ou mise à jour)"""
        pass
    
    @abstractmethod
    def delete(self, project_id: str) -> None:
        """Supprime un projet"""
        pass
    
    @abstractmethod
    def find_by_user_id(self, user_id: str) -> List[Project]:
        """Trouve tous les projets associés à un utilisateur"""
        pass
    
    @abstractmethod
    def assign_to_user(self, project_id: str, user_id: str) -> None:
        """Associe un projet à un utilisateur"""
        pass
    
    @abstractmethod
    def remove_from_user(self, project_id: str, user_id: str) -> None:
        """Dissocie un projet d'un utilisateur"""
        pass

