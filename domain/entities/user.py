"""
Entité User - Modèle métier pour les utilisateurs
"""

from datetime import datetime
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class User:
    """Entité User du domaine"""
    id: str
    username: str
    hashed_password: str
    is_admin: bool
    created_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Validation de l'entité"""
        if not self.username:
            raise ValueError("Username cannot be empty")
        if not self.hashed_password:
            raise ValueError("Hashed password cannot be empty")
    
    def update_last_login(self) -> None:
        """Met à jour la date de dernière connexion"""
        self.last_login_at = datetime.utcnow()


@dataclass
class UserProject:
    """Relation entre User et Project"""
    user_id: str
    project_id: str

