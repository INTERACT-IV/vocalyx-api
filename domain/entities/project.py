"""
Entité Project - Modèle métier pour les projets
"""

from datetime import datetime
from typing import Optional
from dataclasses import dataclass


@dataclass
class Project:
    """Entité Project du domaine"""
    id: str
    name: str
    api_key: str
    created_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Validation de l'entité"""
        if not self.name:
            raise ValueError("Project name cannot be empty")
        if not self.api_key:
            raise ValueError("API key cannot be empty")
        if len(self.name) < 3 or len(self.name) > 50:
            raise ValueError("Project name must be between 3 and 50 characters")
    
    def verify_api_key(self, api_key: str) -> bool:
        """Vérifie si la clé API fournie correspond"""
        import secrets
        return secrets.compare_digest(self.api_key, api_key)

