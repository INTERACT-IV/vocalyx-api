"""
JWTService - Service pour la gestion des tokens JWT
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from jose import JWTError, jwt

logger = logging.getLogger(__name__)


class JWTService:
    """Service pour la gestion des tokens JWT"""
    
    def __init__(self, secret_key: str, algorithm: str = "HS256", expire_minutes: int = 10080):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.expire_minutes = expire_minutes
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Crée un token JWT"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=self.expire_minutes)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def decode_token(self, token: str) -> Dict[str, Any]:
        """Décode un token JWT"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError as e:
            logger.warning(f"JWT decode error: {e}")
            raise ValueError(f"Invalid token: {str(e)}")
    
    def get_username_from_token(self, token: str) -> Optional[str]:
        """Extrait le nom d'utilisateur depuis un token JWT"""
        try:
            payload = self.decode_token(token)
            return payload.get("sub")
        except ValueError:
            return None
    
    def get_admin_status_from_token(self, token: str) -> bool:
        """Extrait le statut admin depuis un token JWT"""
        try:
            payload = self.decode_token(token)
            return payload.get("is_admin", False)
        except ValueError:
            return False

