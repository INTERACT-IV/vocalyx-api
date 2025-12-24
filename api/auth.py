"""
vocalyx-api/api/auth.py
Logique d'authentification (JWT, Hachage, Dépendances)
Refactorisé pour utiliser les services de la clean architecture
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from config import Config
from database import User
from api.dependencies import get_db
from api.schemas import TokenData

# Import des nouveaux services
from infrastructure.dependencies import (
    get_user_service, get_jwt_service
)
from application.services.user_service import UserService
from infrastructure.security.jwt_service import JWTService

logger = logging.getLogger(__name__)
config = Config()

# --- Configuration du Hachage (pour compatibilité) ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Configuration JWT (pour compatibilité) ---
JWT_SECRET_KEY = config.jwt_secret_key
JWT_ALGORITHM = config.jwt_algorithm
JWT_EXPIRE_MINUTES = config.jwt_expire_minutes

# Cible le futur endpoint /api/auth/token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie un mot de passe non haché contre un mot de passe haché (compatibilité)"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Génère un hachage pour un mot de passe (compatibilité)"""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Crée un token JWT (compatibilité)"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Vérifie si un utilisateur existe et si le mot de passe est correct (compatibilité)"""
    # Utiliser les nouveaux services
    from infrastructure.database.repositories import SQLAlchemyUserRepository
    from infrastructure.security.password_hasher import PasswordHasher
    
    user_repository = SQLAlchemyUserRepository(db)
    password_hasher = PasswordHasher()
    user_service = UserService(user_repository, password_hasher)
    
    user = user_service.authenticate(username, password)
    
    # Convertir l'entité User en modèle SQLAlchemy User pour compatibilité
    if user:
        return db.query(User).filter(User.id == user.id).first()
    return None

def get_current_user(
    token: str = Depends(oauth2_scheme),
    user_service: UserService = Depends(get_user_service),
    jwt_service: JWTService = Depends(get_jwt_service)
) -> User:
    """
    Dépendance FastAPI : Décode le token JWT et retourne l'utilisateur
    Version refactorisée utilisant les nouveaux services
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt_service.decode_token(token)
        username: str = payload.get("sub")
        is_admin: bool = payload.get("is_admin", False)
        
        if username is None:
            raise credentials_exception
        
        # Récupérer l'utilisateur via le service
        user_entity = user_service.get_user_by_username(username)
        if user_entity is None:
            logger.warning(f"JWT invalid: User '{username}' not found in DB")
            raise credentials_exception
        
        if user_entity.is_admin != is_admin:
            logger.warning(f"JWT stale: Admin status mismatch for user '{user_entity.username}'")
            raise credentials_exception
        
        # Convertir l'entité en modèle SQLAlchemy pour compatibilité
        from infrastructure.database.session import SessionLocal
        db = SessionLocal()
        try:
            user_model = db.query(User).filter(User.id == user_entity.id).first()
            return user_model
        finally:
            db.close()
    except ValueError as e:  # Erreur de décodage JWT
        logger.warning(f"JWTError: Failed to decode token: {e}")
        raise credentials_exception

def get_current_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """
    Dépendance qui vérifie que l'utilisateur courant est un admin.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user