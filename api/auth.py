"""
vocalyx-api/api/auth.py
Logique d'authentification (JWT, Hachage, Dépendances)
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

logger = logging.getLogger(__name__)
config = Config()

# --- Configuration du Hachage ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Configuration JWT ---
JWT_SECRET_KEY = config.jwt_secret_key
JWT_ALGORITHM = config.jwt_algorithm
JWT_EXPIRE_MINUTES = config.jwt_expire_minutes

# Cible le futur endpoint /api/auth/token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie un mot de passe non haché contre un mot de passe haché"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Génère un hachage pour un mot de passe"""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Crée un token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Vérifie si un utilisateur existe et si le mot de passe est correct"""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        logger.warning(f"Auth failed: User '{username}' not found")
        return None
    if not verify_password(password, user.hashed_password):
        logger.warning(f"Auth failed: Invalid password for user '{username}'")
        return None
    
    logger.info(f"Auth success: User '{username}' authenticated")
    return user

def get_current_user(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
) -> User:
    """
    Dépendance FastAPI : Décode le token JWT et retourne l'utilisateur
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        is_admin: bool = payload.get("is_admin", False)
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        logger.warning(f"JWTError: Failed to decode token")
        raise credentials_exception
    
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        logger.warning(f"JWT invalid: User '{token_data.username}' not found in DB")
        raise credentials_exception
    
    if user.is_admin != is_admin:
        logger.warning(f"JWT stale: Admin status mismatch for user '{user.username}'")
        raise credentials_exception
    
    return user

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