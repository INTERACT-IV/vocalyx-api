"""
vocalyx-api/api/dependencies.py
Dépendances FastAPI pour l'authentification et l'accès DB
"""

import secrets
import logging
from typing import Optional
from fastapi import Depends, HTTPException, status, Header, Form, WebSocket, Query
from fastapi import WebSocketException, status as ws_status
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from database import SessionLocal, Project, User
from config import Config
from api import auth

config = Config()
logger = logging.getLogger(__name__)

def get_db():
    """Dépendance pour obtenir une session de base de données"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_project_key(
    project_name: str = Form(...),
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: Session = Depends(get_db)
) -> Project:
    """
    Vérifie que la clé API correspond au projet (pour les clients externes).
    
    Args:
        project_name: Nom du projet (depuis le formulaire)
        x_api_key: Clé API (depuis le header)
        db: Session de base de données
        
    Returns:
        Project: Le projet validé
        
    Raises:
        HTTPException: Si le projet n'existe pas ou si la clé est invalide
    """
    project = db.query(Project).filter(Project.name == project_name).first()
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project '{project_name}' not found"
        )
    
    if not secrets.compare_digest(project.api_key, x_api_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API Key for this project"
        )
    
    return project

def verify_internal_key(
    x_internal_key: str = Header(..., alias="X-Internal-Key")
) -> bool:
    """
    Vérifie la clé interne pour les communications inter-services
    (Dashboard, Workers).
    
    Args:
        x_internal_key: Clé interne (depuis le header)
        
    Returns:
        bool: True si la clé est valide
        
    Raises:
        HTTPException: Si la clé est invalide
    """
    if not config.internal_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Internal API key not configured"
        )
    
    if not secrets.compare_digest(config.internal_api_key, x_internal_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid internal API key"
        )
    
    return True

def verify_admin_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    db: Session = Depends(get_db)
) -> bool:
    """
    Vérifie que la clé API est celle du projet admin (pour la gestion des projets).
    
    Args:
        x_api_key: Clé API (depuis le header)
        db: Session de base de données
        
    Returns:
        bool: True si la clé est valide
        
    Raises:
        HTTPException: Si la clé est invalide ou le projet admin n'existe pas
    """
    admin_project = db.query(Project).filter(
        Project.name == config.admin_project_name
    ).first()
    
    if not admin_project:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Admin project not configured correctly"
        )
    
    if not secrets.compare_digest(admin_project.api_key, x_api_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return True

async def get_user_from_websocket(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db)
) -> User:
    """
    Dépendance d'authentification pour les WebSockets.
    Récupère le token JWT depuis le paramètre 'token' de la query string.
    """
    logger.info(f"🔐 WebSocket auth attempt, token provided: {token is not None}")
    # ✅ MODIFICATION: Utiliser WebSocketException au lieu de HTTPException
    credentials_exception = WebSocketException(
        code=ws_status.WS_1008_POLICY_VIOLATION,
        reason="Could not validate credentials"
    )
    
    if token is None:
        logger.error("❌ WebSocket auth failed: No token in query string")
        raise credentials_exception
    
    logger.info(f"🔑 Token (first 20 chars): {token[:20]}...")
    
    try:
        payload = jwt.decode(token, auth.JWT_SECRET_KEY, algorithms=[auth.JWT_ALGORITHM])
        username: str = payload.get("sub")
        logger.info(f"✅ JWT decoded successfully, username: {username}")
        if username is None:
            raise credentials_exception
    except JWTError as e:
        logger.warning(f"WebSocket: JWT decode failed: {e}")
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        logger.warning(f"WebSocket: User '{username}' not found in DB")
        raise credentials_exception
    
    logger.info(f"✅ WebSocket: User '{username}' authenticated successfully")
    return user