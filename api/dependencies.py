"""
vocalyx-api/api/dependencies.py
Dépendances FastAPI pour l'authentification et l'accès DB
"""

import secrets
import logging # <-- AJOUT
from typing import Optional
from fastapi import Depends, HTTPException, status, Header, Form, WebSocket, Query
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from database import SessionLocal, Project, User # <-- SessionLocal est bien importé
from config import Config
from api import auth

config = Config()
logger = logging.getLogger(__name__) # <-- AJOUT

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
    Vérifie que la clé API est celle du projet admin.
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
    token: Optional[str] = Query(None), # Lire le token depuis ?token=...
    # db: Session = Depends(get_db) # <-- On garde la correction précédente
) -> User:
    """
    Dépendance d'authentification pour les WebSockets.
    Gère sa propre session DB.
    AJOUT: Logs détaillés.
    """
    
    logger.info("WebSocket: Tentative d'authentification...")
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials from token",
    )
    
    if token is None:
        logger.warning("WebSocket: Échec. Aucun token fourni dans la query string.")
        raise credentials_exception
    
    # logger.debug(f"WebSocket: Token reçu: {token[:15]}...") # Décommenter si nécessaire

    db = SessionLocal()
    try:
        logger.info("WebSocket: Décodage du JWT...")
        payload = jwt.decode(token, auth.JWT_SECRET_KEY, algorithms=[auth.JWT_ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            logger.warning("WebSocket: Échec. 'sub' (username) manquant dans le payload JWT.")
            db.close()
            raise credentials_exception
        
        logger.info(f"WebSocket: Token décodé. Username: {username}")

    except JWTError as e:
        logger.error(f"WebSocket: Échec. Erreur JWT: {e}")
        db.close()
        raise credentials_exception
    
    logger.info(f"WebSocket: Recherche de l'utilisateur '{username}' dans la base de données...")
    user = db.query(User).filter(User.username == username).first()
    
    if user is None:
        logger.warning(f"WebSocket: Échec. Utilisateur '{username}' non trouvé dans la base de données.")
        db.close()
        raise credentials_exception
    
    logger.info(f"WebSocket: Authentification réussie pour l'utilisateur '{username}'.")
    db.close()
    return user