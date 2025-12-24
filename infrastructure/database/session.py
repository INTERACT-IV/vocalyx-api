"""
Configuration de la session de base de données SQLAlchemy
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config import Config

config = Config()

# Créer le moteur de base de données
engine = create_engine(
    config.database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20
)

# Créer la session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db_session():
    """Factory pour obtenir une session de base de données"""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

