"""
Implémentations des repositories SQLAlchemy
"""

import logging
from typing import List, Optional, Dict
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, or_

from domain.entities import User, Project, Transcription
from domain.repositories import (
    UserRepository, ProjectRepository, TranscriptionRepository
)
from infrastructure.database.models import (
    UserModel, ProjectModel, TranscriptionModel
)
from infrastructure.database.mappers import (
    UserMapper, ProjectMapper, TranscriptionMapper
)

logger = logging.getLogger(__name__)


class SQLAlchemyUserRepository(UserRepository):
    """Implémentation SQLAlchemy du UserRepository"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def find_by_id(self, user_id: str) -> Optional[User]:
        """Trouve un utilisateur par son ID"""
        model = self.session.query(UserModel).filter(UserModel.id == user_id).first()
        return UserMapper.to_domain(model) if model else None
    
    def find_by_username(self, username: str) -> Optional[User]:
        """Trouve un utilisateur par son nom d'utilisateur"""
        model = self.session.query(UserModel).filter(UserModel.username == username).first()
        return UserMapper.to_domain(model) if model else None
    
    def find_all(self) -> List[User]:
        """Retourne tous les utilisateurs"""
        models = self.session.query(UserModel).all()
        return [UserMapper.to_domain(model) for model in models]
    
    def save(self, user: User) -> User:
        """Sauvegarde un utilisateur"""
        model = self.session.query(UserModel).filter(UserModel.id == user.id).first()
        
        if model:
            model = UserMapper.to_model(user, model)
        else:
            model = UserMapper.to_model(user)
            self.session.add(model)
        
        try:
            self.session.commit()
            self.session.refresh(model)
            return UserMapper.to_domain(model)
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error saving user: {e}")
            raise
    
    def delete(self, user_id: str) -> None:
        """Supprime un utilisateur"""
        model = self.session.query(UserModel).filter(UserModel.id == user_id).first()
        if model:
            self.session.delete(model)
            self.session.commit()
    
    def find_with_projects(self, user_id: str) -> Optional[User]:
        """Trouve un utilisateur avec ses projets associés"""
        model = (
            self.session.query(UserModel)
            .options(joinedload(UserModel.projects))
            .filter(UserModel.id == user_id)
            .first()
        )
        return UserMapper.to_domain(model) if model else None


class SQLAlchemyProjectRepository(ProjectRepository):
    """Implémentation SQLAlchemy du ProjectRepository"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def find_by_id(self, project_id: str) -> Optional[Project]:
        """Trouve un projet par son ID"""
        model = self.session.query(ProjectModel).filter(ProjectModel.id == project_id).first()
        return ProjectMapper.to_domain(model) if model else None
    
    def find_by_name(self, name: str) -> Optional[Project]:
        """Trouve un projet par son nom"""
        model = self.session.query(ProjectModel).filter(ProjectModel.name == name).first()
        return ProjectMapper.to_domain(model) if model else None
    
    def find_by_api_key(self, api_key: str) -> Optional[Project]:
        """Trouve un projet par sa clé API"""
        model = self.session.query(ProjectModel).filter(ProjectModel.api_key == api_key).first()
        return ProjectMapper.to_domain(model) if model else None
    
    def find_all(self) -> List[Project]:
        """Retourne tous les projets"""
        models = self.session.query(ProjectModel).order_by(ProjectModel.created_at.desc()).all()
        return [ProjectMapper.to_domain(model) for model in models]
    
    def save(self, project: Project) -> Project:
        """Sauvegarde un projet"""
        model = self.session.query(ProjectModel).filter(ProjectModel.id == project.id).first()
        
        if model:
            model = ProjectMapper.to_model(project, model)
        else:
            model = ProjectMapper.to_model(project)
            self.session.add(model)
        
        try:
            self.session.commit()
            self.session.refresh(model)
            return ProjectMapper.to_domain(model)
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error saving project: {e}")
            raise
    
    def delete(self, project_id: str) -> None:
        """Supprime un projet"""
        model = self.session.query(ProjectModel).filter(ProjectModel.id == project_id).first()
        if model:
            self.session.delete(model)
            self.session.commit()
    
    def find_by_user_id(self, user_id: str) -> List[Project]:
        """Trouve tous les projets associés à un utilisateur"""
        user = (
            self.session.query(UserModel)
            .options(joinedload(UserModel.projects))
            .filter(UserModel.id == user_id)
            .first()
        )
        if not user:
            return []
        
        return [ProjectMapper.to_domain(project) for project in user.projects]
    
    def assign_to_user(self, project_id: str, user_id: str) -> None:
        """Associe un projet à un utilisateur"""
        user = self.session.query(UserModel).filter(UserModel.id == user_id).first()
        project = self.session.query(ProjectModel).filter(ProjectModel.id == project_id).first()
        
        if not user or not project:
            raise ValueError("User or project not found")
        
        if project not in user.projects:
            user.projects.append(project)
            self.session.commit()
    
    def remove_from_user(self, project_id: str, user_id: str) -> None:
        """Dissocie un projet d'un utilisateur"""
        user = (
            self.session.query(UserModel)
            .options(joinedload(UserModel.projects))
            .filter(UserModel.id == user_id)
            .first()
        )
        project = self.session.query(ProjectModel).filter(ProjectModel.id == project_id).first()
        
        if not user or not project:
            raise ValueError("User or project not found")
        
        if project in user.projects:
            user.projects.remove(project)
            self.session.commit()


class SQLAlchemyTranscriptionRepository(TranscriptionRepository):
    """Implémentation SQLAlchemy du TranscriptionRepository"""
    
    def __init__(self, session: Session):
        self.session = session
    
    def find_by_id(self, transcription_id: str) -> Optional[Transcription]:
        """Trouve une transcription par son ID"""
        model = self.session.query(TranscriptionModel).filter(
            TranscriptionModel.id == transcription_id
        ).first()
        return TranscriptionMapper.to_domain(model) if model else None
    
    def find_all(
        self,
        page: int = 1,
        limit: int = 25,
        status: Optional[str] = None,
        project_name: Optional[str] = None,
        search: Optional[str] = None,
        allowed_projects: Optional[List[str]] = None
    ) -> List[Transcription]:
        """Trouve toutes les transcriptions avec filtres et pagination"""
        query = self.session.query(TranscriptionModel)
        
        # Filtres de permissions
        if allowed_projects is not None:
            if not allowed_projects:
                return []
            query = query.filter(TranscriptionModel.project_name.in_(allowed_projects))
        
        # Filtres de recherche
        if status:
            query = query.filter(TranscriptionModel.status == status)
        if project_name:
            query = query.filter(TranscriptionModel.project_name == project_name)
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    TranscriptionModel.id.ilike(search_term),
                    TranscriptionModel.file_path.ilike(search_term),
                    TranscriptionModel.text.ilike(search_term)
                )
            )
        
        # Pagination
        offset = (page - 1) * limit
        models = query.order_by(TranscriptionModel.created_at.desc()).limit(limit).offset(offset).all()
        
        return [TranscriptionMapper.to_domain(model) for model in models]
    
    def count(
        self,
        status: Optional[str] = None,
        project_name: Optional[str] = None,
        search: Optional[str] = None,
        allowed_projects: Optional[List[str]] = None
    ) -> Dict[str, int]:
        """Compte les transcriptions avec filtres"""
        # Requête de base pour les comptages globaux (sans filtres spécifiques)
        base_query = self.session.query(TranscriptionModel)
        
        # Requête filtrée pour le total filtré
        filtered_query = self.session.query(TranscriptionModel)
        
        # Filtres de permissions
        if allowed_projects is not None:
            if not allowed_projects:
                return {
                    "total_filtered": 0,
                    "pending": 0, "processing": 0, "done": 0, "error": 0, "total_global": 0
                }
            filtered_query = filtered_query.filter(TranscriptionModel.project_name.in_(allowed_projects))
        
        # Filtres de recherche pour le total filtré
        if status:
            filtered_query = filtered_query.filter(TranscriptionModel.status == status)
        if project_name:
            filtered_query = filtered_query.filter(TranscriptionModel.project_name == project_name)
        if search:
            search_term = f"%{search}%"
            filtered_query = filtered_query.filter(
                or_(
                    TranscriptionModel.id.ilike(search_term),
                    TranscriptionModel.file_path.ilike(search_term),
                    TranscriptionModel.text.ilike(search_term)
                )
            )
        
        # Compter le total filtré
        total_filtered = filtered_query.count()
        
        # Grouper par statut (sur la requête de base avec permissions)
        stats_query = self.session.query(
            TranscriptionModel.status,
            func.count(TranscriptionModel.id)
        )
        
        if allowed_projects is not None:
            stats_query = stats_query.filter(TranscriptionModel.project_name.in_(allowed_projects))
        
        grouped_counts = stats_query.group_by(TranscriptionModel.status).all()
        
        result = {
            "total_filtered": total_filtered,
            "pending": 0, "processing": 0, "done": 0, "error": 0, "total_global": 0
        }
        
        for status_val, count in grouped_counts:
            if status_val in result:
                result[status_val] = count
                result["total_global"] += count
        
        return result
    
    def save(self, transcription: Transcription) -> Transcription:
        """Sauvegarde une transcription"""
        model = self.session.query(TranscriptionModel).filter(
            TranscriptionModel.id == transcription.id
        ).first()
        
        if model:
            model = TranscriptionMapper.to_model(transcription, model)
        else:
            model = TranscriptionMapper.to_model(transcription)
            self.session.add(model)
        
        try:
            self.session.commit()
            self.session.refresh(model)
            return TranscriptionMapper.to_domain(model)
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error saving transcription: {e}")
            raise
    
    def delete(self, transcription_id: str) -> None:
        """Supprime une transcription"""
        model = self.session.query(TranscriptionModel).filter(
            TranscriptionModel.id == transcription_id
        ).first()
        if model:
            self.session.delete(model)
            self.session.commit()
    
    def get_worker_stats(self, allowed_projects: Optional[List[str]] = None) -> Dict[str, Dict[str, float]]:
        """Récupère les statistiques par worker"""
        query = (
            self.session.query(
                TranscriptionModel.worker_id,
                func.sum(TranscriptionModel.duration).label('total_audio_s'),
                func.sum(TranscriptionModel.processing_time).label('total_processing_s')
            )
            .filter(
                TranscriptionModel.worker_id != None,
                TranscriptionModel.status == 'done'
            )
        )
        
        if allowed_projects is not None:
            query = query.filter(TranscriptionModel.project_name.in_(allowed_projects))
        
        results = query.group_by(TranscriptionModel.worker_id).all()
        
        return {
            row.worker_id: {
                'total_audio_processed_s': float(row.total_audio_s or 0),
                'total_processing_time_s': float(row.total_processing_s or 0)
            }
            for row in results
        }

