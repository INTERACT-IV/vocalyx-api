"""
Mappers - Conversion entre modèles SQLAlchemy et entités de domaine
"""

import json
from typing import List, Optional
from infrastructure.database.models import (
    ProjectModel, UserModel, TranscriptionModel
)
from domain.entities import Project, User, Transcription, TranscriptionStatus


class ProjectMapper:
    """Mapper entre ProjectModel et Project"""
    
    @staticmethod
    def to_domain(model: ProjectModel) -> Project:
        """Convertit un ProjectModel en entité Project"""
        return Project(
            id=model.id,
            name=model.name,
            api_key=model.api_key,
            created_at=model.created_at
        )
    
    @staticmethod
    def to_model(project: Project, model: Optional[ProjectModel] = None) -> ProjectModel:
        """Convertit une entité Project en ProjectModel"""
        if model is None:
            model = ProjectModel()
        
        model.id = project.id
        model.name = project.name
        model.api_key = project.api_key
        model.created_at = project.created_at
        
        return model


class UserMapper:
    """Mapper entre UserModel et User"""
    
    @staticmethod
    def to_domain(model: UserModel) -> User:
        """Convertit un UserModel en entité User"""
        return User(
            id=model.id,
            username=model.username,
            hashed_password=model.hashed_password,
            is_admin=model.is_admin,
            created_at=model.created_at,
            last_login_at=model.last_login_at
        )
    
    @staticmethod
    def to_model(user: User, model: Optional[UserModel] = None) -> UserModel:
        """Convertit une entité User en UserModel"""
        if model is None:
            model = UserModel()
        
        model.id = user.id
        model.username = user.username
        model.hashed_password = user.hashed_password
        model.is_admin = user.is_admin
        model.created_at = user.created_at
        model.last_login_at = user.last_login_at
        
        return model


class TranscriptionMapper:
    """Mapper entre TranscriptionModel et Transcription"""
    
    @staticmethod
    def to_domain(model: TranscriptionModel) -> Transcription:
        """Convertit un TranscriptionModel en entité Transcription"""
        # Désérialiser les segments JSON
        segments_list = None
        if model.segments:
            try:
                segments_list = json.loads(model.segments)
            except (json.JSONDecodeError, TypeError):
                segments_list = None
        
        # Désérialiser les données d'enrichissement JSON
        enrichment_data_dict = None
        if model.enrichment_data:
            try:
                enrichment_data_dict = json.loads(model.enrichment_data)
            except (json.JSONDecodeError, TypeError):
                enrichment_data_dict = None
        
        # Désérialiser les prompts d'enrichissement JSON
        enrichment_prompts_dict = None
        if model.enrichment_prompts:
            try:
                enrichment_prompts_dict = json.loads(model.enrichment_prompts)
            except (json.JSONDecodeError, TypeError):
                enrichment_prompts_dict = None
        
        return Transcription(
            id=model.id,
            project_name=model.project_name,
            status=TranscriptionStatus(model.status),
            file_path=model.file_path,
            worker_id=model.worker_id,
            celery_task_id=model.celery_task_id,
            language=model.language,
            processing_time=float(model.processing_time) if model.processing_time else None,
            duration=float(model.duration) if model.duration else None,
            text=model.text,
            segments=segments_list,
            error_message=model.error_message,
            segments_count=model.segments_count,
            vad_enabled=bool(model.vad_enabled),
            diarization_enabled=bool(model.diarization_enabled),
            enrichment_requested=bool(model.enrichment_requested),
            whisper_model=model.whisper_model or "small",
            enrichment_status=model.enrichment_status,
            enrichment_worker_id=model.enrichment_worker_id,
            enrichment_data=enrichment_data_dict,
            enrichment_error=model.enrichment_error,
            enrichment_processing_time=float(model.enrichment_processing_time) if model.enrichment_processing_time else None,
            llm_model=model.llm_model,
            enrichment_prompts=enrichment_prompts_dict,
            text_correction=bool(model.text_correction) if hasattr(model, 'text_correction') else False,
            enriched_text=model.enriched_text if hasattr(model, 'enriched_text') else None,
            enhanced_text=model.enhanced_text if hasattr(model, 'enhanced_text') else None,
            created_at=model.created_at,
            finished_at=model.finished_at
        )
    
    @staticmethod
    def to_model(transcription: Transcription, model: Optional[TranscriptionModel] = None) -> TranscriptionModel:
        """Convertit une entité Transcription en TranscriptionModel"""
        if model is None:
            model = TranscriptionModel()
        
        model.id = transcription.id
        model.project_name = transcription.project_name
        model.status = transcription.status.value
        model.file_path = transcription.file_path
        model.worker_id = transcription.worker_id
        model.celery_task_id = transcription.celery_task_id
        model.language = transcription.language
        model.processing_time = transcription.processing_time
        model.duration = transcription.duration
        model.text = transcription.text
        model.segments = json.dumps(transcription.segments) if transcription.segments else None
        model.error_message = transcription.error_message
        model.segments_count = transcription.segments_count
        model.vad_enabled = 1 if transcription.vad_enabled else 0
        model.diarization_enabled = 1 if transcription.diarization_enabled else 0
        model.enrichment_requested = 1 if transcription.enrichment_requested else 0
        model.whisper_model = transcription.whisper_model
        model.enrichment_status = transcription.enrichment_status
        model.enrichment_worker_id = transcription.enrichment_worker_id
        model.enrichment_data = json.dumps(transcription.enrichment_data, ensure_ascii=False) if transcription.enrichment_data else None
        model.enrichment_error = transcription.enrichment_error
        model.enrichment_processing_time = transcription.enrichment_processing_time
        model.llm_model = transcription.llm_model
        model.enrichment_prompts = json.dumps(transcription.enrichment_prompts, ensure_ascii=False) if transcription.enrichment_prompts else None
        model.text_correction = 1 if transcription.text_correction else 0
        model.enriched_text = transcription.enriched_text
        model.enhanced_text = transcription.enhanced_text
        model.created_at = transcription.created_at
        model.finished_at = transcription.finished_at
        
        return model

