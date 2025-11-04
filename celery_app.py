"""
vocalyx-api/celery_app.py
Configuration de Celery pour l'orchestration des tâches
"""

import logging
from celery import Celery
from config import Config

config = Config()
logger = logging.getLogger(__name__)

# Créer l'instance Celery
celery_app = Celery(
    'vocalyx',
    broker=config.celery_broker_url,
    backend=config.celery_result_backend
)

# Configuration de Celery
celery_app.conf.update(
    # Sérialisation
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    
    # Timezone
    timezone='UTC',
    enable_utc=True,
    
    # Performance
    worker_prefetch_multiplier=1,  # Prendre 1 tâche à la fois (équitable)
    worker_max_tasks_per_child=50, # Redémarrer worker après 50 tâches (libère RAM)
    
    # Résultats
    result_expires=3600,  # Les résultats expirent après 1 heure
    result_persistent=True,  # Persister les résultats dans Redis
    
    # Retry
    task_acks_late=True,  # Acquitter la tâche seulement après succès
    task_reject_on_worker_lost=True,  # Re-enqueue si le worker crash
    
    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
)

# Définition de la tâche (elle sera exécutée par vocalyx-transcribe)
@celery_app.task(
    bind=True,
    name='transcribe_audio',
    max_retries=3,
    default_retry_delay=60  # Retry après 1 minute
)
def transcribe_audio_task(self, transcription_id: str):
    """
    Tâche de transcription.
    
    IMPORTANT: Cette tâche est définie ici mais EXÉCUTÉE par vocalyx-transcribe.
    L'API ne fait qu'enqueuer la tâche.
    
    Args:
        transcription_id: ID de la transcription à traiter
        
    Returns:
        dict: Résultat de la transcription
    """
    from database import SessionLocal, Transcription
    from datetime import datetime
    
    # Mettre à jour le celery_task_id dans la DB
    db = SessionLocal()
    try:
        trans = db.query(Transcription).filter(Transcription.id == transcription_id).first()
        if trans:
            trans.celery_task_id = self.request.id
            trans.status = 'pending'  # S'assurer que le statut est correct
            db.commit()
            logger.info(f"[{transcription_id}] Task {self.request.id} enqueued")
    except Exception as e:
        logger.error(f"[{transcription_id}] Error updating task_id: {e}")
        db.rollback()
    finally:
        db.close()
    
    # Le worker vocalyx-transcribe exécutera la transcription
    return {
        "transcription_id": transcription_id,
        "task_id": self.request.id,
        "status": "queued"
    }

def get_celery_stats():
    """
    Récupère les statistiques Celery (workers actifs, tâches en cours, etc.)
    
    Returns:
        dict: Statistiques Celery
    """
    try:
        inspect = celery_app.control.inspect()
        
        # Workers actifs
        active_workers = inspect.active()
        registered_tasks = inspect.registered()
        stats = inspect.stats()
        
        # Compter les workers
        worker_count = len(active_workers) if active_workers else 0
        
        # Compter les tâches actives
        active_task_count = 0
        if active_workers:
            for worker, tasks in active_workers.items():
                active_task_count += len(tasks)
        
        return {
            "worker_count": worker_count,
            "active_tasks": active_task_count,
            "workers": active_workers or {},
            "registered_tasks": registered_tasks or {},
            "stats": stats or {}
        }
    except Exception as e:
        logger.error(f"Error getting Celery stats: {e}")
        return {
            "worker_count": 0,
            "active_tasks": 0,
            "error": str(e)
        }

def get_task_status(task_id: str):
    """
    Récupère le statut d'une tâche Celery
    
    Args:
        task_id: ID de la tâche Celery
        
    Returns:
        dict: Statut de la tâche
    """
    from celery.result import AsyncResult
    
    result = AsyncResult(task_id, app=celery_app)
    
    return {
        "task_id": task_id,
        "status": result.status,  # PENDING, STARTED, SUCCESS, FAILURE, RETRY
        "result": result.result if result.ready() else None,
        "info": result.info
    }

def cancel_task(task_id: str):
    """
    Annule une tâche Celery
    
    Args:
        task_id: ID de la tâche à annuler
        
    Returns:
        dict: Confirmation d'annulation
    """
    celery_app.control.revoke(task_id, terminate=True, signal='SIGKILL')
    
    logger.info(f"Task {task_id} cancelled")
    
    return {
        "task_id": task_id,
        "status": "cancelled"
    }

if __name__ == "__main__":
    # Pour lancer un worker depuis cette API (déconseillé, utiliser vocalyx-transcribe)
    celery_app.worker_main([
        'worker',
        '--loglevel=info',
        '--concurrency=1'
    ])