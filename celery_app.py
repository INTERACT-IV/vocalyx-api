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

# Définition des tâches (elles seront exécutées par les workers respectifs)
@celery_app.task(
    bind=True,
    name='transcribe_audio',
    max_retries=3,
    default_retry_delay=60,  # Retry après 1 minute
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
        control = celery_app.control
        # --- MODIFICATION 1: Ajouter un timeout à l'inspecteur ---
        inspect = control.inspect(timeout=1.0) 
        
        # --- MODIFICATION 2: Ajouter 'or {}' pour éviter les crashs (NoneType) ---
        active_workers = inspect.active() or {}
        registered_tasks = inspect.registered() or {}
        stats = inspect.stats() or {}

        health_responses = None
        try:
            # Isoler le broadcast, car c'est lui qui échoue le plus
            if stats: # Ne pas faire de broadcast si aucun worker n'est visible
                health_responses = control.broadcast('get_worker_health', reply=True, timeout=1.0)
        except Exception as e:
            logger.warning(f"Erreur lors du broadcast 'get_worker_health': {e}")
            # Ne pas planter toute la fonction si le broadcast échoue

        if health_responses:
            for response in health_responses:
                for worker_name, health_data in response.items():
                    if worker_name in stats and health_data and 'error' not in health_data:
                        # Fusionner les données de santé
                        stats[worker_name]['health'] = health_data
        
        # Compter les workers par type
        transcription_workers = {}
        enrichment_workers = {}
        
        if active_workers:
            for worker_name, tasks in active_workers.items():
                # Identifier le type de worker par son nom
                # Les workers de transcription ont des noms comme "worker-01@..." ou commencent par "worker-"
                # Les workers d'enrichissement ont des noms comme "enrichment-worker-01@..." ou commencent par "enrichment-"
                if worker_name.startswith('enrichment-worker-') or 'enrichment' in worker_name.lower():
                    enrichment_workers[worker_name] = tasks
                else:
                    transcription_workers[worker_name] = tasks
        
        if stats:
            for worker_name in list(stats.keys()):
                if worker_name.startswith('enrichment-worker-') or 'enrichment' in worker_name.lower():
                    if worker_name not in enrichment_workers:
                        enrichment_workers[worker_name] = []
                else:
                    if worker_name not in transcription_workers:
                        transcription_workers[worker_name] = []
        
        # Compter les workers
        worker_count = len(active_workers) # Plus besoin de 'if active_workers else 0'
        transcription_worker_count = len(transcription_workers)
        enrichment_worker_count = len(enrichment_workers)
        
        # Compter les tâches actives par type
        transcription_active_tasks = sum(len(tasks) for tasks in transcription_workers.values())
        enrichment_active_tasks = sum(len(tasks) for tasks in enrichment_workers.values())
        active_task_count = transcription_active_tasks + enrichment_active_tasks
        
        return {
            "worker_count": worker_count,
            "transcription_worker_count": transcription_worker_count,
            "enrichment_worker_count": enrichment_worker_count,
            "active_tasks": active_task_count,
            "transcription_active_tasks": transcription_active_tasks,
            "enrichment_active_tasks": enrichment_active_tasks,
            "workers": active_workers, # 'active_workers' est garanti d'être un dict
            "transcription_workers": transcription_workers,
            "enrichment_workers": enrichment_workers,
            "registered_tasks": registered_tasks,
            "stats": stats
        }
    except Exception as e:
        # Gérer les erreurs de connexion au broker (ex: Redis déconnecté)
        logger.error(f"Erreur majeure dans get_celery_stats (Broker inaccessible?): {e}", exc_info=True)
        # Retourner un état d'erreur clair
        return {
            "worker_count": 0,
            "transcription_worker_count": 0,
            "enrichment_worker_count": 0,
            "active_tasks": 0,
            "transcription_active_tasks": 0,
            "enrichment_active_tasks": 0,
            "workers": {},
            "transcription_workers": {},
            "enrichment_workers": {},
            "registered_tasks": {},
            "stats": {},
            "error": f"Failed to inspect Celery: {str(e)}"
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