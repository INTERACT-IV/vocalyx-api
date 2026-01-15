"""
vocalyx-api/celery_app.py
Configuration de Celery pour l'orchestration des tâches
"""

import logging
import json
import redis
from typing import Tuple
from celery import Celery
from config import Config

config = Config()
logger = logging.getLogger(__name__)

# Client Redis pour stocker les résultats intermédiaires des segments
_redis_client = None

def get_redis_client():
    """Obtient un client Redis pour stocker les résultats des segments"""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(config.redis_url, decode_responses=True)
    return _redis_client

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
# NOTE: Cette tâche est définie ici pour l'API, mais la vraie implémentation est dans vocalyx-transcribe
# On utilise juste le nom pour pouvoir l'enqueuer depuis l'API
@celery_app.task(
    bind=True,
    name='transcribe_audio',
    max_retries=3,
    default_retry_delay=60,  # Retry après 1 minute
)
def transcribe_audio_task(self, transcription_id: str, use_distributed: bool = None):
    """
    Tâche de transcription (orchestrateur).
    
    IMPORTANT: Cette tâche est définie ici mais EXÉCUTÉE par vocalyx-transcribe.
    L'API ne fait qu'enqueuer la tâche.
    
    Si use_distributed=True ou si l'audio dépasse le seuil configuré (par défaut 30s),
    cette tâche va :
    1. Découper l'audio en segments
    2. Créer une tâche par segment (distribuée sur plusieurs workers)
    3. Lancer une tâche d'agrégation qui attend tous les segments
    
    Sinon, elle se comporte comme avant (rétrocompatibilité).
    
    Le seuil minimal est configurable via :
    - config.ini : section [TRANSCRIPTION], clé distributed_min_duration_seconds
    - Variable d'environnement : DISTRIBUTED_MIN_DURATION_SECONDS
    
    Args:
        transcription_id: ID de la transcription à traiter
        use_distributed: Si True, force le mode distribué. Si False, force le mode classique (worker unique). Si None, décide automatiquement selon la durée
        
    Returns:
        dict: Résultat de la transcription
    """
    from database import SessionLocal, Transcription
    from datetime import datetime
    from pathlib import Path
    
    # Mettre à jour le celery_task_id dans la DB
    db = SessionLocal()
    try:
        trans = db.query(Transcription).filter(Transcription.id == transcription_id).first()
        if not trans:
            logger.error(f"[{transcription_id}] Transcription not found")
            return {"status": "error", "error": "Transcription not found"}
        
        trans.celery_task_id = self.request.id
        trans.status = 'pending'
        db.commit()
        
        # Vérifier si on doit utiliser le mode distribué
        file_path = Path(trans.file_path) if trans.file_path else None
        
        if use_distributed is None:
            # Décider automatiquement selon la durée configurée
            min_duration = config.distributed_min_duration_seconds
            if file_path and file_path.exists():
                try:
                    import soundfile as sf
                    duration = sf.info(str(file_path)).duration
                    use_distributed = min_duration > 0 and duration > min_duration
                    logger.info(
                        f"[{transcription_id}] 📊 DISTRIBUTION DECISION | "
                        f"Duration: {duration:.1f}s | "
                        f"Threshold: {min_duration}s {'(distribué désactivé)' if min_duration == 0 else ''} | "
                        f"Mode: {'DISTRIBUTED' if use_distributed else 'CLASSIC (single worker)'} | "
                        f"Reason: {'Audio exceeds threshold' if use_distributed else 'Audio below threshold or distributed disabled'}"
                    )
                except Exception as e:
                    logger.warning(f"[{transcription_id}] ⚠️ Could not get duration, using non-distributed mode: {e}")
                    use_distributed = False
            else:
                use_distributed = False
                logger.info(f"[{transcription_id}] 📊 DISTRIBUTION DECISION | Mode: CLASSIC (single worker) | Reason: File path not available")
        
        if use_distributed and file_path and file_path.exists():
            # MODE DISTRIBUÉ : Découper et distribuer les segments
            logger.info(
                f"[{transcription_id}] 🚀 DISTRIBUTED MODE ACTIVATED | "
                f"File: {Path(file_path).name} | "
                f"Will split into segments and distribute across multiple workers"
            )
            
            # Importer les fonctions de découpage (elles sont dans vocalyx-transcribe)
            # On va créer les segments ici et les envoyer comme tâches séparées
            from celery import current_app as celery_current_app
            
            # Créer les segments (on utilise la même logique que dans transcription_service.py)
            # Pour l'instant, on va juste créer une tâche qui fera le découpage côté worker
            # et qui lancera les sous-tâches
            
            # Envoyer une tâche spéciale qui va orchestrer le découpage et la distribution
            orchestrate_task = celery_current_app.send_task(
                'orchestrate_distributed_transcription',
                args=[transcription_id, str(file_path)],
                queue='transcription',
                countdown=1
            )
            
            logger.info(
                f"[{transcription_id}] ✅ DISTRIBUTED MODE | "
                f"Orchestration task enqueued | "
                f"Task ID: {orchestrate_task.id} | "
                f"Queue: transcription | "
                f"Next: Worker will split audio and create segment tasks"
            )
            
            return {
                "transcription_id": transcription_id,
                "task_id": self.request.id,
                "orchestration_task_id": orchestrate_task.id,
                "status": "queued_distributed",
                "mode": "distributed"
            }
        else:
            # MODE CLASSIQUE : Une seule tâche (rétrocompatibilité)
            logger.info(
                f"[{transcription_id}] 📝 CLASSIC MODE ACTIVATED | "
                f"File: {Path(trans.file_path).name if trans.file_path else 'N/A'} | "
                f"Single worker will process entire audio | "
                f"Task ID: {self.request.id} | "
                f"Queue: transcription"
            )
            return {
                "transcription_id": transcription_id,
                "task_id": self.request.id,
                "status": "queued",
                "mode": "classic"
            }
            
    except Exception as e:
        logger.error(f"[{transcription_id}] Error in transcribe_audio_task: {e}", exc_info=True)
        db.rollback()
        return {
            "transcription_id": transcription_id,
            "status": "error",
            "error": str(e)
        }
    finally:
        db.close()

def check_worker_availability(queue_name: str = 'transcription') -> Tuple[bool, str]:
    """
    Vérifie qu'au moins 1 worker est disponible pour traiter une transcription.
    Un worker est disponible seulement s'il n'y a aucune tâche en attente sur Celery.
    
    Args:
        queue_name: Nom de la queue à vérifier (par défaut 'transcription')
        
    Returns:
        tuple[bool, str]: (disponible, message)
            - disponible: True si au moins 1 worker est disponible, False sinon
            - message: Message explicatif
    """
    try:
        control = celery_app.control
        inspect = control.inspect(timeout=1.0)
        
        # 1. Vérifier qu'il y a au moins 1 worker actif pour la transcription
        stats = inspect.stats() or {}
        active_workers = inspect.active() or {}
        reserved_tasks = inspect.reserved() or {}
        scheduled_tasks = inspect.scheduled() or {}
        
        # Filtrer les workers de transcription (exclure les workers d'enrichissement)
        transcription_workers = {}
        for worker_name in stats.keys():
            if not (worker_name.startswith('enrichment-worker-') or 'enrichment' in worker_name.lower()):
                transcription_workers[worker_name] = active_workers.get(worker_name, [])
        
        if not transcription_workers:
            return False, "Aucun worker de transcription disponible"
        
        # 2. Vérifier qu'il n'y a pas de tâches en attente
        # Compter les tâches réservées (déjà assignées à un worker mais pas encore démarrées)
        total_reserved = 0
        for worker_name, tasks in reserved_tasks.items():
            if not (worker_name.startswith('enrichment-worker-') or 'enrichment' in worker_name.lower()):
                total_reserved += len(tasks)
        
        # Compter les tâches planifiées (en attente dans la queue)
        total_scheduled = 0
        for worker_name, tasks in scheduled_tasks.items():
            if not (worker_name.startswith('enrichment-worker-') or 'enrichment' in worker_name.lower()):
                total_scheduled += len(tasks)
        
        # Compter les tâches actives (en cours de traitement)
        total_active = 0
        for worker_name, tasks in active_workers.items():
            if not (worker_name.startswith('enrichment-worker-') or 'enrichment' in worker_name.lower()):
                total_active += len(tasks)
        
        # Vérifier aussi directement dans Redis la longueur de la queue
        # Celery stocke les queues dans Redis avec le format: celery (queue par défaut) ou le nom de la queue
        queue_length = 0
        try:
            import redis
            broker_url = config.celery_broker_url
            # Extraire l'URL Redis depuis le broker URL
            redis_client = redis.from_url(broker_url, decode_responses=True)
            
            # Celery utilise généralement le nom de la queue directement comme clé Redis
            # Pour la queue 'transcription', la clé sera 'transcription'
            queue_key = queue_name
            queue_length = redis_client.llen(queue_key)
            
            # Vérifier aussi la queue par défaut 'celery' si elle existe
            if queue_name != 'celery':
                default_queue_length = redis_client.llen('celery')
                queue_length += default_queue_length
                
            logger.debug(f"Queue '{queue_name}' length in Redis: {queue_length}")
        except Exception as redis_err:
            logger.warning(f"Impossible de vérifier la longueur de la queue Redis: {redis_err}")
            queue_length = 0
        
        # Un worker est disponible seulement s'il n'y a AUCUNE tâche en attente
        total_pending = total_reserved + total_scheduled + queue_length
        
        if total_pending > 0:
            return False, f"Des tâches sont en attente ({total_pending} tâches: {total_reserved} réservées, {total_scheduled} planifiées, {queue_length} dans Redis)"
        
        # Vérifier qu'au moins un worker n'a pas de tâche active (disponible)
        available_workers = []
        for worker_name, tasks in transcription_workers.items():
            if len(tasks) == 0:
                available_workers.append(worker_name)
        
        if not available_workers:
            return False, f"Tous les workers sont occupés ({len(transcription_workers)} workers actifs avec {total_active} tâches en cours)"
        
        return True, f"Worker disponible ({len(available_workers)}/{len(transcription_workers)} workers libres)"
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de disponibilité des workers: {e}", exc_info=True)
        # En cas d'erreur, on considère qu'un worker n'est pas disponible pour éviter de surcharger
        return False, f"Erreur lors de la vérification: {str(e)}"

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

def trigger_enrichment_task(transcription_id: str):
    """
    Déclenche une tâche d'enrichissement pour une transcription.
    
    Args:
        transcription_id: ID de la transcription à enrichir
        
    Returns:
        dict: Informations sur la tâche créée
    """
    try:
        logger.info(f"[{transcription_id}] 🤖 Triggering enrichment task...")
        enrich_task = celery_app.send_task(
            'enrich_transcription',
            args=[transcription_id],
            queue='enrichment',
            countdown=1
        )
        logger.info(f"[{transcription_id}] ✅ Enrichment task enqueued: {enrich_task.id}")
        return {
            "task_id": enrich_task.id,
            "status": "queued",
            "transcription_id": transcription_id
        }
    except Exception as e:
        logger.error(f"[{transcription_id}] ❌ Failed to enqueue enrichment task: {e}", exc_info=True)
        raise

if __name__ == "__main__":
    # Pour lancer un worker depuis cette API (déconseillé, utiliser vocalyx-transcribe)
    celery_app.worker_main([
        'worker',
        '--loglevel=info',
        '--concurrency=1'
    ])

