# vocalyx-api

API centrale pour le système de transcription audio Vocalyx.

## 🎯 Rôle

- **Propriétaire unique** de la base de données PostgreSQL
- Gestion de la file d'attente Redis + Celery
- API REST pour tous les autres services (Dashboard, Workers)

## 🏗️ Architecture

```
vocalyx-api/
├── app.py                  # Point d'entrée FastAPI
├── config.py               # Configuration
├── database.py             # Modèles SQLAlchemy
├── celery_app.py           # Configuration Celery
├── logging_config.py       # Configuration du logging
├── api/
│   ├── __init__.py
│   ├── endpoints.py        # Routes API
│   ├── dependencies.py     # Auth & DB
│   └── schemas.py          # Schémas Pydantic
├── requirements.txt
├── Dockerfile
└── config.ini
```

## 🚀 Installation

### Prérequis

- Python 3.10+
- PostgreSQL 15+
- Redis 7+

### Installation locale

```bash
# Cloner le dépôt
git clone <repository>
cd vocalyx-api

# Créer un environnement virtuel
python3.10 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements.txt

# Configurer
cp config.ini config.local.ini
# Éditer config.local.ini avec vos paramètres

# Initialiser la base de données
python -c "from database import init_db; init_db()"

# Lancer l'API
python app.py
```

L'API sera accessible sur http://localhost:8000

Documentation: http://localhost:8000/docs

## 🐳 Docker

```bash
# Build
docker build -t vocalyx-api .

# Run
docker run -p 8000:8000 \
  -e DATABASE_URL="postgresql://user:pass@host/db" \
  -e REDIS_URL="redis://redis:6379/0" \
  -v $(pwd)/shared_uploads:/app/shared_uploads \
  vocalyx-api
```

## 📡 Endpoints Principaux

### Projets

- `POST /api/projects` - Créer un projet (admin)
- `GET /api/projects` - Lister les projets (admin)
- `GET /api/projects/{name}` - Détails d'un projet (admin)

### Transcriptions

- `POST /api/transcriptions` - Créer une transcription (clé projet)
- `GET /api/transcriptions` - Lister les transcriptions (interne)
- `GET /api/transcriptions/{id}` - Détails d'une transcription (interne)
- `PATCH /api/transcriptions/{id}` - Mettre à jour (interne)
- `DELETE /api/transcriptions/{id}` - Supprimer (interne)
- `GET /api/transcriptions/count` - Statistiques (interne)

### Workers & Tâches

- `GET /api/workers` - Liste des workers Celery (interne)
- `GET /api/tasks/{id}` - Statut d'une tâche (interne)
- `POST /api/tasks/{id}/cancel` - Annuler une tâche (interne)

## 🔒 Sécurité

### 3 Niveaux d'Authentification

1. **Clé Projet** (`X-API-Key`) - Pour les uploads depuis le Dashboard
2. **Clé Interne** (`X-Internal-Key`) - Pour les communications inter-services
3. **Clé Admin** (`X-API-Key` du projet admin) - Pour la gestion des projets

### Configuration des Clés

```ini
[SECURITY]
internal_api_key = SECRET_KEY_HERE
admin_project_name = ISICOMTECH
```

## ⚙️ Configuration

Voir `config.ini` pour toutes les options disponibles.

### Variables d'Environnement (optionnel)

```bash
DATABASE_URL=postgresql://user:pass@host/db
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/0
```

## 📊 Monitoring

- **Logs**: `logs/vocalyx-api.log`
- **Health Check**: `GET /health`
- **Celery Flower**: Utiliser `docker-compose` avec le service `flower`

## 🧪 Tests

```bash
# Tests unitaires (à implémenter)
pytest tests/

# Test de santé
curl http://localhost:8000/health
```

## 📝 Changelog

### Version 0.0.0
- Architecture microservices découplée
- Support Redis/Celery
- API REST complète
- Multi-projets avec clés API

## 📄 Licence

Propriétaire - Guilhem RICHARD