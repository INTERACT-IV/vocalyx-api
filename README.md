# Vocalyx API

API centrale REST et WebSocket pour la gestion des transcriptions audio.

## Description

Module API central de Vocalyx exposant une interface REST pour la gestion des transcriptions, projets et utilisateurs. Fournit également une connexion WebSocket pour les mises à jour en temps réel du dashboard.

## Architecture

### Structure

```
vocalyx-api/
├── api/                    # Couche API (endpoints, auth, websocket)
├── application/            # Services applicatifs
├── domain/                 # Entités métier et repositories
├── infrastructure/         # Implémentations techniques
│   ├── database/          # Modèles SQLAlchemy et repositories
│   ├── external/          # Clients externes (Redis)
│   └── security/          # JWT et hashage de mots de passe
├── app.py                 # Point d'entrée FastAPI
├── database.py            # Configuration base de données
└── celery_app.py          # Configuration Celery
```

### Fonctionnalités

- **Endpoints REST** : CRUD pour transcriptions, projets, utilisateurs
- **Authentification** : JWT avec OAuth2
- **WebSocket** : Mises à jour temps réel via Redis Pub/Sub
- **Gestion des tâches** : Distribution via Celery
- **Administration** : Gestion des utilisateurs et projets

## Dépendances principales

### FastAPI
Framework web asynchrone Python pour la création d'APIs REST. Utilisé pour les endpoints HTTP et la documentation automatique (Swagger/OpenAPI).

### Uvicorn
Serveur ASGI haute performance pour exécuter FastAPI. Supporte le protocole WebSocket et le traitement asynchrone.

### SQLAlchemy
ORM Python pour l'interaction avec PostgreSQL. Gère les modèles de données, les sessions et les requêtes.

### Celery
Système de files d'attente distribuées pour l'exécution asynchrone de tâches. Utilisé pour distribuer les transcriptions aux workers.

### Redis / aioredis
Broker de messages pour Celery et système Pub/Sub pour les notifications WebSocket. `aioredis` fournit le client asynchrone.

### Pydantic
Validation et sérialisation de données. Utilisé pour les schémas de requêtes/réponses et la validation des modèles.

### python-jose
Bibliothèque JWT pour l'authentification. Génère et valide les tokens d'accès.

### passlib / bcrypt
Hashage sécurisé des mots de passe. `bcrypt` est l'algorithme utilisé par `passlib`.

### psycopg2-binary
Adaptateur PostgreSQL pour Python. Utilisé par SQLAlchemy pour la connexion à la base de données.

## Configuration

Variables d'environnement principales :

- `DATABASE_URL` : URL de connexion PostgreSQL
- `REDIS_URL` : URL de connexion Redis
- `CELERY_BROKER_URL` : URL du broker Celery
- `CELERY_RESULT_BACKEND` : Backend de résultats Celery
- `INTERNAL_API_KEY` : Clé pour la communication interne
- `ADMIN_PROJECT_NAME` : Nom du projet administrateur
- `CORS_ORIGINS` : Origines autorisées pour CORS
- `LOG_LEVEL` : Niveau de logging (DEBUG, INFO, WARNING, ERROR)

## Endpoints principaux

### Authentification
- `POST /api/auth/token` : Obtenir un token JWT
- `GET /api/user/me` : Profil utilisateur actuel

### Transcriptions
- `POST /api/transcriptions` : Créer une transcription
- `GET /api/transcriptions` : Lister les transcriptions
- `GET /api/transcriptions/{id}` : Détails d'une transcription
- `PUT /api/transcriptions/{id}` : Mettre à jour une transcription
- `DELETE /api/transcriptions/{id}` : Supprimer une transcription

### Projets
- `GET /api/projects` : Lister les projets
- `POST /api/projects` : Créer un projet
- `GET /api/projects/{name}` : Détails d'un projet

### Administration
- `GET /api/admin/users` : Lister les utilisateurs
- `POST /api/admin/users` : Créer un utilisateur
- `POST /api/admin/users/{id}/assign-project` : Assigner un projet
- `DELETE /api/admin/users/{id}` : Supprimer un utilisateur

### WebSocket
- `WS /api/ws/updates` : Connexion WebSocket pour les mises à jour temps réel

## WebSocket

Le module expose un endpoint WebSocket pour les mises à jour en temps réel :

- Authentification via token JWT dans l'URL
- Diffusion des mises à jour de transcriptions via Redis Pub/Sub
- Envoi périodique des statistiques des workers
- Gestion des connexions multiples via `ConnectionManager`

## Base de données

Modèles principaux :

- **User** : Utilisateurs du système
- **Project** : Projets de transcription
- **Transcription** : Métadonnées des transcriptions

Les tables sont créées automatiquement au démarrage via SQLAlchemy.

## Logs

Les logs sont écrits dans `./shared/logs/vocalyx-api.log` avec le format :

```
%(asctime)s [%(levelname)s] %(name)s: %(message)s
```

Voir `DOCUMENTATION_LOGS.md` pour la documentation complète des logs.

