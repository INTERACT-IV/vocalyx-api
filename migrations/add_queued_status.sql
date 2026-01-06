-- Migration : Ajouter le statut "queued" à l'Enum transcription_status
-- Date : 2025-01-XX
-- Description : Ajoute le statut "queued" pour distinguer les transcriptions en attente dans la file Celery

-- PostgreSQL : Modifier l'Enum pour ajouter "queued"
-- Note : PostgreSQL ne permet pas de modifier directement un Enum, il faut le recréer

-- Étape 1 : Créer un nouvel Enum avec "queued"
DO $$ BEGIN
    CREATE TYPE transcription_status_new AS ENUM ('pending', 'queued', 'processing', 'transcribed', 'done', 'error');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Étape 2 : Convertir les valeurs existantes
ALTER TABLE transcriptions 
    ALTER COLUMN status TYPE transcription_status_new 
    USING status::text::transcription_status_new;

-- Étape 3 : Supprimer l'ancien Enum et renommer le nouveau
DROP TYPE transcription_status;
ALTER TYPE transcription_status_new RENAME TO transcription_status;

-- Vérification : Afficher les statuts actuels
-- SELECT DISTINCT status FROM transcriptions;
