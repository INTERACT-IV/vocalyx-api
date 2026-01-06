-- Migration : Ajouter les colonnes de métriques de performance
-- Date : 2025-01-XX
-- Description : Ajoute les colonnes pour suivre le temps d'attente vs temps de traitement

-- Ajouter les colonnes de timestamps
ALTER TABLE transcriptions 
ADD COLUMN IF NOT EXISTS queued_at TIMESTAMP,
ADD COLUMN IF NOT EXISTS processing_start_time TIMESTAMP,
ADD COLUMN IF NOT EXISTS processing_end_time TIMESTAMP;

-- Ajouter la colonne de métrique
ALTER TABLE transcriptions 
ADD COLUMN IF NOT EXISTS queue_wait_time FLOAT;

-- Créer des index pour améliorer les performances des requêtes de métriques
CREATE INDEX IF NOT EXISTS idx_transcriptions_queued_at ON transcriptions(queued_at);
CREATE INDEX IF NOT EXISTS idx_transcriptions_processing_start_time ON transcriptions(processing_start_time);

-- Vérification : Afficher les colonnes ajoutées
-- SELECT column_name, data_type, is_nullable
-- FROM information_schema.columns 
-- WHERE table_name = 'transcriptions' 
--     AND column_name IN ('queued_at', 'processing_start_time', 'processing_end_time', 'queue_wait_time')
-- ORDER BY column_name;
