-- Migration: Ajout du champ initial_prompt pour le prompting système (comme WhisperX)
-- Date: 2026-01-28
-- Description: Ajoute le champ initial_prompt à la table transcriptions pour permettre
--              le prompting système dans la transcription (uniquement mode classique)

-- Ajouter la colonne initial_prompt (nullable, Text)
ALTER TABLE transcriptions 
ADD COLUMN IF NOT EXISTS initial_prompt TEXT NULL;

-- Commentaire pour documentation
COMMENT ON COLUMN transcriptions.initial_prompt IS 'Prompt initial optionnel pour guider la transcription (comme WhisperX). Utilisé uniquement en mode classique (non distribué).';
