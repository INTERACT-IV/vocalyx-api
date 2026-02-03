-- Migration : Ajouter la colonne text_list
-- Date : 2026-02-02
-- Description : Ajoute la colonne text_list pour stocker la liste formatée des segments avec speakers
-- Format : JSON stringifié contenant ["SPEAKER_00: texte", "SPEAKER_01: texte", ...]

-- Ajouter la colonne text_list
ALTER TABLE transcriptions 
ADD COLUMN IF NOT EXISTS text_list TEXT;

-- Vérification : Afficher la colonne ajoutée
-- SELECT column_name, data_type, is_nullable
-- FROM information_schema.columns 
-- WHERE table_name = 'transcriptions' 
--     AND column_name = 'text_list';
