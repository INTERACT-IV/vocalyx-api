-- Migration: Ajout des colonnes pour l'enrichissement et la correction du texte
-- Date: 2025-12-09
-- Description: Ajoute les colonnes text_correction, enriched_text et enhanced_text à la table transcriptions

-- Vérifier si les colonnes existent déjà avant de les ajouter
DO $$
BEGIN
    -- Ajouter text_correction si elle n'existe pas
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'transcriptions' AND column_name = 'text_correction'
    ) THEN
        ALTER TABLE transcriptions 
        ADD COLUMN text_correction INTEGER DEFAULT 0;
        COMMENT ON COLUMN transcriptions.text_correction IS 'Correction du texte (orthographe, grammaire) - option séparée';
    END IF;

    -- Ajouter enriched_text si elle n'existe pas
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'transcriptions' AND column_name = 'enriched_text'
    ) THEN
        ALTER TABLE transcriptions 
        ADD COLUMN enriched_text TEXT;
        COMMENT ON COLUMN transcriptions.enriched_text IS 'Texte corrigé si text_correction=true';
    END IF;

    -- Ajouter enhanced_text si elle n'existe pas
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'transcriptions' AND column_name = 'enhanced_text'
    ) THEN
        ALTER TABLE transcriptions 
        ADD COLUMN enhanced_text TEXT;
        COMMENT ON COLUMN transcriptions.enhanced_text IS 'Texte enrichi avec métadonnées (JSON stringifié) - généré par défaut si enrichment=true';
    END IF;
END $$;

-- Vérifier que les colonnes ont été ajoutées
SELECT 
    column_name, 
    data_type, 
    column_default,
    is_nullable
FROM information_schema.columns 
WHERE table_name = 'transcriptions' 
    AND column_name IN ('text_correction', 'enriched_text', 'enhanced_text')
ORDER BY column_name;
