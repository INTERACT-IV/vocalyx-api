-- Migration: Add initial_prompt field to transcriptions table
-- Date: 2026-01-07
-- Description: Adds support for context prompts to guide Whisper transcription

ALTER TABLE transcriptions 
ADD COLUMN IF NOT EXISTS initial_prompt TEXT NULL;

-- Add comment to document the column
COMMENT ON COLUMN transcriptions.initial_prompt IS 'Context prompt to guide Whisper transcription (e.g., "Customer service conversation between agent and client")';
