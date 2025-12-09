# Migrations de base de données

Ce dossier contient les scripts de migration SQL pour la base de données Vocalyx.

## Migration: add_enrichment_columns.sql

Ajoute les colonnes suivantes à la table `transcriptions` :
- `text_correction` (INTEGER, default=0) : Flag pour activer la correction du texte
- `enriched_text` (TEXT, nullable) : Texte corrigé si text_correction=true
- `enhanced_text` (TEXT, nullable) : Métadonnées JSON (titre, résumé, score, bullet points)

## Exécution

### Via Docker Compose

```bash
# Exécuter la migration
docker-compose exec -T postgres psql -U vocalyx -d vocalyx_db < vocalyx-api/migrations/add_enrichment_columns.sql
```

### Via psql direct

```bash
psql -U vocalyx -d vocalyx_db -f vocalyx-api/migrations/add_enrichment_columns.sql
```

### Via shell PostgreSQL

```bash
docker-compose exec postgres psql -U vocalyx -d vocalyx_db
```

Puis copier-coller le contenu du fichier SQL.

## Vérification

Après exécution, vérifier que les colonnes existent :

```sql
SELECT column_name, data_type, column_default, is_nullable
FROM information_schema.columns 
WHERE table_name = 'transcriptions' 
    AND column_name IN ('text_correction', 'enriched_text', 'enhanced_text')
ORDER BY column_name;
```
