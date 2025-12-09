#!/usr/bin/env python3
"""
Script pour exécuter la migration add_enrichment_columns.sql
"""

import os
import sys
import psycopg2
from pathlib import Path

# Ajouter le répertoire parent au path pour importer config
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import Config

config = Config()

def run_migration():
    """Exécute la migration SQL"""
    # Lire le fichier SQL
    migration_file = Path(__file__).parent / "add_enrichment_columns.sql"
    
    if not migration_file.exists():
        print(f"❌ Fichier de migration non trouvé: {migration_file}")
        return False
    
    # Extraire les informations de connexion depuis DATABASE_URL
    # Format: postgresql://user:password@host:port/database
    db_url = config.database_url
    
    if not db_url:
        print("❌ DATABASE_URL non configuré")
        return False
    
    # Parser l'URL
    # Format: postgresql://vocalyx:vocalyx_secret@postgres:5432/vocalyx_db
    # ou: postgresql://vocalyx:vocalyx_secret@localhost:5432/vocalyx_db
    try:
        # Enlever le préfixe postgresql://
        if db_url.startswith("postgresql://"):
            db_url = db_url[13:]
        elif db_url.startswith("postgres://"):
            db_url = db_url[11:]
        
        # Parser user:password@host:port/database
        parts = db_url.split("@")
        if len(parts) != 2:
            raise ValueError("Format d'URL invalide")
        
        user_pass = parts[0].split(":")
        if len(user_pass) != 2:
            raise ValueError("Format user:password invalide")
        
        user = user_pass[0]
        password = user_pass[1]
        
        host_port_db = parts[1].split("/")
        if len(host_port_db) != 2:
            raise ValueError("Format host:port/database invalide")
        
        host_port = host_port_db[0].split(":")
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 5432
        database = host_port_db[1]
        
    except Exception as e:
        print(f"❌ Erreur lors du parsing de DATABASE_URL: {e}")
        print(f"   URL: {config.database_url}")
        return False
    
    print(f"📊 Connexion à la base de données...")
    print(f"   Host: {host}")
    print(f"   Port: {port}")
    print(f"   Database: {database}")
    print(f"   User: {user}")
    
    try:
        # Se connecter à la base de données
        conn = psycopg2.connect(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        print(f"✅ Connecté à la base de données")
        
        # Lire et exécuter le script SQL
        print(f"📝 Lecture du fichier de migration: {migration_file}")
        with open(migration_file, 'r', encoding='utf-8') as f:
            sql_script = f.read()
        
        print(f"🚀 Exécution de la migration...")
        cursor.execute(sql_script)
        
        # Vérifier les résultats
        cursor.execute("""
            SELECT column_name, data_type, column_default, is_nullable
            FROM information_schema.columns 
            WHERE table_name = 'transcriptions' 
                AND column_name IN ('text_correction', 'enriched_text', 'enhanced_text')
            ORDER BY column_name;
        """)
        
        results = cursor.fetchall()
        
        if results:
            print(f"\n✅ Migration réussie ! Colonnes ajoutées :")
            print(f"{'Colonne':<20} {'Type':<15} {'Défaut':<15} {'Nullable':<10}")
            print("-" * 60)
            for row in results:
                col_name, data_type, col_default, is_nullable = row
                default_str = str(col_default) if col_default else "NULL"
                print(f"{col_name:<20} {data_type:<15} {default_str:<15} {is_nullable:<10}")
        else:
            print(f"⚠️  Aucune colonne trouvée (peut-être qu'elles existaient déjà)")
        
        cursor.close()
        conn.close()
        
        print(f"\n✅ Migration terminée avec succès !")
        return True
        
    except psycopg2.Error as e:
        print(f"❌ Erreur PostgreSQL: {e}")
        return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = run_migration()
    sys.exit(0 if success else 1)
