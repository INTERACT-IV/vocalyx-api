"""
vocalyx-api/config.py
Gestion de la configuration
"""

import os
import logging
import configparser
from pathlib import Path
from typing import List

class Config:
    """Charge et gère la configuration depuis config.ini"""
    
    def __init__(self, config_file: str = "config.ini"):
        self.config = configparser.ConfigParser()
        self.config_file = config_file
        
        if not os.path.exists(config_file):
            self._create_default_config()
        
        self.config.read(config_file)
        self._load_settings()
        
    def _create_default_config(self):
        """Crée un fichier de configuration par défaut"""
        config = configparser.ConfigParser()
        
        config['DATABASE'] = {
            'url': 'postgresql://vocalyx:vocalyx_secret@localhost:5432/vocalyx_db'
        }
        
        config['REDIS'] = {
            'url': 'redis://localhost:6379/0'
        }
        
        config['CELERY'] = {
            'broker_url': 'redis://localhost:6379/0',
            'result_backend': 'redis://localhost:6379/0'
        }
        
        config['PATHS'] = {
            'upload_dir': './shared_uploads'
        }
        
        config['SECURITY'] = {
            'internal_api_key': 'CHANGE_ME_SECRET_INTERNAL_KEY',
            'admin_project_name': 'ISICOMTECH'
        }
        
        config['CORS'] = {
            'origins': 'http://localhost:8080,http://localhost:3000'
        }
        
        config['LOGGING'] = {
            'level': 'INFO',
            'file_enabled': 'true',
            'file_path': 'logs/vocalyx-api.log',
            'colored': 'true'
        }
        
        config['LIMITS'] = {
            'max_file_size_mb': '100',
            'allowed_extensions': 'wav,mp3,m4a,flac,ogg,webm'
        }
        
        with open(self.config_file, 'w') as f:
            config.write(f)
        
        logging.info(f"✅ Created default config file: {self.config_file}")
    
    def _load_settings(self):
        """Charge les paramètres dans des attributs"""
        
        # DATABASE
        self.database_url = self.config.get('DATABASE', 'url')
        
        # REDIS
        self.redis_url = self.config.get('REDIS', 'url')
        
        # CELERY
        self.celery_broker_url = self.config.get('CELERY', 'broker_url')
        self.celery_result_backend = self.config.get('CELERY', 'result_backend')
        
        # PATHS
        self.upload_dir = Path(self.config.get('PATHS', 'upload_dir'))
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        
        # SECURITY
        self.internal_api_key = self.config.get('SECURITY', 'internal_api_key')
        self.admin_project_name = self.config.get('SECURITY', 'admin_project_name')
        
        if self.internal_api_key == 'CHANGE_ME_SECRET_INTERNAL_KEY':
            logging.warning("⚠️ SECURITY: Internal API key is using default value. Please change it!")
        
        # CORS
        origins_str = self.config.get('CORS', 'origins', fallback='*')
        self.cors_origins = [o.strip() for o in origins_str.split(',') if o.strip()]
        
        # LOGGING
        self.log_level = self.config.get('LOGGING', 'level', fallback='INFO')
        self.log_file_enabled = self.config.getboolean('LOGGING', 'file_enabled', fallback=True)
        self.log_file_path = self.config.get('LOGGING', 'file_path', fallback='logs/vocalyx-api.log')
        self.log_colored = self.config.getboolean('LOGGING', 'colored', fallback=True)
        
        # LIMITS
        self.max_file_size_mb = self.config.getint('LIMITS', 'max_file_size_mb', fallback=100)
        extensions_str = self.config.get('LIMITS', 'allowed_extensions', fallback='wav,mp3')
        self.allowed_extensions = set(ext.strip().lower() for ext in extensions_str.split(','))
    
    def reload(self):
        """Recharge la configuration depuis le fichier"""
        self.config.read(self.config_file)
        self._load_settings()
        logging.info("🔄 Configuration reloaded")