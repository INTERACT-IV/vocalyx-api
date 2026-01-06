"""
vocalyx-api/logging_config.py
Configuration du logging
"""

import logging
import sys
from pathlib import Path

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

def setup_logging(log_level: str = "INFO", log_file: str = None):
    """Configure le logging standard"""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    handlers = []
    
    # Handler console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(
        logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    )
    handlers.append(console_handler)
    
    # Handler fichier (optionnel)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(
            logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        )
        handlers.append(file_handler)
    
    logging.basicConfig(
        level=numeric_level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=handlers,
        force=True
    )
    
    # Configurer les loggers spécifiques
    for logger_name in ["uvicorn", "uvicorn.access", "uvicorn.error", 
                        "celery", "vocalyx"]:
        log = logging.getLogger(logger_name)
        log.setLevel(numeric_level)
        log.handlers.clear()
        for handler in handlers:
            log.addHandler(handler)
        log.propagate = False
    
    # Réduire le verbosité de watchfiles
    logging.getLogger("watchfiles").setLevel(logging.WARNING)
    
    logger = logging.getLogger("vocalyx")
    logger.info("✅ Logging configured")
    
    return logger

class ColoredFormatter(logging.Formatter):
    """Formatter avec couleurs pour le terminal"""
    
    COLORS = {
        'DEBUG': '\033[0;36m',    # Cyan
        'INFO': '\033[0;32m',     # Vert
        'WARNING': '\033[0;33m',  # Jaune
        'ERROR': '\033[0;31m',    # Rouge
        'CRITICAL': '\033[1;31m', # Rouge gras
    }
    RESET = '\033[0m'
    
    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        return super().format(record)

def setup_colored_logging(log_level: str = "INFO", log_file: str = None):
    """Configure le logging avec couleurs"""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    handlers = []
    
    # Handler console avec couleurs
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(
        ColoredFormatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    )
    handlers.append(console_handler)
    
    # Handler fichier sans couleurs
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(
            logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
        )
        handlers.append(file_handler)
    
    logging.basicConfig(
        level=numeric_level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=handlers,
        force=True
    )
    
    for logger_name in ["uvicorn", "uvicorn.access", "uvicorn.error", 
                        "celery", "vocalyx"]:
        log = logging.getLogger(logger_name)
        log.setLevel(numeric_level)
        log.handlers.clear()
        for handler in handlers:
            log.addHandler(handler)
        log.propagate = False
    
    logging.getLogger("watchfiles").setLevel(logging.WARNING)
    
    logger = logging.getLogger("vocalyx")
    logger.info("✅ Colored logging configured")
    
    return logger

def get_uvicorn_log_config(log_level: str = "INFO"):
    """Configuration de logging pour Uvicorn"""
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": LOG_FORMAT,
                "datefmt": LOG_DATE_FORMAT,
            },
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "uvicorn": {
                "handlers": ["default"],
                "level": log_level.upper(),
                "propagate": False
            },
            "uvicorn.error": {
                "handlers": ["default"],
                "level": log_level.upper(),
                "propagate": False
            },
            "uvicorn.access": {
                "handlers": ["default"],
                "level": log_level.upper(),
                "propagate": False
            },
            "watchfiles": {
                "handlers": ["default"],
                "level": "WARNING",
                "propagate": False
            },
        },
    }