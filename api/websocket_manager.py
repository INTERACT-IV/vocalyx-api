"""
vocalyx-api/api/websocket_manager.py
Gestionnaire de connexions WebSocket (Corrigé)
"""

import logging
from typing import List
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class ConnectionManager:
    """Gestionnaire des connexions WebSocket actives"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        logger.info("ConnectionManager initialisé")
    
    async def connect(self, websocket: WebSocket):
        """
        ✅ CORRECTION: Ne plus appeler accept() ici
        La connexion a déjà été acceptée dans l'endpoint
        """
        self.active_connections.append(websocket)
        logger.info(f"✅ Client ajouté au manager. Total: {len(self.active_connections)} connexions actives")
    
    def disconnect(self, websocket: WebSocket):
        """Retire une connexion du manager"""
        try:
            self.active_connections.remove(websocket)
            logger.info(f"Client retiré du manager. Total: {len(self.active_connections)} connexions actives")
        except ValueError:
            logger.warning("Tentative de retrait d'une connexion non présente dans le manager")
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Envoie un message à une connexion spécifique"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi d'un message personnel: {e}")
            self.disconnect(websocket)
    
    async def broadcast(self, message: dict):
        """
        Diffuse un message à toutes les connexions actives.
        Retire automatiquement les connexions mortes.
        """
        if not self.active_connections:
            logger.debug("Aucune connexion active pour le broadcast")
            return
        
        logger.debug(f"📡 Broadcast vers {len(self.active_connections)} client(s)")
        
        dead_connections = []
        
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Erreur lors du broadcast vers un client: {e}")
                dead_connections.append(connection)
        
        # Nettoyer les connexions mortes
        for dead in dead_connections:
            self.disconnect(dead)
        
        if dead_connections:
            logger.info(f"🧹 {len(dead_connections)} connexion(s) morte(s) retirée(s)")

# Instance globale du manager
manager = ConnectionManager()