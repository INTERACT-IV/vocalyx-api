"""
RedisClient - Client pour Redis Pub/Sub
"""

import logging
import aioredis
from typing import Optional

logger = logging.getLogger(__name__)


class RedisClient:
    """Client pour Redis Pub/Sub"""
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._pub: Optional[aioredis.Redis] = None
        self._sub_conn: Optional[aioredis.Redis] = None
        self._sub: Optional[aioredis.client.PubSub] = None
    
    async def connect(self):
        """Connecte le client Redis"""
        try:
            self._pub = await aioredis.from_url(self.redis_url)
            self._sub_conn = await aioredis.from_url(self.redis_url)
            self._sub = self._sub_conn.pubsub()
            logger.info("Redis client connected")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    async def disconnect(self):
        """Déconnecte le client Redis"""
        if self._pub:
            await self._pub.close()
        if self._sub_conn:
            await self._sub_conn.close()
        logger.info("Redis client disconnected")
    
    async def publish(self, channel: str, message: str):
        """Publie un message sur un canal"""
        if self._pub:
            await self._pub.publish(channel, message)
    
    async def subscribe(self, channel: str):
        """S'abonne à un canal"""
        if self._sub:
            await self._sub.subscribe(channel)
    
    @property
    def pubsub(self):
        """Retourne le client PubSub"""
        return self._sub
    
    @property
    def publisher(self):
        """Retourne le client de publication"""
        return self._pub

