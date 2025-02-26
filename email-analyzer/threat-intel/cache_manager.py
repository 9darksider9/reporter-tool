import redis
import json
import os

# Load environment variables
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
CACHE_TTL = int(os.getenv("CACHE_TTL", 86400))  # 24 hours

class CacheManager:
    def __init__(self):
        self.client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

    def get_cache(self, key):
        """Retrieve cached data if available"""
        data = self.client.get(key)
        return json.loads(data) if data else None

    def set_cache(self, key, value):
        """Store data in cache with TTL"""
        self.client.setex(key, CACHE_TTL, json.dumps(value))

    def clear_cache(self, key):
        """Delete specific key from cache"""
        self.client.delete(key)

# Initialize cache manager
cache_manager = CacheManager()