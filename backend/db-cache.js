/**
 * Query result caching + PostgreSQL support
 * Caches hot query results in memory with Redis fallback
 */

let redisInstance = null;

// In-memory cache (fast local fallback, with TTL)
const localCache = new Map();

const CACHE_TTLs = {
  user: 60,               // 1 min
  voucher: 30,            // 30 sec
  class: 300,             // 5 min
  attendance: 60,         // 1 min
  metrics: 10             // 10 sec
};

function setRedisInstance(redis) {
  redisInstance = redis;
}

async function cacheGet(key) {
  // Try local cache first
  const cached = localCache.get(key);
  if (cached && cached.expires > Date.now()) {
    return cached.value;
  }
  
  // Try Redis if available
  if (redisInstance) {
    try {
      const val = await redisInstance.get(`cache:${key}`);
      if (val) {
        return JSON.parse(val);
      }
    } catch (e) {
      // ignore
    }
  }
  
  return null;
}

async function cacheSet(key, value, ttlType = 'voucher') {
  const ttl = CACHE_TTLs[ttlType] || 60;
  
  // Local cache
  localCache.set(key, {
    value,
    expires: Date.now() + ttl * 1000
  });
  
  // Redis cache
  if (redisInstance) {
    try {
      await redisInstance.set(`cache:${key}`, JSON.stringify(value), 'EX', ttl);
    } catch (e) {
      // ignore
    }
  }
}

function cacheClear(pattern) {
  // Clear local cache by pattern
  for (const key of localCache.keys()) {
    if (key.includes(pattern)) {
      localCache.delete(key);
    }
  }
  
  // Redis cleanup async
  if (redisInstance) {
    redisInstance.eval(`
      local keys = redis.call('keys', ARGV[1])
      for i,k in ipairs(keys) do redis.call('del', k) end
      return #keys
    `, 0, `cache:${pattern}*`).catch(e => {});
  }
}

module.exports = {
  setRedisInstance,
  cacheGet,
  cacheSet,
  cacheClear
};
