/**
 * StashPot — Redis Cache Layer (Performance #11)
 *
 * Cache expensive read-only endpoints (stats, protocol info, rates).
 * Gracefully degrades to no-cache if Redis is unavailable.
 */

import Redis from 'ioredis';

let redis: Redis | null = null;

function getClient(): Redis | null {
  if (redis) return redis;
  const url = process.env.REDIS_URL;
  if (!url) return null;

  try {
    redis = new Redis(url, {
      maxRetriesPerRequest: 2,
      enableOfflineQueue:   false,
      connectTimeout:       3_000,
      lazyConnect:          false,
    });
    redis.on('error', (err) => {
      console.error('[cache] redis error:', err.message);
    });
    return redis;
  } catch {
    return null;
  }
}

/**
 * Get a cached value. Returns null on miss or failure.
 */
export async function cacheGet<T = any>(key: string): Promise<T | null> {
  const client = getClient();
  if (!client) return null;
  try {
    const raw = await client.get(`sp:${key}`);
    if (!raw) return null;
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

/**
 * Set a cached value with TTL in seconds.
 */
export async function cacheSet(key: string, value: any, ttlSecs: number = 60): Promise<void> {
  const client = getClient();
  if (!client) return;
  try {
    await client.setex(`sp:${key}`, ttlSecs, JSON.stringify(value));
  } catch {
    /* swallow — cache is best-effort */
  }
}

/**
 * Cache wrapper: if key exists, return cached value; else compute, store, return.
 */
export async function cached<T>(
  key:     string,
  ttlSecs: number,
  fn:      () => Promise<T>,
): Promise<T> {
  const hit = await cacheGet<T>(key);
  if (hit !== null) return hit;
  const fresh = await fn();
  await cacheSet(key, fresh, ttlSecs);
  return fresh;
}

/**
 * Invalidate a cache key (or all keys matching a pattern).
 */
export async function cacheDelete(keyOrPattern: string): Promise<void> {
  const client = getClient();
  if (!client) return;
  try {
    if (keyOrPattern.includes('*')) {
      const keys = await client.keys(`sp:${keyOrPattern}`);
      if (keys.length) await client.del(...keys);
    } else {
      await client.del(`sp:${keyOrPattern}`);
    }
  } catch { /* swallow */ }
}
