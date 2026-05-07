/**
 * StashPot — Redis Cache Utility
 *
 * Used by stats routes and other endpoints that need short-lived caching.
 * TTL defaults to 60 seconds.
 */

import { Redis } from 'ioredis';

let redis: Redis | null = null;

function getRedisClient(): Redis | null {
  if (!process.env.REDIS_URL) return null;
  if (redis) return redis;

  try {
    redis = new Redis(process.env.REDIS_URL, {
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: true,
    });

    redis.on('error', (err: Error) => {
      console.error('[redis] Connection error:', err.message);
    });

    redis.connect().catch((err: Error) => {
      console.error('[redis] Failed to connect:', err.message);
      redis = null;
    });

    return redis;
  } catch (err) {
    console.error('[redis] Initialization failed:', (err as Error).message);
    return null;
  }
}

/**
 * Fetch cached value or compute and cache it.
 * Falls back to computing if Redis is unavailable.
 */
export async function cached<T>(
  key: string,
  ttlSeconds: number,
  compute: () => Promise<T>,
): Promise<T> {
  const client = getRedisClient();

  if (!client) {
    // No Redis — just compute
    return compute();
  }

  try {
    const cached = await client.get(key);
    if (cached) {
      return JSON.parse(cached) as T;
    }
  } catch (err) {
    console.warn(`[cache] GET failed for key ${key}:`, (err as Error).message);
  }

  const value = await compute();

  try {
    await client.setex(key, ttlSeconds, JSON.stringify(value));
  } catch (err) {
    console.warn(`[cache] SET failed for key ${key}:`, (err as Error).message);
  }

  return value;
}

/**
 * Invalidate a cached key.
 */
export async function invalidate(key: string): Promise<void> {
  const client = getRedisClient();
  if (!client) return;

  try {
    await client.del(key);
  } catch (err) {
    console.warn(`[cache] DEL failed for key ${key}:`, (err as Error).message);
  }
}
