/**
 * StashPot — Redis Cache Utility
 *
 * Used by stats routes and other endpoints that need short-lived caching.
 * TTL defaults to 60 seconds.
 */
/**
 * Fetch cached value or compute and cache it.
 * Falls back to computing if Redis is unavailable.
 */
export declare function cached<T>(key: string, ttlSeconds: number, compute: () => Promise<T>): Promise<T>;
/**
 * Invalidate a cached key.
 */
export declare function invalidate(key: string): Promise<void>;
