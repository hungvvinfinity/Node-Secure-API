import { RedisSecurityStore } from '../../src/store/redis.js';

/**
 * Probes whether a real Redis test instance is reachable.
 * - If url is undefined: returns false (allowing unit-only skips in local development).
 * - If url is explicitly empty, malformed, or unreachable: throws a sanitized
 *   Error('REDIS_TEST_UNAVAILABLE') without leaking credentials or URLs.
 * - If reachable: returns true.
 */
export async function checkRedisAvailable(url?: string, timeoutMs = 500): Promise<boolean> {
  // If undefined => false (unit-only local skips allowed)
  if (url === undefined) {
    return false;
  }

  // Blank is explicitly invalid
  if (typeof url !== 'string' || url.trim() === '') {
    throw new Error('REDIS_TEST_UNAVAILABLE');
  }

  // Check URL protocol: must be redis: or rediss:
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    throw new Error('REDIS_TEST_UNAVAILABLE');
  }

  if (parsedUrl.protocol !== 'redis:' && parsedUrl.protocol !== 'rediss:') {
    throw new Error('REDIS_TEST_UNAVAILABLE');
  }

  let store: RedisSecurityStore | undefined;
  try {
    store = new RedisSecurityStore({
      url,
      connectTimeoutMs: timeoutMs,
      commandTimeoutMs: timeoutMs
    });
    const ok = await store.ping();
    if (!ok) {
      throw new Error('REDIS_TEST_UNAVAILABLE');
    }
    return true;
  } catch {
    throw new Error('REDIS_TEST_UNAVAILABLE');
  } finally {
    if (store) {
      try {
        await store.close();
      } catch {
        // Safe disposal
      }
    }
  }
}
