import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SecurityError } from '../src/contracts.js';
import {
  GoogleRevocationSource,
  parseCacheControlMaxAge,
} from '../src/platform/trust.js';

function createMockResponse(
  bodyObj: Record<string, unknown>,
  headers: Record<string, string> = {},
  status = 200,
): Response {
  return new Response(JSON.stringify(bodyObj), {
    status,
    headers: {
      'content-type': 'application/json',
      ...headers,
    },
  });
}

const DEFAULT_SAMPLE_BODY = {
  entries: {
    '1a2b': { status: 'REVOKED' },
    '3c4d': { status: 'SUSPENDED' },
  },
};

describe('Trust & Revocation Cache Management Regressions', () => {
  // Test 1: Fresh cache control - hits cache within TTL without extra fetch
  it('serves cached serials within TTL without invoking fetch', async () => {
    let callCount = 0;
    let mockNow = 1_000_000;

    const mockFetch: typeof fetch = async () => {
      callCount++;
      return createMockResponse(DEFAULT_SAMPLE_BODY, {
        'cache-control': 'public, max-age=3600',
      });
    };

    const source = new GoogleRevocationSource({
      fetchFn: mockFetch,
      now: () => mockNow,
    });

    assert.equal(source.isReady(), false);

    // Initial fetch
    const serials1 = await source.getRevokedSerials();
    assert.equal(callCount, 1);
    assert.equal(serials1.size, 2);
    assert.equal(source.isReady(), true);

    // Advance clock halfway into TTL (1800s = 1_800_000 ms)
    mockNow += 1_800_000;
    assert.equal(source.isReady(), true);

    const serials2 = await source.getRevokedSerials();
    assert.equal(callCount, 1, 'Subsequent call within TTL must hit memory cache');
    assert.equal(serials2, serials1, 'Must return the same cached Set instance');
  });

  // Test 2: Cache-Control max-age=0, no-cache, and no-store disable caching
  it('disables cache reuse when Cache-Control is max-age=0, no-cache, or no-store', async () => {
    // 2a. no-cache
    let callCount = 0;
    let currentCacheControl = 'no-cache';

    const mockFetch: typeof fetch = async () => {
      callCount++;
      return createMockResponse(DEFAULT_SAMPLE_BODY, {
        'cache-control': currentCacheControl,
      });
    };

    const source = new GoogleRevocationSource({
      fetchFn: mockFetch,
      now: () => 1_000_000,
    });

    await source.getRevokedSerials();
    assert.equal(callCount, 1);
    assert.equal(source.isReady(), false, 'isReady must be false when no-cache is returned');

    await source.getRevokedSerials();
    assert.equal(callCount, 2, 'Must refetch immediately on subsequent call for no-cache');

    // 2b. no-store
    currentCacheControl = 'no-store, private';
    await source.getRevokedSerials();
    assert.equal(callCount, 3);
    assert.equal(source.isReady(), false, 'isReady must be false when no-store is returned');

    // 2c. max-age=0
    currentCacheControl = 'max-age=0';
    await source.getRevokedSerials();
    assert.equal(callCount, 4);
    assert.equal(source.isReady(), false, 'isReady must be false when max-age=0 is returned');

    await source.getRevokedSerials();
    assert.equal(callCount, 5, 'Must refetch immediately on subsequent call for max-age=0');
  });

  // Test 3: Subtract upstream Age header from max-age
  it('subtracts upstream Age header from max-age to compute remaining TTL', async () => {
    let callCount = 0;
    let mockNow = 2_000_000;

    // Upstream has max-age=600 (600s), but Age is 400s => remaining TTL is 200s (200,000 ms)
    const mockFetch: typeof fetch = async () => {
      callCount++;
      return createMockResponse(DEFAULT_SAMPLE_BODY, {
        'cache-control': 'public, max-age=600',
        age: '400',
      });
    };

    const source = new GoogleRevocationSource({
      fetchFn: mockFetch,
      now: () => mockNow,
    });

    await source.getRevokedSerials();
    assert.equal(callCount, 1);
    assert.equal(source.isReady(), true);

    // Advance clock to remainingTTL - 1ms (199,999 ms)
    mockNow += 199_999;
    assert.equal(source.isReady(), true);
    await source.getRevokedSerials();
    assert.equal(callCount, 1, 'Must still be fresh at remaining TTL - 1ms');

    // Advance clock 1ms further to remainingTTL (200,000 ms)
    mockNow += 1;
    assert.equal(source.isReady(), false, 'Must be stale once remaining TTL has elapsed');
    await source.getRevokedSerials();
    assert.equal(callCount, 2, 'Must trigger fresh fetch when remaining TTL elapsed');
  });

  // Test 4: Upstream Age header >= max-age or malformed Age header
  it('treats response as immediately stale if Age >= max-age or Age is malformed', async () => {
    let callCount = 0;
    let mockHeaders: Record<string, string> = {
      'cache-control': 'public, max-age=120',
      age: '150', // Age > max-age
    };

    const mockFetch: typeof fetch = async () => {
      callCount++;
      return createMockResponse(DEFAULT_SAMPLE_BODY, mockHeaders);
    };

    const source = new GoogleRevocationSource({
      fetchFn: mockFetch,
      now: () => 1_000_000,
    });

    // 4a. Age >= max-age
    await source.getRevokedSerials();
    assert.equal(callCount, 1);
    assert.equal(source.isReady(), false, 'isReady must be false when Age >= max-age');

    await source.getRevokedSerials();
    assert.equal(callCount, 2, 'Must refetch immediately when Age >= max-age');

    // 4b. Malformed non-numeric Age header failclosed
    mockHeaders = {
      'cache-control': 'public, max-age=120',
      age: 'invalid-non-numeric-age',
    };

    await source.getRevokedSerials();
    assert.equal(callCount, 3);
    assert.equal(source.isReady(), false, 'isReady must be false when Age is malformed');

    await source.getRevokedSerials();
    assert.equal(callCount, 4, 'Must refetch immediately when Age is malformed');
  });

  // Test 5: Stale exact boundary condition (age === effectiveTtlMs)
  it('strictly expires at exact TTL boundary (age >= effectiveTtlMs)', async () => {
    let callCount = 0;
    let mockNow = 5_000_000;
    const ttlSeconds = 60;
    const ttlMs = ttlSeconds * 1000;

    const mockFetch: typeof fetch = async () => {
      callCount++;
      return createMockResponse(DEFAULT_SAMPLE_BODY, {
        'cache-control': `public, max-age=${ttlSeconds}`,
      });
    };

    const source = new GoogleRevocationSource({
      fetchFn: mockFetch,
      now: () => mockNow,
      maxAgeMs: ttlMs,
    });

    await source.getRevokedSerials();
    assert.equal(callCount, 1);

    // Just before boundary: age = 59,999 ms
    mockNow += ttlMs - 1;
    assert.equal(source.isReady(), true);
    await source.getRevokedSerials();
    assert.equal(callCount, 1, 'Must hit cache at effectiveTtlMs - 1');

    // Exactly at boundary: age = 60,000 ms
    mockNow += 1;
    assert.equal(source.isReady(), false, 'Must be stale at exact boundary age === effectiveTtlMs');
    await source.getRevokedSerials();
    assert.equal(callCount, 2, 'Must execute refresh at exact boundary');
  });

  // Test 6: Clock rollback failclosed (currentTime < fetchedAt)
  it('fails closed and refreshes if system clock rolls back', async () => {
    let callCount = 0;
    let mockNow = 10_000_000;

    const mockFetch: typeof fetch = async () => {
      callCount++;
      return createMockResponse(DEFAULT_SAMPLE_BODY, {
        'cache-control': 'public, max-age=3600',
      });
    };

    const source = new GoogleRevocationSource({
      fetchFn: mockFetch,
      now: () => mockNow,
    });

    await source.getRevokedSerials();
    assert.equal(callCount, 1);
    assert.equal(source.isReady(), true);

    // Clock rollback: currentTime goes backward by 1ms (age < 0)
    mockNow -= 1;
    assert.equal(source.isReady(), false, 'isReady must return false on clock rollback');

    await source.getRevokedSerials();
    assert.equal(callCount, 2, 'Must force fresh fetch on negative age / clock rollback');
    assert.equal(source.isReady(), true, 'Must become ready after successful rollback recovery');
  });

  // Test 7: Refresh coalescing (concurrent in-flight deduplication)
  it('coalesces multiple concurrent refresh requests into a single in-flight fetch', async () => {
    let callCount = 0;
    let resolveResponse: (res: Response) => void = () => {};

    const mockFetch: typeof fetch = async () => {
      callCount++;
      return new Promise<Response>((resolve) => {
        resolveResponse = resolve;
      });
    };

    const source = new GoogleRevocationSource({
      fetchFn: mockFetch,
      now: () => 1_000_000,
    });

    // Launch 5 concurrent calls (mix of refresh and getRevokedSerials)
    const p1 = source.refresh();
    const p2 = source.getRevokedSerials();
    const p3 = source.refresh();
    const p4 = source.getRevokedSerials();
    const p5 = source.refresh();

    // While promises are in-flight, mockFetch should only have been called once
    assert.equal(callCount, 1, 'Only one HTTP request must be dispatched for concurrent callers');

    // Resolve the in-flight request
    resolveResponse(
      createMockResponse(DEFAULT_SAMPLE_BODY, {
        'cache-control': 'public, max-age=300',
      }),
    );

    const [res1, res2, res3, res4, res5] = await Promise.all([p1, p2, p3, p4, p5]);

    // All callers receive identical results
    assert.equal(res1, res2);
    assert.equal(res2, res3);
    assert.equal(res3, res4);
    assert.equal(res4, res5);
    assert.equal(callCount, 1, 'Call count remains 1 after resolution');

    // Subsequent explicit refresh after settling dispatches a new fetch
    const pNext = source.refresh();
    assert.equal(callCount, 2, 'New refresh call after completion triggers a second fetch');
    resolveResponse(createMockResponse(DEFAULT_SAMPLE_BODY));
    await pNext;
  });

  // Test 8: Unavailable refresh failclosed (no stale data leak)
  it('fails closed with REVOCATION_STATUS_UNAVAILABLE (503) when stale and refresh fails', async () => {
    let callCount = 0;
    let mockNow = 1_000_000;
    let shouldFail = false;

    const mockFetch: typeof fetch = async () => {
      callCount++;
      if (shouldFail) {
        throw new Error('Upstream 503 / Network failure');
      }
      return createMockResponse(DEFAULT_SAMPLE_BODY, {
        'cache-control': 'public, max-age=60',
      });
    };

    const source = new GoogleRevocationSource({
      fetchFn: mockFetch,
      now: () => mockNow,
    });

    // Initial fetch succeeds
    const initialSerials = await source.getRevokedSerials();
    assert.equal(callCount, 1);
    assert.equal(initialSerials.size, 2);

    // Stale: advance clock beyond TTL
    mockNow += 60_001;
    assert.equal(source.isReady(), false);

    // Make network fail
    shouldFail = true;

    // Must fail closed with 503, never return stale snapshot
    await assert.rejects(
      () => source.getRevokedSerials(),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'REVOCATION_STATUS_UNAVAILABLE');
        assert.equal(err.status, 503);
        return true;
      },
    );

    // Verify snapshot was not revived or extended
    assert.equal(source.isReady(), false, 'Stale snapshot must not be extended on refresh failure');
  });
});
