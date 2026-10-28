import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { createClient } from 'redis';
import { CachingSecurityStore } from '../src/store/cached.js';
import { MemorySecurityStore } from '../src/store/memory.js';
import { RedisSecurityStore } from '../src/store/redis.js';
import { SecurityService } from '../src/core/security-service.js';
import { createServer } from '../src/http/server.js';
import { buildCanonicalBuffer } from '../src/core/canonical.js';
import { SecurityError, type DeviceRecord, type DeviceSecurityProvider } from '../src/contracts.js';
import { signCanonical } from './helpers/crypto-fixtures.js';
import { checkRedisAvailable } from './helpers/redis-probe.js';

const REDIS_URL = process.env.REDIS_TEST_URL;

class MockSigningProvider implements DeviceSecurityProvider {
  readonly platform = 'android' as const;

  async verifyRegistration(): Promise<any> {
    throw new Error('Not implemented');
  }

  async verifyRequest(device: DeviceRecord, proof: any): Promise<{ signCount?: number }> {
    const isMatch = crypto.verify(
      'sha256',
      proof.canonical,
      crypto.createPublicKey(device.publicKeyPem),
      Buffer.from(proof.signature, 'base64')
    );
    if (!isMatch) {
      throw new SecurityError('INVALID_SIGNATURE', 401);
    }
    return {};
  }
}

describe('CachingSecurityStore (Performance Decorator & Invariants)', () => {
  const dummyPublicKey = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...dummy\n-----END PUBLIC KEY-----';

  function createSampleDevice(deviceId: string, extraMetadata: Record<string, unknown> = {}): DeviceRecord {
    return {
      deviceId,
      platform: 'android',
      publicKeyPem: dummyPublicKey,
      registeredAt: 1700000000000,
      lastSequence: '0',
      metadata: {
        model: 'Pixel 9',
        ...extraMetadata
      }
    };
  }

  it('proves cold-cache miss and warm-cache hit behavior with statistics tracking', async () => {
    const memory = new MemorySecurityStore();
    const cachedStore = new CachingSecurityStore(memory);

    const device = createSampleDevice('dev-cache-1');
    await memory.createDeviceNX(device);

    assert.equal(cachedStore.stats.hits, 0);
    assert.equal(cachedStore.stats.misses, 0);

    // First read: cache miss, hits inner store
    const res1 = await cachedStore.getDevice('dev-cache-1');
    assert.ok(res1);
    assert.equal(res1.deviceId, 'dev-cache-1');
    assert.equal(cachedStore.stats.misses, 1);
    assert.equal(cachedStore.stats.hits, 0);
    assert.equal(cachedStore.stats.size, 1);

    // Second read: cache hit, served from RAM
    const res2 = await cachedStore.getDevice('dev-cache-1');
    assert.ok(res2);
    assert.equal(res2.deviceId, 'dev-cache-1');
    assert.equal(cachedStore.stats.hits, 1);
    assert.equal(cachedStore.stats.misses, 1);
  });

  it('guarantees defensive structured cloning: mutating returned record does not mutate internal cache', async () => {
    const memory = new MemorySecurityStore();
    const cachedStore = new CachingSecurityStore(memory);

    const device = createSampleDevice('dev-clone-test');
    await memory.createDeviceNX(device);

    const fetched1 = await cachedStore.getDevice('dev-clone-test');
    assert.ok(fetched1);
    // Mutate the returned object
    fetched1.lastSequence = '999';
    (fetched1.metadata as any).model = 'Tampered Phone';

    // Next getDevice should return pristine cached values
    const fetched2 = await cachedStore.getDevice('dev-clone-test');
    assert.ok(fetched2);
    assert.equal(fetched2.lastSequence, '0');
    assert.equal((fetched2.metadata as any).model, 'Pixel 9');
  });

  it('enforces TTL expiration and LRU capacity bounds', async () => {
    let mockTime = 1000000;
    const memory = new MemorySecurityStore({ now: () => mockTime });
    const cachedStore = new CachingSecurityStore(memory, {
      maxEntries: 2,
      ttlMs: 5000,
      now: () => mockTime
    });

    await memory.createDeviceNX(createSampleDevice('dev-a'));
    await memory.createDeviceNX(createSampleDevice('dev-b'));
    await memory.createDeviceNX(createSampleDevice('dev-c'));

    // Cache dev-a and dev-b
    await cachedStore.getDevice('dev-a');
    await cachedStore.getDevice('dev-b');
    assert.equal(cachedStore.stats.size, 2);

    // Reading dev-c causes LRU eviction of dev-a (oldest)
    await cachedStore.getDevice('dev-c');
    assert.equal(cachedStore.stats.size, 2);

    // dev-a should now be a miss again
    const missCountBefore = cachedStore.stats.misses;
    await cachedStore.getDevice('dev-a');
    assert.equal(cachedStore.stats.misses, missCountBefore + 1);

    // Test TTL expiration: advance clock by 6000ms
    mockTime += 6000;
    const missCountBeforeTtl = cachedStore.stats.misses;
    await cachedStore.getDevice('dev-b');
    assert.equal(cachedStore.stats.misses, missCountBeforeTtl + 1);
  });

  it('guarantees challenges strictly bypass cache and remain durable and single-use', async () => {
    const memory = new MemorySecurityStore();
    const cachedStore = new CachingSecurityStore(memory);

    await cachedStore.saveChallenge('chal-1234', 'android', 60);

    // Consuming once succeeds
    const consumed1 = await cachedStore.consumeChallenge('chal-1234');
    assert.ok(consumed1);
    assert.equal(consumed1.platform, 'android');

    // Consuming again immediately fails (not cached in RAM)
    const consumed2 = await cachedStore.consumeChallenge('chal-1234');
    assert.equal(consumed2, null);
  });

  it('guarantees commitSequence always delegates to inner store: multi-gateway race rejects stale sequence', async () => {
    const sharedMemory = new MemorySecurityStore();
    // Simulate Gateway A and Gateway B wrapping the same durable store
    const gatewayA = new CachingSecurityStore(sharedMemory);
    const gatewayB = new CachingSecurityStore(sharedMemory);

    const device = createSampleDevice('dev-multi-gw');
    await sharedMemory.createDeviceNX(device);

    // Both gateways warm their caches at sequence '0'
    const devA = await gatewayA.getDevice('dev-multi-gw');
    const devB = await gatewayB.getDevice('dev-multi-gw');
    assert.equal(devA?.lastSequence, '0');
    assert.equal(devB?.lastSequence, '0');

    // Gateway A commits sequence '1' -> succeeds in inner store and updates Gateway A cache
    const resA = await gatewayA.commitSequence('dev-multi-gw', dummyPublicKey, '1');
    assert.equal(resA.ok, true);

    const devAfterCommitA = await gatewayA.getDevice('dev-multi-gw');
    assert.equal(devAfterCommitA?.lastSequence, '1');

    // Gateway B attempts to commit sequence '1' -> delegates to inner store which REJECTS with REPLAY
    const resB = await gatewayB.commitSequence('dev-multi-gw', dummyPublicKey, '1');
    assert.equal(resB.ok, false);
    if (!resB.ok) {
      assert.equal(resB.reason, 'REPLAY');
    }

    // Committing with wrong public key delegates to inner store and invalidates cache
    const wrongKeyRes = await gatewayA.commitSequence('dev-multi-gw', 'wrong-key', '2');
    assert.equal(wrongKeyRes.ok, false);
    if (!wrongKeyRes.ok) {
      assert.equal(wrongKeyRes.reason, 'KEY_MISMATCH');
    }
  });

  it('guarantees deleted/revoked record in inner store invalidates cache and prevents business execution', async () => {
    const memory = new MemorySecurityStore();
    const cachedStore = new CachingSecurityStore(memory);
    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPem = ecKey.publicKey.export({ format: 'pem', type: 'spki' }) as string;
    const privPem = ecKey.privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;

    const deviceId = 'dev-revoked-exec-test';
    const now = 1729800000000;

    // 1. Create and warm real device in cachedStore
    await cachedStore.createDeviceNX({
      deviceId,
      platform: 'android',
      publicKeyPem: pubPem,
      registeredAt: now,
      lastSequence: '0',
      metadata: { model: 'Pixel 9' }
    });

    // Warm cache: reading device puts it in RAM cache
    const warmedDev = await cachedStore.getDevice(deviceId);
    assert.ok(warmedDev);
    assert.equal(cachedStore.stats.size, 1);

    // 2. Set up SecurityService and HTTP server with business handler spy
    let businessHandlerCalls = 0;
    const provider = new MockSigningProvider();
    const service = new SecurityService({
      store: cachedStore,
      providers: [provider],
      now: () => now
    });

    const app = createServer({
      securityService: service,
      store: cachedStore,
      businessHandler: async (_req, res) => {
        businessHandlerCalls++;
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
      }
    });

    const server = await new Promise<http.Server>((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    const addr = server.address() as any;
    const baseUrl = `http://127.0.0.1:${addr.port}`;

    try {
      // 3. Delete the SAME record from inner store while cachedStore STILL has it in RAM
      // In MemorySecurityStore, deleting from the underlying devices map simulates out-of-band admin deletion
      (memory as any).devices.delete(deviceId);

      // Verify device is still present in RAM cache before request
      assert.equal(cachedStore.stats.size, 1);

      // 4. Client sends request with VALID signature for sequence 1 signed by device's private key
      const target = '/api/tarot/read';
      const rawBody = Buffer.from(JSON.stringify({ query: 'future' }), 'utf8');
      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', target, rawBody);
      const signature = signCanonical(privPem, canonical);

      const res = await new Promise<{ status: number; body: string }>((resolve, reject) => {
        const req = http.request(
          new URL(target, baseUrl),
          {
            method: 'POST',
            headers: {
              Connection: 'close',
              'content-type': 'application/json',
              'x-device-id': deviceId,
              'x-timestamp': String(now),
              'x-sequence': '1',
              'x-signature': signature
            }
          },
          (r) => {
            const chunks: Buffer[] = [];
            r.on('data', (c) => chunks.push(c));
            r.on('end', () =>
              resolve({
                status: r.statusCode || 500,
                body: Buffer.concat(chunks).toString('utf8')
              })
            );
          }
        );
        req.on('error', reject);
        req.write(rawBody);
        req.end();
      });

      // 5. Must fail closed with 401 DEVICE_NOT_REGISTERED
      assert.equal(res.status, 401);
      const errJson = JSON.parse(res.body);
      assert.equal(errJson.error, 'DEVICE_NOT_REGISTERED');

      // CRITICAL SECURITY INVARIANT: Business handler must NEVER be called!
      assert.equal(businessHandlerCalls, 0);

      // CRITICAL CACHE INVARIANT: Cache must be invalidated upon commitSequence NOT_FOUND!
      const devAfterAttempt = await cachedStore.getDevice(deviceId);
      assert.equal(devAfterAttempt, null);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await cachedStore.close();
    }
  });

  it('clears volatile cache on close()', async () => {
    const memory = new MemorySecurityStore();
    const cachedStore = new CachingSecurityStore(memory);

    await cachedStore.createDeviceNX(createSampleDevice('dev-close-test'));
    assert.equal(cachedStore.stats.size, 1);

    await cachedStore.close();
    assert.equal(cachedStore.stats.size, 0);
    assert.equal(cachedStore.stats.hits, 0);
    assert.equal(cachedStore.stats.misses, 0);
  });

  describe('Durable Receipt Persistence & Request-Slim Hot Path (Real Redis Integration)', async () => {
    const isRedisAvailable = await checkRedisAvailable(REDIS_URL);

    if (!isRedisAvailable) {
      it.skip('Skipping Redis receipt tests: REDIS_TEST_URL not reachable', () => {});
      return;
    }

    const redisUrl = REDIS_URL!;

    it('proves durable receipt persists in Redis HSET while getDevice and RAM cache return request-slim metadata', async () => {
      const prefix = `test:sec:receipt:${crypto.randomUUID()}:`;
      const redisStore = new RedisSecurityStore({ url: redisUrl, keyPrefix: prefix });
      const cachedStore = new CachingSecurityStore(redisStore);

      const rawClient = createClient({ url: redisUrl });
      rawClient.on('error', () => {});
      await rawClient.connect();

      const deviceId = 'dev-receipt-proof-1';
      const fakeReceipt = Buffer.alloc(2048, 0xef).toString('base64');
      const sampleDevice: DeviceRecord = {
        deviceId,
        platform: 'android',
        publicKeyPem: dummyPublicKey,
        registeredAt: Date.now(),
        lastSequence: '0',
        keyId: 'attest-key-123',
        signCount: 1,
        metadata: {
          receipt: fakeReceipt,
          carrier: 'T-Mobile',
          country: 'US'
        }
      };

      try {
        // 1. Create device via CachingSecurityStore (delegates to RedisSecurityStore)
        const created = await cachedStore.createDeviceNX(sampleDevice);
        assert.equal(created, true);

        // 2. PROVE PRODUCTION DURABLE RECEIPT: Raw Redis HGET on the receipt field
        const redisDeviceKey = `${prefix}device:${deviceId}`;
        const rawReceiptInRedis = await rawClient.hGet(redisDeviceKey, 'receipt');
        assert.equal(
          rawReceiptInRedis,
          fakeReceipt,
          'Redis HSET receipt field must persist exact receipt bytes durably'
        );

        // 3. PROVE HOT PATH SLIMMING: RedisSecurityStore.getDevice excludes receipt from HMGET
        const redisFetched = await redisStore.getDevice(deviceId);
        assert.ok(redisFetched);
        assert.equal(redisFetched.metadata.receipt, undefined);
        assert.equal(redisFetched.metadata.carrier, 'T-Mobile');
        assert.equal(redisFetched.metadata.country, 'US');

        // 4. PROVE RAM CACHE SLIMMING: CachingSecurityStore.getDevice excludes receipt in RAM
        const cachedFetched = await cachedStore.getDevice(deviceId);
        assert.ok(cachedFetched);
        assert.equal(cachedFetched.metadata.receipt, undefined);
        assert.equal(cachedFetched.metadata.carrier, 'T-Mobile');
        assert.equal(cachedFetched.metadata.country, 'US');
      } finally {
        const keys = await rawClient.keys(`${prefix}*`);
        if (keys.length > 0) {
          await rawClient.del(keys);
        }
        await rawClient.quit();
        await cachedStore.close();
      }
    });
  });
});
