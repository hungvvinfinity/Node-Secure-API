import test, { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import crypto from 'node:crypto';
import { createClient, type RedisClientType } from 'redis';
import { MemorySecurityStore } from '../src/store/memory.js';
import { RedisSecurityStore } from '../src/store/redis.js';
import { SecurityError, type DeviceRecord } from '../src/contracts.js';
import { checkRedisAvailable } from './helpers/redis-probe.js';

describe('Security Store Unit & Integration Tests', () => {
  const REDIS_TEST_URL = process.env.REDIS_TEST_URL;

  describe('MemorySecurityStore (Unit)', () => {
    it('saves and consumes challenge exactly once', async () => {
      const store = new MemorySecurityStore();
      const challenge = crypto.randomBytes(32).toString('hex');

      await store.saveChallenge(challenge, 'android', 60);

      // First consume succeeds
      const first = await store.consumeChallenge(challenge);
      assert.ok(first);
      assert.equal(first.platform, 'android');

      // Second consume returns null (single-use guarantee)
      const second = await store.consumeChallenge(challenge);
      assert.equal(second, null);

      await store.close();
    });

    it('rejects invalid or negative TTL with INVALID_CHALLENGE (400)', async () => {
      const store = new MemorySecurityStore();
      const challenge = crypto.randomBytes(32).toString('hex');

      await assert.rejects(
        () => store.saveChallenge(challenge, 'android', -1),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_CHALLENGE');
          assert.equal(err.status, 400);
          return true;
        }
      );

      await assert.rejects(
        () => store.saveChallenge(challenge, 'android', 1.5),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_CHALLENGE');
          assert.equal(err.status, 400);
          return true;
        }
      );

      await store.close();
    });

    it('rejects expired challenge via injected clock at boundary', async () => {
      let currentClock = 1729800000000;
      const store = new MemorySecurityStore({ now: () => currentClock });
      const challenge = crypto.randomBytes(32).toString('hex');

      // Save challenge with 60 seconds TTL (expires at currentClock + 60000)
      await store.saveChallenge(challenge, 'android', 60);

      // Advance clock right to the exact expiration boundary (+60000 ms)
      currentClock += 60000;

      const consumed = await store.consumeChallenge(challenge);
      assert.equal(consumed, null, 'Challenge at or beyond expiration boundary must return null');

      await store.close();
    });

    it('guarantees exactly 1 winner in 20 concurrent challenge consume attempts', async () => {
      const store = new MemorySecurityStore();
      const challenge = crypto.randomBytes(32).toString('hex');
      await store.saveChallenge(challenge, 'android', 60);

      const attempts = Array.from({ length: 20 }, () => store.consumeChallenge(challenge));
      const results = await Promise.all(attempts);

      const winners = results.filter((r) => r !== null);
      const losers = results.filter((r) => r === null);

      assert.equal(winners.length, 1, 'Exactly one concurrent consume must win');
      assert.equal(losers.length, 19, 'Remaining 19 concurrent consumes must fail');

      await store.close();
    });

    it('creates device NX without overwrite or sequence reset', async () => {
      const store = new MemorySecurityStore();
      const device: DeviceRecord = {
        deviceId: 'dev-1',
        platform: 'android',
        publicKeyPem: 'pem-1',
        lastSequence: '0',
        registeredAt: Date.now(),
        metadata: {}
      };

      const created = await store.createDeviceNX(device);
      assert.equal(created, true);

      // Advance sequence to 100
      await store.commitSequence('dev-1', 'pem-1', '100');

      // Re-register attempt with same deviceId but lastSequence=0
      const secondRegister = await store.createDeviceNX(device);
      assert.equal(secondRegister, false, 'Re-registration must be rejected by NX');

      // Sequence must remain 100 (never reset!)
      const current = await store.getDevice('dev-1');
      assert.equal(current?.lastSequence, '100');

      await store.close();
    });

    it('enforces atomic CAS sequence with >2^53 BigInt support', async () => {
      const store = new MemorySecurityStore();
      const device: DeviceRecord = {
        deviceId: 'dev-bigint',
        platform: 'android',
        publicKeyPem: 'pem-bigint',
        lastSequence: '9007199254740992', // 2^53
        registeredAt: Date.now(),
        metadata: {}
      };
      await store.createDeviceNX(device);

      // Advance to 2^53 + 1
      const res1 = await store.commitSequence('dev-bigint', 'pem-bigint', '9007199254740993');
      assert.equal(res1.ok, true);

      // Replay attempt with same sequence
      const resReplay = await store.commitSequence('dev-bigint', 'pem-bigint', '9007199254740993');
      assert.equal(resReplay.ok, false);
      assert.equal(resReplay.reason, 'REPLAY');

      // Regressive sequence attempt
      const resLower = await store.commitSequence('dev-bigint', 'pem-bigint', '9007199254740990');
      assert.equal(resLower.ok, false);
      assert.equal(resLower.reason, 'REPLAY');

      // Key mismatch
      const resKey = await store.commitSequence('dev-bigint', 'wrong-pem', '9007199254740995');
      assert.equal(resKey.ok, false);
      assert.equal(resKey.reason, 'KEY_MISMATCH');

      // Unknown device
      const resUnknown = await store.commitSequence('unknown-dev', 'pem-bigint', '1');
      assert.equal(resUnknown.ok, false);
      assert.equal(resUnknown.reason, 'NOT_FOUND');

      await store.close();
    });
  });

  describe('RedisSecurityStore (Real Redis Integration)', () => {
    let redisAvailable = false;
    let rootClient: RedisClientType | null = null;
    const trackedPrefixes: string[] = [];

    before(async () => {
      redisAvailable = await checkRedisAvailable(REDIS_TEST_URL);
      if (!redisAvailable) {
        return;
      }

      rootClient = createClient({
        url: REDIS_TEST_URL,
        disableOfflineQueue: true,
        commandOptions: { timeout: 500 },
        socket: {
          connectTimeout: 500,
          reconnectStrategy: false
        }
      }) as RedisClientType;
      rootClient.on('error', () => {}); // Safe error listener prevents unhandled error crashes

      let timer: NodeJS.Timeout | undefined;
      try {
        const timeoutPromise = new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error('REDIS_TEST_UNAVAILABLE')), 500);
        });
        await Promise.race([rootClient.connect(), timeoutPromise]);
      } catch {
        if (rootClient) {
          try {
            rootClient.destroy();
          } catch {}
          rootClient = null;
        }
        throw new Error('REDIS_TEST_UNAVAILABLE');
      } finally {
        if (timer) {
          clearTimeout(timer);
        }
      }
    });

    after(async () => {
      // Clean up only our own tracked test prefixes; NEVER CALL FLUSHDB
      if (rootClient && rootClient.isOpen) {
        for (const prefix of trackedPrefixes) {
          try {
            const keys = await rootClient.keys(`${prefix}*`);
            if (keys.length > 0) {
              await rootClient.del(keys);
            }
          } catch {}
        }
        try {
          await rootClient.quit();
        } catch {
          try {
            rootClient.destroy();
          } catch {}
        }
      }
    });

    function getTestPrefix(): string {
      const p = `test:sec:${crypto.randomUUID().slice(0, 8)}:`;
      trackedPrefixes.push(p);
      return p;
    }

    it('connects to real Redis test instance without FLUSHDB', async (t) => {
      if (!redisAvailable) {
        t.skip(`Real Redis unavailable at ${REDIS_TEST_URL}`);
        return;
      }

      const prefix = getTestPrefix();
      const store = new RedisSecurityStore({
        url: REDIS_TEST_URL,
        keyPrefix: prefix,
        connectTimeoutMs: 1000,
        commandTimeoutMs: 1000
      });

      assert.equal(await store.ping(), true);
      await store.close();
    });

    it('cold-start concurrency regression: 20 simultaneous pings on newly initialized store all succeed', async (t) => {
      if (!redisAvailable) {
        t.skip(`Real Redis unavailable at ${REDIS_TEST_URL}`);
        return;
      }

      const prefix = getTestPrefix();
      // Brand new cold store without previous connection
      const coldStore = new RedisSecurityStore({
        url: REDIS_TEST_URL,
        keyPrefix: prefix,
        connectTimeoutMs: 1000,
        commandTimeoutMs: 1000
      });

      // Fire 20 concurrent pings simultaneously on cold client
      const pingPromises = Array.from({ length: 20 }, () => coldStore.ping());
      const results = await Promise.all(pingPromises);

      for (const res of results) {
        assert.equal(res, true, 'Every concurrent ping during cold-start connection must return true');
      }

      await coldStore.close();
    });

    it('atomically saves and single-use consumes challenge in Redis', async (t) => {
      if (!redisAvailable) {
        t.skip(`Real Redis unavailable at ${REDIS_TEST_URL}`);
        return;
      }

      const prefix = getTestPrefix();
      const store = new RedisSecurityStore({ url: REDIS_TEST_URL, keyPrefix: prefix });
      const challenge = crypto.randomBytes(32).toString('hex');

      await store.saveChallenge(challenge, 'android', 60);

      // First consume
      const res1 = await store.consumeChallenge(challenge);
      assert.ok(res1);
      assert.equal(res1.platform, 'android');

      // Second consume returns null
      const res2 = await store.consumeChallenge(challenge);
      assert.equal(res2, null);

      await store.close();
    });

    it('guarantees exactly 1 winner in 20 concurrent challenge consume attempts in Redis', async (t) => {
      if (!redisAvailable) {
        t.skip(`Real Redis unavailable at ${REDIS_TEST_URL}`);
        return;
      }

      const prefix = getTestPrefix();
      const store = new RedisSecurityStore({ url: REDIS_TEST_URL, keyPrefix: prefix });
      const challenge = crypto.randomBytes(32).toString('hex');
      await store.saveChallenge(challenge, 'android', 60);

      const attempts = Array.from({ length: 20 }, () => store.consumeChallenge(challenge));
      const results = await Promise.all(attempts);

      const winners = results.filter((r) => r !== null);
      const losers = results.filter((r) => r === null);

      assert.equal(winners.length, 1, 'Only 1 winner across 20 concurrent consumes in Redis');
      assert.equal(losers.length, 19, '19 losers across 20 concurrent consumes in Redis');

      await store.close();
    });

    it('creates device with NX and prevents overwrite/reset in Redis', async (t) => {
      if (!redisAvailable) {
        t.skip(`Real Redis unavailable at ${REDIS_TEST_URL}`);
        return;
      }

      const prefix = getTestPrefix();
      const store = new RedisSecurityStore({ url: REDIS_TEST_URL, keyPrefix: prefix });

      const deviceId = `dev-${crypto.randomUUID()}`;
      const device: DeviceRecord = {
        deviceId,
        platform: 'android',
        publicKeyPem: 'spki-pem-real',
        lastSequence: '0',
        registeredAt: Date.now(),
        metadata: { model: 'Pixel 9' }
      };

      const created = await store.createDeviceNX(device);
      assert.equal(created, true);

      // Advance sequence to 50
      const commitRes = await store.commitSequence(deviceId, 'spki-pem-real', '50');
      assert.equal(commitRes.ok, true);

      // Attempt re-registration
      const reRegister = await store.createDeviceNX(device);
      assert.equal(reRegister, false, 'createDeviceNX must reject existing deviceId');

      // Stored device sequence must still be 50
      const stored = await store.getDevice(deviceId);
      assert.equal(stored?.lastSequence, '50');
      assert.equal((stored?.metadata as any)?.model, 'Pixel 9');

      await store.close();
    });

    it('guarantees exactly 1 winner in 20 concurrent requests with the SAME sequence in Redis Lua', async (t) => {
      if (!redisAvailable) {
        t.skip(`Real Redis unavailable at ${REDIS_TEST_URL}`);
        return;
      }

      const prefix = getTestPrefix();
      const store = new RedisSecurityStore({ url: REDIS_TEST_URL, keyPrefix: prefix });

      const deviceId = `race-dev-${crypto.randomUUID()}`;
      await store.createDeviceNX({
        deviceId,
        platform: 'android',
        publicKeyPem: 'pem-race',
        lastSequence: '0',
        registeredAt: Date.now(),
        metadata: {}
      });

      // 20 concurrent requests with sequence '10'
      const racingSequence = '10';
      const racePromises = Array.from({ length: 20 }, () =>
        store.commitSequence(deviceId, 'pem-race', racingSequence)
      );

      const results = await Promise.all(racePromises);
      const winners = results.filter((r) => r.ok === true);
      const replays = results.filter((r) => r.ok === false && r.reason === 'REPLAY');

      assert.equal(winners.length, 1, 'Exactly one concurrent request must win CAS sequence advance');
      assert.equal(replays.length, 19, 'All other 19 concurrent requests must fail with REPLAY');

      // Subsequent request with sequence 11 succeeds
      const nextRes = await store.commitSequence(deviceId, 'pem-race', '11');
      assert.equal(nextRes.ok, true);

      await store.close();
    });

    it('correctly handles sequence comparison > 2^53 in Redis Lua without precision loss', async (t) => {
      if (!redisAvailable) {
        t.skip(`Real Redis unavailable at ${REDIS_TEST_URL}`);
        return;
      }

      const prefix = getTestPrefix();
      const store = new RedisSecurityStore({ url: REDIS_TEST_URL, keyPrefix: prefix });

      const deviceId = `big-dev-${crypto.randomUUID()}`;
      await store.createDeviceNX({
        deviceId,
        platform: 'android',
        publicKeyPem: 'pem-big',
        lastSequence: '9007199254740992', // 2^53
        registeredAt: Date.now(),
        metadata: {}
      });

      // Advance to 9007199254740993 (2^53 + 1)
      const res1 = await store.commitSequence(deviceId, 'pem-big', '9007199254740993');
      assert.equal(res1.ok, true);

      // Attempt with lower sequence 9007199254740990 -> Replay
      const resLower = await store.commitSequence(deviceId, 'pem-big', '9007199254740990');
      assert.equal(resLower.ok, false);
      assert.equal(resLower.reason, 'REPLAY');

      // Attempt with identical sequence 9007199254740993 -> Replay
      const resSame = await store.commitSequence(deviceId, 'pem-big', '9007199254740993');
      assert.equal(resSame.ok, false);
      assert.equal(resSame.reason, 'REPLAY');

      // Advance to MAX_INT64: 9223372036854775807
      const resMax = await store.commitSequence(deviceId, 'pem-big', '9223372036854775807');
      assert.equal(resMax.ok, true);

      await store.close();
    });

    it('fails closed and prevents mutation on corrupted Redis state', async (t) => {
      if (!redisAvailable || !rootClient) {
        t.skip(`Real Redis unavailable at ${REDIS_TEST_URL}`);
        return;
      }

      const prefix = getTestPrefix();
      const store = new RedisSecurityStore({ url: REDIS_TEST_URL, keyPrefix: prefix });

      const deviceId = `corrupt-dev-${crypto.randomUUID()}`;
      const deviceKey = `${prefix}device:${deviceId}`;

      // Corrupt state in Redis: write a malformed non-decimal lastSequence
      await rootClient.hSet(deviceKey, {
        deviceId,
        platform: 'android',
        publicKeyPem: 'pem-corrupt',
        lastSequence: 'INVALID_CORRUPTED_SEQ',
        registeredAt: String(Date.now()),
        signCount: 'CORRUPTED_SIGN_COUNT'
      });

      // Attempting commitSequence on corrupted device must reject / fail closed without mutating
      const result = await store.commitSequence(deviceId, 'pem-corrupt', '100');
      assert.equal(result.ok, false);

      // Verify the key in Redis was NOT mutated into a valid sequence
      const storedLastSeq = await rootClient.hGet(deviceKey, 'lastSequence');
      assert.equal(storedLastSeq, 'INVALID_CORRUPTED_SEQ', 'Corrupt sequence must not be mutated');

      await store.close();
    });

    it('handles blackhole TCP server gracefully with bounded timeout without hanging', async () => {
      const sockets = new Set<net.Socket>();
      const blackholeServer = net.createServer((socket) => {
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
      });

      await new Promise<void>((resolve) => {
        blackholeServer.listen(0, '127.0.0.1', () => resolve());
      });

      const addr = blackholeServer.address() as net.AddressInfo;
      const blackholeUrl = `redis://127.0.0.1:${addr.port}`;

      const store = new RedisSecurityStore({
        url: blackholeUrl,
        keyPrefix: 'sec:blackhole:',
        connectTimeoutMs: 150,
        commandTimeoutMs: 150
      });

      const startTime = Date.now();
      const pingResult = await store.ping();
      const durationMs = Date.now() - startTime;

      // Ping should return false within bounded time (well under 1500ms)
      assert.equal(pingResult, false);
      assert.ok(durationMs < 1500, `Ping to blackhole must not hang (took ${durationMs}ms)`);

      // Store close must not hang
      await store.close();

      // Probe helper must also fail closed with REDIS_TEST_UNAVAILABLE within bounded time
      await assert.rejects(
        () => checkRedisAvailable(blackholeUrl, 150),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'REDIS_TEST_UNAVAILABLE');
          return true;
        }
      );

      // Clean up server and destroy only own blackhole sockets
      for (const s of sockets) {
        s.destroy();
      }
      sockets.clear();

      await new Promise<void>((resolve) => {
        blackholeServer.close(() => resolve());
      });
    });
  });
});
