import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { createClient } from 'redis';
import { RedisSecurityStore } from '../src/store/redis.js';
import { SecurityService } from '../src/core/security-service.js';
import { AndroidSecurityProvider } from '../src/platform/android.js';
import { IOSSecurityProvider } from '../src/platform/ios.js';
import { AppleReceiptVerifier } from '../src/platform/ios-receipt.js';
import { createServer } from '../src/http/server.js';
import { buildCanonicalBuffer } from '../src/core/canonical.js';
import {
  createAttestationChain,
  signCanonical,
  createRootCA
} from './helpers/crypto-fixtures.js';
import {
  createIosAttestationFixture,
  createIosAssertion,
  createAppleAttestRootCA,
  createReceiptCA
} from './helpers/ios-fixtures.js';
import { checkRedisAvailable } from './helpers/redis-probe.js';

const REDIS_URL = process.env.REDIS_TEST_URL;

interface HttpResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  json: () => any;
}

function makeRequest(
  baseUrl: string,
  options: {
    method?: string;
    path: string;
    headers?: Record<string, string>;
    body?: string | Buffer;
  }
): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const url = new URL(options.path, baseUrl);
    const reqHeaders = {
      Connection: 'close',
      ...options.headers
    };
    const req = http.request(
      url,
      {
        method: options.method ?? 'GET',
        headers: reqHeaders
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const bodyStr = Buffer.concat(chunks).toString('utf8');
          resolve({
            status: res.statusCode || 500,
            headers: res.headers,
            body: bodyStr,
            json: () => {
              try {
                return JSON.parse(bodyStr);
              } catch {
                return null;
              }
            }
          });
        });
      }
    );

    req.on('error', reject);
    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

describe('Redis Persistence Across Restart & Server Lifecycle', async () => {
  const isRedisAvailable = await checkRedisAvailable(REDIS_URL);

  if (!isRedisAvailable) {
    it.skip('Skipping Redis persistence tests: REDIS_TEST_URL not reachable', () => {});
    return;
  }

  const redisUrl = REDIS_URL!;

  async function cleanupPrefix(prefix: string) {
    const rawClient = createClient({ url: redisUrl });
    rawClient.on('error', () => {});
    await rawClient.connect();
    try {
      const keys = await rawClient.keys(`${prefix}*`);
      if (keys.length > 0) {
        await rawClient.del(keys);
      }
    } finally {
      await rawClient.quit();
    }
  }

  it('proves Redis store preserves sequence, signCount and keys across store close and reopen without mutation', async () => {
    const prefix = `test:sec:persist:${crypto.randomUUID()}:`;
    const deviceId = 'persist-dev-1';
    const initialKey = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk1...fakeA\n-----END PUBLIC KEY-----';
    const wrongKey = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk2...fakeB\n-----END PUBLIC KEY-----';

    try {
      // 1. Initial Store Session
      const store1 = new RedisSecurityStore({ url: redisUrl, keyPrefix: prefix });
      const created = await store1.createDeviceNX({
        deviceId,
        platform: 'android',
        publicKeyPem: initialKey,
        registeredAt: Date.now(),
        lastSequence: '0',
        metadata: { model: 'pixel-9' }
      });
      assert.equal(created, true);

      // Commit sequence 1
      const res1 = await store1.commitSequence(deviceId, initialKey, '1');
      assert.equal(res1.ok, true);

      // Commit sequence 2
      const res2 = await store1.commitSequence(deviceId, initialKey, '2');
      assert.equal(res2.ok, true);

      // Verify sequence is 2
      const dev1 = await store1.getDevice(deviceId);
      assert.equal(dev1?.lastSequence, '2');

      // Close store 1 connection
      await store1.close();

      // 2. Reopened Store Session (Brand new instance on same prefix)
      const store2 = new RedisSecurityStore({ url: redisUrl, keyPrefix: prefix });

      // Verify device survived restart exactly
      const dev2 = await store2.getDevice(deviceId);
      assert.ok(dev2);
      assert.equal(dev2.deviceId, deviceId);
      assert.equal(dev2.publicKeyPem, initialKey);
      assert.equal(dev2.lastSequence, '2');

      // Verify replaying sequence 2 is rejected
      const replayRes = await store2.commitSequence(deviceId, initialKey, '2');
      assert.equal(replayRes.ok, false);
      if (!replayRes.ok) {
        assert.equal(replayRes.reason, 'REPLAY');
      }

      // Verify committing with wrong public key is rejected
      const wrongKeyRes = await store2.commitSequence(deviceId, wrongKey, '3');
      assert.equal(wrongKeyRes.ok, false);
      if (!wrongKeyRes.ok) {
        assert.equal(wrongKeyRes.reason, 'KEY_MISMATCH');
      }

      // INVARIANT: Failed commit must NOT advance sequence
      const devAfterFailed = await store2.getDevice(deviceId);
      assert.equal(devAfterFailed?.lastSequence, '2');

      // Verify sequence 3 succeeds
      const res3 = await store2.commitSequence(deviceId, initialKey, '3');
      assert.equal(res3.ok, true);

      const devAfter3 = await store2.getDevice(deviceId);
      assert.equal(devAfter3?.lastSequence, '3');

      // INVARIANT: createDeviceNX must not reset sequence or overwrite keys
      const resetAttempt = await store2.createDeviceNX({
        deviceId,
        platform: 'android',
        publicKeyPem: wrongKey,
        registeredAt: Date.now(),
        lastSequence: '0',
        metadata: { model: 'rogue' }
      });
      assert.equal(resetAttempt, false);

      const devAfterResetAttempt = await store2.getDevice(deviceId);
      assert.equal(devAfterResetAttempt?.lastSequence, '3');
      assert.equal(devAfterResetAttempt?.publicKeyPem, initialKey);

      await store2.close();
    } finally {
      await cleanupPrefix(prefix);
    }
  });

  it('proves full HTTP server restart with Redis persistence enforces iOS signCount and sequence continuity', async () => {
    const prefix = `test:sec:ios-http-persist:${crypto.randomUUID()}:`;
    const now = 1729800000000;
    const appId = 'TEAMID123.com.astrology.tarot';

    const appleRootCA = await createAppleAttestRootCA({ now });
    const receiptRootCA = await createReceiptCA({ now });

    function createIosServerInstance() {
      const store = new RedisSecurityStore({ url: redisUrl, keyPrefix: prefix });
      const provider = new IOSSecurityProvider({
        trustAnchors: [appleRootCA.certPem],
        appId,
        receiptVerifier: new AppleReceiptVerifier({
          trustAnchors: [receiptRootCA.certPem],
          now: () => now
        }),
        now: () => now
      });

      const service = new SecurityService({
        store,
        providers: [provider],
        now: () => now
      });

      const app = createServer({
        securityService: service,
        store,
        businessHandler: async (_req: http.IncomingMessage, res: http.ServerResponse) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ status: 'success', reading: 'The Star' }));
        }
      });

      return { app, store, service };
    }

    let server1: http.Server | undefined;
    let inst1: ReturnType<typeof createIosServerInstance> | undefined;
    let server2: http.Server | undefined;
    let inst2: ReturnType<typeof createIosServerInstance> | undefined;

    try {
      // 1. Start Server 1
      inst1 = createIosServerInstance();
      server1 = await new Promise<http.Server>((resolve) => {
        const s = inst1!.app.listen(0, '127.0.0.1', () => resolve(s));
      });
      const addr1 = server1.address() as any;
      const baseUrl1 = `http://127.0.0.1:${addr1.port}`;

      // Step A: Issue challenge
      const chResp = await makeRequest(baseUrl1, {
        method: 'POST',
        path: '/api/auth/challenge',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ platform: 'ios' })
      });
      assert.equal(chResp.status, 200);
      const chData = chResp.json();
      assert.equal(chData.status, 'SUCCESS');
      const challenge = chData.challenge;

      // Step B: Register device using real iOS attestation
      const regFixture = await createIosAttestationFixture({
        appId,
        now,
        challenge,
        rootCA: appleRootCA,
        receiptRootCA
      });

      const regResp = await makeRequest(baseUrl1, {
        method: 'POST',
        path: '/api/auth/register-device',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          challenge,
          attestationObject: regFixture.attestationObjectBase64,
          keyId: regFixture.keyId
        })
      });
      assert.equal(regResp.status, 200);
      const regData = regResp.json();
      assert.equal(regData.status, 'SUCCESS');
      const deviceId = regData.deviceId;

      // Step C: Send authenticated request seq=1, counter=1 on Server 1
      const rawBody1 = Buffer.from(JSON.stringify({ question: 'destiny' }), 'utf8');
      const target = '/api/tarot/read';
      const canonical1 = buildCanonicalBuffer(String(now), '1', 'POST', target, rawBody1);
      const assertion1 = createIosAssertion({
        appId,
        privateKeyPem: regFixture.leafPrivateKeyPem,
        canonicalBuffer: canonical1,
        counter: 1
      });

      const req1Resp = await makeRequest(baseUrl1, {
        method: 'POST',
        path: target,
        headers: {
          'content-type': 'application/json',
          'x-device-id': deviceId,
          'x-timestamp': String(now),
          'x-sequence': '1',
          'x-assertion': assertion1.assertionBase64
        },
        body: rawBody1
      });
      assert.equal(req1Resp.status, 200);
      assert.equal(req1Resp.json().reading, 'The Star');

      // Shutdown Server 1 completely
      await new Promise<void>((resolve) => server1!.close(() => resolve()));
      await inst1.store.close();
      server1 = undefined;
      inst1 = undefined;

      // 2. Start Server 2 (Fresh process on same Redis prefix)
      inst2 = createIosServerInstance();
      server2 = await new Promise<http.Server>((resolve) => {
        const s = inst2!.app.listen(0, '127.0.0.1', () => resolve(s));
      });
      const addr2 = server2.address() as any;
      const baseUrl2 = `http://127.0.0.1:${addr2.port}`;

      // Step D: Replay seq=1, counter=1 on Server 2 -> MUST BE REJECTED
      const replayResp = await makeRequest(baseUrl2, {
        method: 'POST',
        path: target,
        headers: {
          'content-type': 'application/json',
          'x-device-id': deviceId,
          'x-timestamp': String(now),
          'x-sequence': '1',
          'x-assertion': assertion1.assertionBase64
        },
        body: rawBody1
      });
      assert.equal(replayResp.status, 401);

      // Step E: Send invalid counter (counter 1 <= previousCounter 1) for seq=2 -> REJECTED
      const rawBody2 = Buffer.from(JSON.stringify({ question: 'fortune' }), 'utf8');
      const canonical2 = buildCanonicalBuffer(String(now), '2', 'POST', target, rawBody2);
      const staleCounterAssertion = createIosAssertion({
        appId,
        privateKeyPem: regFixture.leafPrivateKeyPem,
        canonicalBuffer: canonical2,
        counter: 1 // Stale counter!
      });

      const staleResp = await makeRequest(baseUrl2, {
        method: 'POST',
        path: target,
        headers: {
          'content-type': 'application/json',
          'x-device-id': deviceId,
          'x-timestamp': String(now),
          'x-sequence': '2',
          'x-assertion': staleCounterAssertion.assertionBase64
        },
        body: rawBody2
      });
      assert.equal(staleResp.status, 401);

      // Step F: Send valid seq=2, counter=2 on Server 2 -> 200 OK
      const validAssertion2 = createIosAssertion({
        appId,
        privateKeyPem: regFixture.leafPrivateKeyPem,
        canonicalBuffer: canonical2,
        counter: 2
      });

      const req2Resp = await makeRequest(baseUrl2, {
        method: 'POST',
        path: target,
        headers: {
          'content-type': 'application/json',
          'x-device-id': deviceId,
          'x-timestamp': String(now),
          'x-sequence': '2',
          'x-assertion': validAssertion2.assertionBase64
        },
        body: rawBody2
      });
      assert.equal(req2Resp.status, 200);
      assert.equal(req2Resp.json().reading, 'The Star');

      // Shutdown Server 2
      await new Promise<void>((resolve) => server2!.close(() => resolve()));
      await inst2.store.close();
      server2 = undefined;
      inst2 = undefined;
    } finally {
      if (server1) await new Promise<void>((resolve) => server1!.close(() => resolve()));
      if (inst1) await inst1.store.close();
      if (server2) await new Promise<void>((resolve) => server2!.close(() => resolve()));
      if (inst2) await inst2.store.close();
      await cleanupPrefix(prefix);
    }
  });

  it('proves full HTTP server restart with Redis persistence enforces sequence continuity and replay protection', async () => {
    const prefix = `test:sec:http-persist:${crypto.randomUUID()}:`;
    const now = 1729800000000;
    const rootCA = await createRootCA({ now });

    const emptyRevocations = {
      async getRevokedSerials() { return new Set<string>(); }
    };

    function createServerInstance() {
      const store = new RedisSecurityStore({ url: redisUrl, keyPrefix: prefix });
      const provider = new AndroidSecurityProvider({
        trustAnchors: [rootCA.certPem],
        expectedPackageName: 'com.astrology.tarot',
        expectedSignerDigests: [
          crypto.createHash('sha256').update('test-apk-signing-cert').digest('hex')
        ],
        revocationSource: emptyRevocations,
        now: () => now
      });

      const service = new SecurityService({
        store,
        providers: [provider],
        now: () => now
      });

      const app = createServer({
        securityService: service,
        store,
        businessHandler: async (_req: http.IncomingMessage, res: http.ServerResponse) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ status: 'success', reading: 'The Sun' }));
        }
      });

      return { app, store, service };
    }

    let server1: http.Server | undefined;
    let inst1: ReturnType<typeof createServerInstance> | undefined;
    let server2: http.Server | undefined;
    let inst2: ReturnType<typeof createServerInstance> | undefined;

    try {
      // 1. Start Server 1
      inst1 = createServerInstance();
      server1 = await new Promise<http.Server>((resolve) => {
        const s = inst1!.app.listen(0, '127.0.0.1', () => resolve(s));
      });
      const addr1 = server1.address() as any;
      const baseUrl1 = `http://127.0.0.1:${addr1.port}`;

      // Register device on Server 1
      // Step A: Issue challenge
      const chResp = await makeRequest(baseUrl1, {
        method: 'POST',
        path: '/api/auth/challenge',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ platform: 'android' })
      });
      assert.equal(chResp.status, 200);
      const chData = chResp.json();
      assert.equal(chData.status, 'SUCCESS');
      const challenge = chData.challenge;

      // Step B: Generate real attestation fixture with challenge
      const fixture = await createAttestationChain({
        now,
        rootCA,
        challengeHex: challenge
      });

      const regResp = await makeRequest(baseUrl1, {
        method: 'POST',
        path: '/api/auth/register-device',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          challenge,
          certificateChain: fixture.chain
        })
      });
      assert.equal(regResp.status, 200);
      const regData = regResp.json();
      assert.equal(regData.status, 'SUCCESS');
      const deviceId = regData.deviceId;
      assert.equal(deviceId, fixture.deviceId);

      // Step C: Send authenticated request seq=1 on Server 1
      const rawBody1 = Buffer.from(JSON.stringify({ card: 'the-fool' }), 'utf8');
      const target = '/api/tarot/read';
      const canonical1 = buildCanonicalBuffer(String(now), '1', 'POST', target, rawBody1);
      const sig1 = signCanonical(fixture.leafPrivateKeyPem, canonical1);

      const req1Resp = await makeRequest(baseUrl1, {
        method: 'POST',
        path: target,
        headers: {
          'content-type': 'application/json',
          'x-device-id': deviceId,
          'x-timestamp': String(now),
          'x-sequence': '1',
          'x-signature': sig1
        },
        body: rawBody1
      });
      assert.equal(req1Resp.status, 200);
      assert.equal(req1Resp.json().reading, 'The Sun');

      // Shutdown Server 1 completely
      await new Promise<void>((resolve) => server1!.close(() => resolve()));
      await inst1.store.close();
      server1 = undefined;
      inst1 = undefined;

      // 2. Start Server 2 (Fresh process simulation on same Redis prefix)
      inst2 = createServerInstance();
      server2 = await new Promise<http.Server>((resolve) => {
        const s = inst2!.app.listen(0, '127.0.0.1', () => resolve(s));
      });
      const addr2 = server2.address() as any;
      const baseUrl2 = `http://127.0.0.1:${addr2.port}`;

      // Step D: Replay seq=1 on Server 2 -> MUST BE REJECTED with 401 REPLAY_DETECTED
      const replayResp = await makeRequest(baseUrl2, {
        method: 'POST',
        path: target,
        headers: {
          'content-type': 'application/json',
          'x-device-id': deviceId,
          'x-timestamp': String(now),
          'x-sequence': '1',
          'x-signature': sig1
        },
        body: rawBody1
      });
      assert.equal(replayResp.status, 401);
      const replayBody = replayResp.json();
      assert.equal(replayBody.error, 'REPLAY_DETECTED');

      // Step E: Send invalid signature (valid base64 DER signed by different key) for seq=2 -> 401 INVALID_SIGNATURE
      const rawBody2 = Buffer.from(JSON.stringify({ card: 'magician' }), 'utf8');
      const canonical2 = buildCanonicalBuffer(String(now), '2', 'POST', target, rawBody2);
      const rogueKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const wrongKeyPem = rogueKey.privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
      const wrongSig = signCanonical(wrongKeyPem, canonical2);

      const invalidSigResp = await makeRequest(baseUrl2, {
        method: 'POST',
        path: target,
        headers: {
          'content-type': 'application/json',
          'x-device-id': deviceId,
          'x-timestamp': String(now),
          'x-sequence': '2',
          'x-signature': wrongSig
        },
        body: rawBody2
      });
      assert.equal(invalidSigResp.status, 401);
      const invalidSigBody = invalidSigResp.json();
      assert.equal(invalidSigBody.error, 'INVALID_SIGNATURE');

      // Step F: Send valid signature for seq=2 -> MUST SUCCEED (200 OK)
      const sig2 = signCanonical(fixture.leafPrivateKeyPem, canonical2);

      const req2Resp = await makeRequest(baseUrl2, {
        method: 'POST',
        path: target,
        headers: {
          'content-type': 'application/json',
          'x-device-id': deviceId,
          'x-timestamp': String(now),
          'x-sequence': '2',
          'x-signature': sig2
        },
        body: rawBody2
      });
      assert.equal(req2Resp.status, 200);
      assert.equal(req2Resp.json().reading, 'The Sun');

      // Step G: Send valid signature for seq=3 -> MUST SUCCEED (200 OK)
      const rawBody3 = Buffer.from(JSON.stringify({ card: 'empress' }), 'utf8');
      const canonical3 = buildCanonicalBuffer(String(now), '3', 'POST', target, rawBody3);
      const sig3 = signCanonical(fixture.leafPrivateKeyPem, canonical3);

      const req3Resp = await makeRequest(baseUrl2, {
        method: 'POST',
        path: target,
        headers: {
          'content-type': 'application/json',
          'x-device-id': deviceId,
          'x-timestamp': String(now),
          'x-sequence': '3',
          'x-signature': sig3
        },
        body: rawBody3
      });
      assert.equal(req3Resp.status, 200);
      assert.equal(req3Resp.json().reading, 'The Sun');

      // Shutdown Server 2
      await new Promise<void>((resolve) => server2!.close(() => resolve()));
      await inst2.store.close();
      server2 = undefined;
      inst2 = undefined;
    } catch (err) {
      console.error('SERVER RESTART PERSISTENCE ERROR:', err);
      throw err;
    } finally {
      if (server1) await new Promise<void>((resolve) => server1!.close(() => resolve()));
      if (inst1) await inst1.store.close();
      if (server2) await new Promise<void>((resolve) => server2!.close(() => resolve()));
      if (inst2) await inst2.store.close();
      await cleanupPrefix(prefix);
    }
  });
});
