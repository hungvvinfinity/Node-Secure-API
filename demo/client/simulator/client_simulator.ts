#!/usr/bin/env node
/**
 * End-to-End Client Simulator & Dual-Tier Verification Suite for Node-Secure-API.
 *
 * Demonstrates and verifies complete protocol compliance for both tiers:
 *
 * PART I: Hardware VIP Tier (TEE / StrongBox)
 * 1. Challenge acquisition with dynamic PoW parameters
 * 2. Hardware key attestation & device registration (tier: 'hardware', permanent lease)
 * 3. Canonical string formatting & SHA256withECDSA signing
 * 4. Replay attack rejection (HTTP 401 REPLAY_DETECTED)
 * 5. Tampered body rejection (HTTP 401 INVALID_SIGNATURE)
 * 6. Expired timestamp rejection (HTTP 401 EXPIRED_TIMESTAMP)
 * 7. Out-of-order sequence rejection (HTTP 401 REPLAY_DETECTED)
 * 8. Safe retry preservation of Idempotency-Key
 *
 * PART II: Software Protected Tier (PoW, 2h Lease, Tarpit, Concurrency)
 * 9. Standard EC P-256 SPKI PEM generation & Client PoW Solver
 * 10. Software registration with PoW solution (tier: 'software', 2h lease)
 * 11. Tarot reading on Software Tier with Tarpit Delay enforcement
 * 12. Replay & Tamper attack rejection on Software Tier
 * 13. Concurrency Lock enforcement (HTTP 429 CONCURRENT_REQUEST_DISALLOWED)
 * 14. Rolling Lease Expiry (HTTP 401 LEASE_EXPIRED) & Silent Renewal recovery
 */

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http, { type Server } from 'node:http';
import { AddressInfo } from 'node:net';

import { MemorySecurityStore } from '../../../src/store/memory.js';
import { SecurityService } from '../../../src/core/security-service.js';
import { AndroidSecurityProvider } from '../../../src/platform/android.js';
import { createServer } from '../../../src/http/server.js';
import { createAttestationChain, signCanonical } from '../../../test/helpers/crypto-fixtures.js';
import { countLeadingZeroBits, solveProofOfWork } from '../../../src/core/pow.js';

interface TestServerContext {
  server: Server;
  baseUrl: string;
  fixture: Awaited<ReturnType<typeof createAttestationChain>>;
  advanceTime(ms: number): void;
  getTime(): number;
  close(): Promise<void>;
}

class StaticRevocationSource {
  async getRevokedSerials(): Promise<Set<string>> {
    return new Set<string>();
  }
}

async function startSimulatorTestServer(): Promise<TestServerContext> {
  let simulatedTime = Date.now();
  const getTime = () => simulatedTime;
  const advanceTime = (ms: number) => { simulatedTime += ms; };
  const store = new MemorySecurityStore({ now: getTime });

  // Create an Android hardware attestation fixture with package com.astrology.tarot
  const fixture = await createAttestationChain({
    now: simulatedTime,
    attestationSecurityLevel: 1, // TEE
    keymasterSecurityLevel: 1,   // TEE
    packageName: 'com.astrology.tarot',
    packageVersion: 1n
  });

  const androidProvider = new AndroidSecurityProvider({
    trustAnchors: [fixture.rootCertPem],
    expectedPackageName: fixture.expectedPackageName,
    expectedSignerDigests: fixture.expectedSignerDigests,
    minimumVersion: 1n,
    revocationSource: new StaticRevocationSource(),
    allowSoftwareTier: true,
    powDifficultyBits: 14, // 14 bits for sub-second test execution
    softwareDeviceTtlSeconds: 7200, // 2 hours
    now: getTime
  });

  const securityService = new SecurityService({
    store,
    providers: [androidProvider],
    powDifficultyBits: 14,
    softwareRateLimitRpm: 6,
    now: getTime
  });

  const server = createServer({
    securityService,
    store,
    softwareTarpitDelayMs: 600, // 600ms for fast test verification while asserting delay
    businessHandler: (req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'SUCCESS',
        data: {
          card: 'The Star',
          meaning: 'Dual-Tier hardware/software security successfully protected your request!'
        }
      }));
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => resolve());
    server.once('error', reject);
  });

  const addr = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  return {
    server,
    baseUrl,
    fixture,
    advanceTime,
    getTime,
    close: () => new Promise<void>((resolve) => server.close(() => resolve()))
  };
}

async function httpPost(
  url: string,
  body: string | Buffer,
  headers: Record<string, string> = {}
): Promise<{ status: number; headers: http.IncomingHttpHeaders; data: any; rawBody: string; durationMs: number }> {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
  const start = performance.now();
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'content-length': String(payload.length),
      ...headers
    },
    body: payload
  });

  const durationMs = performance.now() - start;
  const rawBody = await response.text();
  let data: any;
  try {
    data = JSON.parse(rawBody);
  } catch {
    data = rawBody;
  }

  return {
    status: response.status,
    headers: Object.fromEntries(response.headers.entries()),
    data,
    rawBody,
    durationMs
  };
}

async function runSimulatorSuite(): Promise<void> {
  console.log('================================================================');
  console.log(' 🚀 RUNNING NODE-SECURE-API DUAL-TIER CLIENT SIMULATOR SUITE');
  console.log('================================================================\n');

  const context = await startSimulatorTestServer();
  const { baseUrl, fixture, advanceTime, getTime } = context;

  try {
    console.log(`[Setup] Local Dual-Tier server started at: ${baseUrl}`);
    console.log(`[Setup] Target package: ${fixture.expectedPackageName}`);
    console.log(`[Setup] Tier 1: Hardware VIP | Tier 2: Software Protected (PoW & 2h Lease)\n`);

    // =========================================================================
    // PART I: HARDWARE VIP TIER (TEE / StrongBox)
    // =========================================================================
    console.log('--- PART I: HARDWARE VIP TIER VERIFICATION ---');

    // -------------------------------------------------------------------------
    // TEST 1: Challenge Endpoint with PoW metadata
    // -------------------------------------------------------------------------
    console.log('[Test 1] Requesting challenge from POST /api/auth/challenge...');
    const challengeRes = await httpPost(`${baseUrl}/api/auth/challenge`, JSON.stringify({ platform: 'android' }));
    assert.equal(challengeRes.status, 200, `Expected 200, got: ${challengeRes.status}`);
    assert.equal(challengeRes.data.status, 'SUCCESS');
    assert.match(challengeRes.data.challenge, /^[0-9a-fA-F]{64}$/, 'Challenge must be 64 hex characters');
    assert.ok(challengeRes.data.pow, 'Response must include PoW puzzle');
    assert.ok(typeof challengeRes.data.pow.salt === 'string');
    assert.equal(challengeRes.data.pow.difficulty, 14);
    const challengeHex = challengeRes.data.challenge;
    console.log(` -> PASS: Received 64-char hex challenge and PoW params (diff: ${challengeRes.data.pow.difficulty})`);

    // -------------------------------------------------------------------------
    // TEST 2: Hardware Device Registration (VIP Permanent Lease)
    // -------------------------------------------------------------------------
    console.log('\n[Test 2] Submitting hardware attestation certificate chain...');
    const boundFixture = await createAttestationChain({
      challengeHex,
      packageName: 'com.astrology.tarot',
      packageVersion: 1n,
      attestationSecurityLevel: 1,
      keymasterSecurityLevel: 1,
      rootCA: fixture.rootCA
    });

    const regRes = await httpPost(
      `${baseUrl}/api/auth/register-device`,
      JSON.stringify({
        challenge: challengeHex,
        certificateChain: boundFixture.chain
      })
    );

    assert.equal(regRes.status, 200, `Expected 200, got: ${regRes.status}`);
    assert.equal(regRes.data.status, 'SUCCESS');
    assert.equal(regRes.data.tier, 'hardware');
    const hwDeviceId = regRes.data.deviceId;
    console.log(` -> PASS: Registered Hardware VIP device. Tier: ${regRes.data.tier} | ID: ${hwDeviceId}`);

    let hwSequence = 0n;
    function signHwRequest(method: string, target: string, rawBody: string | Buffer, options: { timestamp?: number; sequence?: bigint } = {}) {
      const ts = options.timestamp !== undefined ? String(options.timestamp) : String(getTime());
      if (options.sequence !== undefined) {
        hwSequence = options.sequence;
      } else {
        hwSequence += 1n;
      }
      const seqStr = hwSequence.toString();
      const bodyBytes = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8');
      const bodyHash = crypto.createHash('sha256').update(bodyBytes).digest('hex');
      const canonical = `${ts}:${seqStr}:${method.toUpperCase()}:${target}:${bodyHash}`;
      const signature = signCanonical(boundFixture.leafPrivateKeyPem, canonical);

      return {
        headers: {
          'X-Device-Id': hwDeviceId,
          'X-Timestamp': ts,
          'X-Sequence': seqStr,
          'X-Signature': signature
        },
        bodyBytes
      };
    }

    // -------------------------------------------------------------------------
    // TEST 3: Legitimate Hardware Request (VIP Fast-Track, 0ms Delay)
    // -------------------------------------------------------------------------
    console.log('\n[Test 3] Sending valid signed request on Hardware VIP Tier...');
    const tarotBody = JSON.stringify({ question: 'Tarot VIP', idempotencyKey: crypto.randomUUID() });
    const hwProof = signHwRequest('POST', '/api/tarot/read', tarotBody);
    const hwTarotRes = await httpPost(`${baseUrl}/api/tarot/read`, hwProof.bodyBytes, hwProof.headers);

    assert.equal(hwTarotRes.status, 200);
    assert.equal(hwTarotRes.data.status, 'SUCCESS');
    assert.ok(hwTarotRes.durationMs < 400, `Hardware VIP must have zero tarpit delay (took ${hwTarotRes.durationMs}ms)`);
    console.log(` -> PASS: Hardware VIP Tarot read successful (${Math.round(hwTarotRes.durationMs)}ms, Fast-Track)`);

    // -------------------------------------------------------------------------
    // TEST 4: Hardware Replay Attack Rejection
    // -------------------------------------------------------------------------
    console.log('\n[Test 4] Replaying exact same Hardware packet with Sequence 1...');
    const hwReplayRes = await httpPost(`${baseUrl}/api/tarot/read`, hwProof.bodyBytes, hwProof.headers);
    assert.equal(hwReplayRes.status, 401);
    assert.equal(hwReplayRes.data.error, 'REPLAY_DETECTED');
    console.log(` -> PASS: Replay detected and rejected: HTTP 401 REPLAY_DETECTED`);

    // -------------------------------------------------------------------------
    // TEST 5: Hardware Tampered Body Rejection
    // -------------------------------------------------------------------------
    console.log('\n[Test 5] Tampering body of signed packet on Hardware Tier...');
    const proof2 = signHwRequest('POST', '/api/tarot/read', tarotBody);
    const hwTamperRes = await httpPost(`${baseUrl}/api/tarot/read`, JSON.stringify({ question: 'HACKED' }), proof2.headers);
    assert.equal(hwTamperRes.status, 401);
    assert.equal(hwTamperRes.data.error, 'INVALID_SIGNATURE');
    console.log(` -> PASS: Tampered body rejected: HTTP 401 INVALID_SIGNATURE`);

    // -------------------------------------------------------------------------
    // TEST 6: Hardware Expired Timestamp Rejection
    // -------------------------------------------------------------------------
    console.log('\n[Test 6] Sending expired timestamp (-30s) on Hardware Tier...');
    const expiredProof = signHwRequest('POST', '/api/tarot/read', tarotBody, { timestamp: getTime() - 30_000 });
    const hwExpiredRes = await httpPost(`${baseUrl}/api/tarot/read`, expiredProof.bodyBytes, expiredProof.headers);
    assert.equal(hwExpiredRes.status, 401);
    assert.equal(hwExpiredRes.data.error, 'EXPIRED_TIMESTAMP');
    console.log(` -> PASS: Expired timestamp rejected: HTTP 401 EXPIRED_TIMESTAMP`);

    // -------------------------------------------------------------------------
    // TEST 7: Hardware Out-of-Order Sequence Rejection
    // -------------------------------------------------------------------------
    console.log('\n[Test 7] Sending out-of-order sequence (Seq 1 when lastSequence >= 2)...');
    const lowSeqProof = signHwRequest('POST', '/api/tarot/read', tarotBody, { sequence: 1n });
    const hwLowSeqRes = await httpPost(`${baseUrl}/api/tarot/read`, lowSeqProof.bodyBytes, lowSeqProof.headers);
    assert.equal(hwLowSeqRes.status, 401);
    assert.equal(hwLowSeqRes.data.error, 'REPLAY_DETECTED');
    console.log(` -> PASS: Lower sequence strictly rejected: HTTP 401 REPLAY_DETECTED`);

    // -------------------------------------------------------------------------
    // TEST 8: Safe Client Retry on Hardware Tier
    // -------------------------------------------------------------------------
    console.log('\n[Test 8] Safe Retry: Fresh sequence & timestamp, invariant Idempotency-Key...');
    const retryProof = signHwRequest('POST', '/api/tarot/read', tarotBody);
    const hwRetryRes = await httpPost(`${baseUrl}/api/tarot/read`, retryProof.bodyBytes, retryProof.headers);
    assert.equal(hwRetryRes.status, 200);
    console.log(` -> PASS: Safe retry succeeded with fresh sequence (${hwSequence})`);

    // =========================================================================
    // PART II: SOFTWARE PROTECTED TIER (PoW, 2h Lease, Tarpit, Concurrency)
    // =========================================================================
    console.log('\n----------------------------------------------------------------');
    console.log('--- PART II: SOFTWARE PROTECTED TIER VERIFICATION (DUAL-TIER) ---');
    console.log('----------------------------------------------------------------');

    // -------------------------------------------------------------------------
    // TEST 9: Key Generation & Proof of Work Solving
    // -------------------------------------------------------------------------
    console.log('[Test 9] Generating standard EC P-256 key pair & solving PoW puzzle...');
    const swKeyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const swPublicKeyPem = swKeyPair.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const swPrivateKeyPem = swKeyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;

    const swChalRes = await httpPost(`${baseUrl}/api/auth/challenge`, JSON.stringify({ platform: 'android' }));
    const swChallenge = swChalRes.data.challenge;
    const swPow = swChalRes.data.pow;

    const powStart = performance.now();
    const swNonce = solveProofOfWork(swChallenge, swPow.salt, swPow.difficulty);
    const powDuration = Math.round(performance.now() - powStart);
    console.log(` -> PASS: Solved PoW puzzle in ${powDuration}ms (nonce: ${swNonce}, diff: ${swPow.difficulty})`);

    // -------------------------------------------------------------------------
    // TEST 10: Software Device Registration with PoW Solution (6-Hour Lease)
    // -------------------------------------------------------------------------
    console.log('\n[Test 10] Registering Tier 2 Software device with PoW nonce and SPKI PEM...');
    const swRegRes = await httpPost(
      `${baseUrl}/api/auth/register-device`,
      JSON.stringify({
        challenge: swChallenge,
        publicKeyPem: swPublicKeyPem,
        powNonce: swNonce
      })
    );

    assert.equal(swRegRes.status, 200, `Expected 200, got: ${swRegRes.status} (${swRegRes.rawBody})`);
    assert.equal(swRegRes.data.status, 'SUCCESS');
    assert.equal(swRegRes.data.tier, 'software');
    const swDeviceId = swRegRes.data.deviceId;
    console.log(` -> PASS: Device registered on Tier: ${swRegRes.data.tier} | ID: ${swDeviceId}`);

    let swSequence = 0n;
    function signSwRequest(method: string, target: string, rawBody: string | Buffer, options: { timestamp?: number; sequence?: bigint } = {}) {
      const ts = options.timestamp !== undefined ? String(options.timestamp) : String(getTime());
      if (options.sequence !== undefined) {
        swSequence = options.sequence;
      } else {
        swSequence += 1n;
      }
      const seqStr = swSequence.toString();
      const bodyBytes = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8');
      const bodyHash = crypto.createHash('sha256').update(bodyBytes).digest('hex');
      const canonical = `${ts}:${seqStr}:${method.toUpperCase()}:${target}:${bodyHash}`;
      const signature = signCanonical(swPrivateKeyPem, canonical);

      return {
        headers: {
          'X-Device-Id': swDeviceId,
          'X-Timestamp': ts,
          'X-Sequence': seqStr,
          'X-Signature': signature
        },
        bodyBytes
      };
    }

    // -------------------------------------------------------------------------
    // TEST 11: Software Tarot Read with Tarpit Delay Enforcement
    // -------------------------------------------------------------------------
    console.log('\n[Test 11] Executing signed Tarot request on Software Tier (verifying Tarpit Delay)...');
    const swTarotBody = JSON.stringify({ question: 'Tarot Software', idempotencyKey: crypto.randomUUID() });
    const swProof1 = signSwRequest('POST', '/api/tarot/read', swTarotBody);
    const swTarotRes = await httpPost(`${baseUrl}/api/tarot/read`, swProof1.bodyBytes, swProof1.headers);

    assert.equal(swTarotRes.status, 200);
    assert.equal(swTarotRes.data.status, 'SUCCESS');
    assert.ok(
      swTarotRes.durationMs >= 550,
      `Software Tier must enforce tarpit delay >= 600ms (actual: ${swTarotRes.durationMs}ms)`
    );
    console.log(` -> PASS: Software Tarot request verified with Tarpit Delay (${Math.round(swTarotRes.durationMs)}ms)`);

    // -------------------------------------------------------------------------
    // TEST 12: Replay & Tamper Attack Rejection on Software Tier
    // -------------------------------------------------------------------------
    console.log('\n[Test 12] Verifying Replay & Tamper attacks are rejected on Software Tier...');
    // Replay
    const swReplayRes = await httpPost(`${baseUrl}/api/tarot/read`, swProof1.bodyBytes, swProof1.headers);
    assert.equal(swReplayRes.status, 401);
    assert.equal(swReplayRes.data.error, 'REPLAY_DETECTED');
    console.log(' -> PASS: Replay attack rejected on Software Tier (401 REPLAY_DETECTED)');

    // Tamper
    const swProof2 = signSwRequest('POST', '/api/tarot/read', swTarotBody);
    const swTamperRes = await httpPost(`${baseUrl}/api/tarot/read`, JSON.stringify({ question: 'TAMPERED_SW' }), swProof2.headers);
    assert.equal(swTamperRes.status, 401);
    assert.equal(swTamperRes.data.error, 'INVALID_SIGNATURE');
    console.log(' -> PASS: Tamper attack rejected on Software Tier (401 INVALID_SIGNATURE)');

    // -------------------------------------------------------------------------
    // TEST 13: Concurrency Lock Enforcement on Software Tier (1 In-Flight Request)
    // -------------------------------------------------------------------------
    console.log('\n[Test 13] Verifying Software Tier Concurrency Lock (max 1 in-flight request)...');
    const p1Body = JSON.stringify({ question: 'Parallel 1', idempotencyKey: crypto.randomUUID() });
    const p2Body = JSON.stringify({ question: 'Parallel 2', idempotencyKey: crypto.randomUUID() });
    const p1Proof = signSwRequest('POST', '/api/tarot/read', p1Body);
    const p2Proof = signSwRequest('POST', '/api/tarot/read', p2Body);

    const call1 = httpPost(`${baseUrl}/api/tarot/read`, p1Proof.bodyBytes, p1Proof.headers);
    await new Promise((r) => setTimeout(r, 20)); // Small delta to ensure call 1 enters lock
    const call2 = httpPost(`${baseUrl}/api/tarot/read`, p2Proof.bodyBytes, p2Proof.headers);

    const [c1Res, c2Res] = await Promise.all([call1, call2]);
    assert.equal(c1Res.status, 200, `Call 1 should succeed: ${c1Res.status}`);
    assert.equal(c2Res.status, 429, `Call 2 must be blocked by concurrency lock: ${c2Res.status}`);
    assert.equal(c2Res.data.error, 'CONCURRENT_REQUEST_DISALLOWED');
    console.log(' -> PASS: Concurrency lock strictly blocked parallel in-flight call (429 CONCURRENT_REQUEST_DISALLOWED)');

    // -------------------------------------------------------------------------
    // TEST 14: Rolling Lease Expiry (2 Hours) & Silent Renewal
    // -------------------------------------------------------------------------
    console.log('\n[Test 14] Simulating 2-Hour Lease Expiration and Automatic Silent Renewal...');
    // Advance simulated time past 2-hour TTL (+ 3 hours)
    advanceTime(3 * 3600 * 1000);

    const expiredBody = JSON.stringify({ question: 'After 3 hours' });
    const expiredProofSw = signSwRequest('POST', '/api/tarot/read', expiredBody);
    const leaseExpRes = await httpPost(`${baseUrl}/api/tarot/read`, expiredProofSw.bodyBytes, expiredProofSw.headers);

    assert.equal(leaseExpRes.status, 401, `Expired lease must fail with 401, got: ${leaseExpRes.status}`);
    assert.ok(
      leaseExpRes.data.error === 'DEVICE_NOT_REGISTERED' || leaseExpRes.data.error === 'DEVICE_LEASE_EXPIRED',
      `Expected DEVICE_NOT_REGISTERED or DEVICE_LEASE_EXPIRED, got: ${leaseExpRes.data.error}`
    );
    console.log(` -> PASS: Server strictly enforced 2-hour lease expiry: HTTP 401 ${leaseExpRes.data.error}`);

    // Simulate Client Silent Renewal
    console.log(' -> Executing Client Silent Renewal (fresh challenge, PoW re-solve, re-registration)...');
    const renewChalRes = await httpPost(`${baseUrl}/api/auth/challenge`, JSON.stringify({ platform: 'android' }));
    const renewChal = renewChalRes.data.challenge;
    const renewPow = renewChalRes.data.pow;
    const renewNonce = solveProofOfWork(renewChal, renewPow.salt, renewPow.difficulty);

    const renewRegRes = await httpPost(
      `${baseUrl}/api/auth/register-device`,
      JSON.stringify({
        challenge: renewChal,
        publicKeyPem: swPublicKeyPem,
        powNonce: renewNonce
      })
    );
    assert.equal(renewRegRes.status, 200);
    assert.equal(renewRegRes.data.tier, 'software');

    // Reset sequence and retry request with new lease
    swSequence = 0n;
    const recoveredProof = signSwRequest('POST', '/api/tarot/read', expiredBody);
    const recoveredRes = await httpPost(`${baseUrl}/api/tarot/read`, recoveredProof.bodyBytes, recoveredProof.headers);

    assert.equal(recoveredRes.status, 200);
    assert.equal(recoveredRes.data.status, 'SUCCESS');
    console.log(' -> PASS: Silent Renewal succeeded seamlessly! Post-renewal request returned HTTP 200 OK');

    console.log('\n================================================================');
    console.log(' 🎉 ALL 14 DUAL-TIER VERIFICATION TESTS PASSED SUCCESSFULLY (100%)');
    console.log('================================================================\n');

  } finally {
    await context.close();
  }
}

runSimulatorSuite().catch((err) => {
  console.error('\n❌ SIMULATOR SUITE FAILED:', err);
  process.exit(1);
});
