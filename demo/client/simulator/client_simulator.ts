#!/usr/bin/env node
/**
 * End-to-End Client Simulator & Verification Suite for Node-Secure-API Android Client.
 *
 * Demonstrates and verifies the complete cryptographic handshake and runtime security invariants:
 * 1. Challenge acquisition from /api/auth/challenge
 * 2. Hardware key attestation & device registration at /api/auth/register-device
 * 3. Canonical string formatting & SHA256withECDSA request signing for /api/tarot/read
 * 4. Replay attack rejection (HTTP 401 REPLAY_DETECTED)
 * 5. Tampered body rejection (HTTP 401 INVALID_SIGNATURE)
 * 6. Expired timestamp rejection (HTTP 401 EXPIRED_TIMESTAMP)
 * 7. Out-of-order sequence rejection (HTTP 401 REPLAY_DETECTED)
 * 8. Safe retry preservation of Idempotency-Key
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

interface TestServerContext {
  server: Server;
  baseUrl: string;
  fixture: Awaited<ReturnType<typeof createAttestationChain>>;
  close(): Promise<void>;
}

class StaticRevocationSource {
  async getRevokedSerials(): Promise<Set<string>> {
    return new Set<string>();
  }
}

async function startSimulatorTestServer(): Promise<TestServerContext> {
  const store = new MemorySecurityStore();
  const fixedNow = Date.now();

  // Create an Android hardware attestation fixture with package com.astrology.tarot
  const fixture = await createAttestationChain({
    now: fixedNow,
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
    revocationSource: new StaticRevocationSource()
  });

  const securityService = new SecurityService({
    store,
    providers: [androidProvider]
  });

  const server = createServer({
    securityService,
    store,
    businessHandler: (req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'SUCCESS',
        data: {
          card: 'The Star',
          meaning: 'Hardware security successfully protected your request!'
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
    close: () => new Promise<void>((resolve) => server.close(() => resolve()))
  };
}

async function httpPost(
  url: string,
  body: string | Buffer,
  headers: Record<string, string> = {}
): Promise<{ status: number; headers: http.IncomingHttpHeaders; data: any; rawBody: string }> {
  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'content-length': String(payload.length),
      ...headers
    },
    body: payload
  });

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
    rawBody
  };
}

async function runSimulatorSuite(): Promise<void> {
  console.log('================================================================');
  console.log(' 🚀 RUNNING NODE-SECURE-API CLIENT SIMULATOR VERIFICATION SUITE');
  console.log('================================================================\n');

  const context = await startSimulatorTestServer();
  const { baseUrl, fixture } = context;

  try {
    console.log(`[Setup] Local test server started at: ${baseUrl}`);
    console.log(`[Setup] Test Trust Anchor initialized for package: ${fixture.expectedPackageName}\n`);

    // -------------------------------------------------------------------------
    // TEST 1: Challenge Endpoint (/api/auth/challenge)
    // -------------------------------------------------------------------------
    console.log('[Test 1] Requesting challenge from POST /api/auth/challenge...');
    const challengeRes = await httpPost(`${baseUrl}/api/auth/challenge`, JSON.stringify({ platform: 'android' }));
    assert.equal(challengeRes.status, 200, `Expected 200, got: ${challengeRes.status}`);
    assert.equal(challengeRes.data.status, 'SUCCESS');
    assert.match(challengeRes.data.challenge, /^[0-9a-fA-F]{64}$/, 'Challenge must be 64 hex characters');
    const challengeHex = challengeRes.data.challenge;
    console.log(` -> PASS: Received valid 64-char hex challenge: ${challengeHex.substring(0, 16)}...`);

    // -------------------------------------------------------------------------
    // TEST 2: Device Registration (/api/auth/register-device)
    // -------------------------------------------------------------------------
    console.log('\n[Test 2] Generating attested EC P-256 certificate chain and registering device...');
    // Generate fresh certificate chain bound to the server-issued challenge
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

    assert.equal(regRes.status, 200, `Expected 200 from register-device, got: ${regRes.status} (${regRes.rawBody})`);
    assert.equal(regRes.data.status, 'SUCCESS');
    assert.ok(typeof regRes.data.deviceId === 'string' && regRes.data.deviceId.length > 0);
    const assignedDeviceId = regRes.data.deviceId;
    console.log(` -> PASS: Device registered successfully. Assigned Device ID: ${assignedDeviceId}`);

    // Helper to produce canonical request proof
    let sequenceCounter = 0n;
    function signRequest(
      method: string,
      target: string,
      rawBody: string | Buffer,
      options: { timestamp?: number; sequence?: bigint; keyPem?: string } = {}
    ) {
      const ts = options.timestamp !== undefined ? String(options.timestamp) : String(Date.now());
      if (options.sequence !== undefined) {
        sequenceCounter = options.sequence;
      } else {
        sequenceCounter += 1n;
      }
      const seqStr = sequenceCounter.toString();
      const bodyBytes = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, 'utf8');
      const bodyHash = crypto.createHash('sha256').update(bodyBytes).digest('hex');
      const canonical = `${ts}:${seqStr}:${method.toUpperCase()}:${target}:${bodyHash}`;

      const key = options.keyPem || boundFixture.leafPrivateKeyPem;
      const signature = signCanonical(key, canonical);

      return {
        headers: {
          'X-Device-Id': assignedDeviceId,
          'X-Timestamp': ts,
          'X-Sequence': seqStr,
          'X-Signature': signature
        },
        canonical,
        bodyBytes
      };
    }

    // -------------------------------------------------------------------------
    // TEST 3: Legitimate Signed Request to /api/tarot/read (Sequence 1)
    // -------------------------------------------------------------------------
    console.log('\n[Test 3] Sending valid signed request to /api/tarot/read (Sequence 1)...');
    const tarotBody = JSON.stringify({
      question: 'What is the future of mobile security?',
      idempotencyKey: crypto.randomUUID()
    });

    const validProof = signRequest('POST', '/api/tarot/read', tarotBody);
    const tarotRes = await httpPost(`${baseUrl}/api/tarot/read`, validProof.bodyBytes, validProof.headers);

    assert.equal(tarotRes.status, 200, `Expected 200, got: ${tarotRes.status} (${tarotRes.rawBody})`);
    assert.equal(tarotRes.data.status, 'SUCCESS');
    assert.equal(tarotRes.data.data.card, 'The Star');
    console.log(` -> PASS: Successfully authenticated and read Tarot card: "${tarotRes.data.data.card}"`);

    // -------------------------------------------------------------------------
    // TEST 4: Replay Attack Rejection (Re-sending exact same packet)
    // -------------------------------------------------------------------------
    console.log('\n[Test 4] Simulating REPLAY ATTACK: Re-sending exact same packet with Sequence 1...');
    const replayRes = await httpPost(`${baseUrl}/api/tarot/read`, validProof.bodyBytes, validProof.headers);

    assert.equal(replayRes.status, 401, `Expected 401, got: ${replayRes.status}`);
    assert.equal(replayRes.data.error, 'REPLAY_DETECTED', `Expected REPLAY_DETECTED, got: ${replayRes.data.error}`);
    console.log(` -> PASS: Server detected and rejected replay packet: HTTP 401 REPLAY_DETECTED`);

    // -------------------------------------------------------------------------
    // TEST 5: Tampered Body Attack Rejection
    // -------------------------------------------------------------------------
    console.log('\n[Test 5] Simulating TAMPER ATTACK: Body altered after signing...');
    const tamperedBody = JSON.stringify({
      question: 'HACKED QUESTION: Send me secret data!',
      idempotencyKey: crypto.randomUUID()
    });
    // Send valid headers from Sequence 2, but replace the body with tamperedBody
    const proofSeq2 = signRequest('POST', '/api/tarot/read', tarotBody); // seq 2
    const tamperRes = await httpPost(`${baseUrl}/api/tarot/read`, tamperedBody, proofSeq2.headers);

    assert.equal(tamperRes.status, 401, `Expected 401, got: ${tamperRes.status}`);
    assert.equal(tamperRes.data.error, 'INVALID_SIGNATURE', `Expected INVALID_SIGNATURE, got: ${tamperRes.data.error}`);
    console.log(` -> PASS: Server detected body digest mismatch: HTTP 401 INVALID_SIGNATURE`);

    // -------------------------------------------------------------------------
    // TEST 6: Expired Timestamp Attack Rejection
    // -------------------------------------------------------------------------
    console.log('\n[Test 6] Simulating EXPIRED TIMESTAMP ATTACK: Timestamp 30 seconds in the past...');
    const expiredTimestamp = Date.now() - 30_000; // 30 seconds ago (> 15 seconds limit)
    const expiredProof = signRequest('POST', '/api/tarot/read', tarotBody, {
      timestamp: expiredTimestamp
    });
    const expiredRes = await httpPost(`${baseUrl}/api/tarot/read`, expiredProof.bodyBytes, expiredProof.headers);

    assert.equal(expiredRes.status, 401, `Expected 401, got: ${expiredRes.status}`);
    assert.equal(expiredRes.data.error, 'EXPIRED_TIMESTAMP', `Expected EXPIRED_TIMESTAMP, got: ${expiredRes.data.error}`);
    console.log(` -> PASS: Server rejected expired timestamp: HTTP 401 EXPIRED_TIMESTAMP`);

    // -------------------------------------------------------------------------
    // TEST 7: Lower / Out-of-Order Sequence Rejection
    // -------------------------------------------------------------------------
    console.log('\n[Test 7] Simulating OUT-OF-ORDER SEQUENCE ATTACK: Sending Sequence 1 when lastSequence >= 2...');
    const lowSeqProof = signRequest('POST', '/api/tarot/read', tarotBody, {
      sequence: 1n // Server has committed up to 2
    });
    const lowSeqRes = await httpPost(`${baseUrl}/api/tarot/read`, lowSeqProof.bodyBytes, lowSeqProof.headers);

    assert.equal(lowSeqRes.status, 401, `Expected 401, got: ${lowSeqRes.status}`);
    assert.equal(lowSeqRes.data.error, 'REPLAY_DETECTED', `Expected REPLAY_DETECTED, got: ${lowSeqRes.data.error}`);
    console.log(` -> PASS: Server strictly enforced increasing sequence: HTTP 401 REPLAY_DETECTED`);

    // -------------------------------------------------------------------------
    // TEST 8: Safe Retry with Fresh Sequence & Preserved Idempotency Key
    // -------------------------------------------------------------------------
    console.log('\n[Test 8] Simulating SAFE CLIENT RETRY: Fresh sequence & timestamp, invariant Idempotency-Key...');
    const retryProof = signRequest('POST', '/api/tarot/read', tarotBody); // advances sequence to 4
    const retryRes = await httpPost(`${baseUrl}/api/tarot/read`, retryProof.bodyBytes, retryProof.headers);

    assert.equal(retryRes.status, 200, `Expected 200, got: ${retryRes.status}`);
    assert.equal(retryRes.data.status, 'SUCCESS');
    console.log(` -> PASS: Safe retry succeeded with fresh sequence (${sequenceCounter}): HTTP 200 OK`);

    console.log('\n================================================================');
    console.log(' 🎉 ALL 8 VERIFICATION TESTS PASSED SUCCESSFULLY (100% SUCCESS)');
    console.log('================================================================\n');

  } finally {
    await context.close();
  }
}

runSimulatorSuite().catch((err) => {
  console.error('\n❌ SIMULATOR SUITE FAILED:', err);
  process.exit(1);
});
