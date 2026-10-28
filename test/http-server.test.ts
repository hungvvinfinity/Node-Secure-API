import test, { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import crypto from 'node:crypto';
import { createServer } from '../src/http/server.js';
import { SecurityService } from '../src/core/security-service.js';
import { MemorySecurityStore } from '../src/store/memory.js';
import { buildCanonicalBuffer } from '../src/core/canonical.js';
import {
  SecurityError,
  type DeviceRecord,
  type DeviceSecurityProvider,
  type RegistrationInput,
  type RequestProof,
  type VerifiedRegistration
} from '../src/contracts.js';
import { signCanonical, createAttestationChain } from './helpers/crypto-fixtures.js';

class MockAndroidHttpProvider implements DeviceSecurityProvider {
  readonly platform = 'android' as const;

  async verifyRegistration(
    input: RegistrationInput,
    context: { challenge: Buffer }
  ): Promise<VerifiedRegistration> {
    if (!input.certificateChain || input.certificateChain.length === 0) {
      throw new SecurityError('INVALID_CERTIFICATE_CHAIN', 400);
    }
    const leafDer = Buffer.from(input.certificateChain[0], 'base64');
    const leafCert = new crypto.X509Certificate(leafDer);
    return {
      publicKeyPem: leafCert.publicKey.export({ type: 'spki', format: 'pem' }) as string,
      metadata: { challenge: context.challenge.toString('utf8') }
    };
  }

  async verifyRequest(device: DeviceRecord, proof: RequestProof): Promise<{ signCount?: number }> {
    const isMatch = crypto.verify(
      'sha256',
      proof.canonical,
      device.publicKeyPem,
      Buffer.from(proof.signature || '', 'base64')
    );
    if (!isMatch) {
      throw new SecurityError('INVALID_SIGNATURE', 401);
    }
    return {};
  }
}

interface HttpRequestOptions {
  method?: string;
  path: string;
  headers?: Record<string, string | string[]>;
  body?: Buffer | string;
  rawHeaders?: string[];
}

interface HttpResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  json: () => any;
}

function makeRequest(baseUrl: string, options: HttpRequestOptions): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const url = new URL(options.path, baseUrl);
    const req = http.request(
      url,
      {
        method: options.method ?? 'GET',
        headers: options.headers
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
            json: () => JSON.parse(bodyStr)
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

describe('HTTP Server End-to-End & Protocol Compliance Tests', () => {
  let store: MemorySecurityStore;
  let service: SecurityService;
  let server: http.Server;
  let baseUrl: string;
  let fixedNow: number;
  let fixture: Awaited<ReturnType<typeof createAttestationChain>>;
  let businessHandlerInvoked = false;

  before(async () => {
    fixedNow = 1729800000000;
    store = new MemorySecurityStore();
    service = new SecurityService({
      store,
      providers: [new MockAndroidHttpProvider()],
      now: () => fixedNow
    });

    server = createServer({
      securityService: service,
      store,
      businessHandler: async (req, res, context) => {
        businessHandlerInvoked = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'SUCCESS', fromCustomHandler: true, sequence: context.sequence }));
      }
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve());
    });

    const addr = server.address() as any;
    baseUrl = `http://127.0.0.1:${addr.port}`;
    fixture = await createAttestationChain();
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await store.close();
  });

  beforeEach(() => {
    businessHandlerInvoked = false;
  });

  describe('Health & Readiness', () => {
    it('returns 200 UP on GET /health', async () => {
      const res = await makeRequest(baseUrl, { path: '/health' });
      assert.equal(res.status, 200);
      assert.equal(res.json().status, 'UP');
    });

    it('returns 200 READY on GET /ready when store is healthy', async () => {
      const res = await makeRequest(baseUrl, { path: '/ready' });
      assert.equal(res.status, 200);
      assert.equal(res.json().status, 'READY');
    });
  });

  describe('HTTP Wire & Header Protections', () => {
    it('rejects duplicate security headers with 400 DUPLICATE_HEADER', async () => {
      const addr = server.address() as any;
      const rawResponse = await new Promise<string>((resolve, reject) => {
        const client = net.connect(addr.port, '127.0.0.1', () => {
          client.write(
            'POST /api/tarot/read HTTP/1.1\r\n' +
            'Host: 127.0.0.1\r\n' +
            'Connection: close\r\n' +
            'X-Device-Id: dev-1\r\n' +
            'X-Device-Id: dev-2\r\n' + // Duplicate header on wire!
            'X-Timestamp: ' + fixedNow + '\r\n' +
            'X-Sequence: 1\r\n' +
            'X-Signature: sig\r\n' +
            'Content-Length: 0\r\n' +
            '\r\n'
          );
        });
        let data = '';
        client.on('data', (chunk) => { data += chunk.toString(); });
        client.on('end', () => resolve(data));
        client.on('error', reject);
      });

      assert.ok(rawResponse.includes('400'), 'Must return HTTP 400');
      assert.ok(rawResponse.includes('DUPLICATE_HEADER'), 'Must report DUPLICATE_HEADER in body');
    });

    it('rejects compressed or unsupported content encodings with 415 UNSUPPORTED_ENCODING', async () => {
      const res = await makeRequest(baseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'content-encoding': 'gzip',
          'content-type': 'application/json'
        },
        body: Buffer.from('dummy-gzip-data')
      });

      assert.equal(res.status, 415);
      assert.equal(res.json().error, 'UNSUPPORTED_ENCODING');
    });
  });

  describe('Control Endpoints (Challenge & Device Registration)', () => {
    it('issues challenge via POST /api/auth/challenge', async () => {
      const res = await makeRequest(baseUrl, {
        method: 'POST',
        path: '/api/auth/challenge',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ platform: 'android' })
      });

      assert.equal(res.status, 200);
      const data = res.json();
      assert.equal(data.status, 'SUCCESS');
      assert.equal(typeof data.challenge, 'string');
      assert.equal(data.challenge.length, 64);
    });

    it('rejects GET /api/auth/challenge with 405 METHOD_NOT_ALLOWED', async () => {
      const res = await makeRequest(baseUrl, {
        method: 'GET',
        path: '/api/auth/challenge'
      });
      assert.equal(res.status, 405);
      assert.equal(res.json().error, 'METHOD_NOT_ALLOWED');
    });

    it('rejects malformed JSON payload on /api/auth/challenge with 400 INVALID_JSON', async () => {
      const res = await makeRequest(baseUrl, {
        method: 'POST',
        path: '/api/auth/challenge',
        headers: { 'content-type': 'application/json' },
        body: 'invalid-json{'
      });
      assert.equal(res.status, 400);
      assert.equal(res.json().error, 'INVALID_JSON');
    });

    it('successfully registers device via POST /api/auth/register-device', async () => {
      // 1. Get challenge
      const chRes = await makeRequest(baseUrl, {
        method: 'POST',
        path: '/api/auth/challenge',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ platform: 'android' })
      });
      const challenge = chRes.json().challenge;

      // 2. Register
      const regRes = await makeRequest(baseUrl, {
        method: 'POST',
        path: '/api/auth/register-device',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          challenge,
          certificateChain: fixture.chain
        })
      });

      assert.equal(regRes.status, 200);
      const data = regRes.json();
      assert.equal(data.status, 'SUCCESS');
      assert.equal(data.deviceId, fixture.deviceId);
    });

    it('rejects replay registration with same challenge with 401 INVALID_CHALLENGE', async () => {
      const chRes = await makeRequest(baseUrl, {
        method: 'POST',
        path: '/api/auth/challenge',
        headers: { 'content-type': 'application/json' },
        body: '{}'
      });
      const challenge = chRes.json().challenge;

      // First succeeds
      const r1 = await makeRequest(baseUrl, {
        method: 'POST',
        path: '/api/auth/register-device',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ challenge, certificateChain: fixture.chain })
      });
      // Could be 200 or 409 if device already registered, but challenge is consumed
      assert.ok(r1.status === 200 || r1.status === 409);

      // Second with consumed challenge must fail with 401 INVALID_CHALLENGE
      const r2 = await makeRequest(baseUrl, {
        method: 'POST',
        path: '/api/auth/register-device',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ challenge, certificateChain: fixture.chain })
      });
      assert.equal(r2.status, 401);
      assert.equal(r2.json().error, 'INVALID_CHALLENGE');
    });
  });

  describe('Business Protected Endpoint (/api/tarot/read)', () => {
    let deviceId: string;

    beforeEach(async () => {
      const chRes = await makeRequest(baseUrl, {
        method: 'POST',
        path: '/api/auth/challenge',
        headers: { 'content-type': 'application/json' },
        body: '{}'
      });
      const challenge = chRes.json().challenge;

      const regRes = await makeRequest(baseUrl, {
        method: 'POST',
        path: '/api/auth/register-device',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ challenge, certificateChain: fixture.chain })
      });
      deviceId = fixture.deviceId;
    });

    it('successfully processes valid signed request and executes businessHandler', async () => {
      const rawBody = Buffer.from('{"question":"love"}', 'utf8');
      const target = '/api/tarot/read';
      const timestamp = String(fixedNow);
      const sequence = '1';

      const canonical = buildCanonicalBuffer(timestamp, sequence, 'POST', target, rawBody);
      const signature = signCanonical(fixture.leafPrivateKeyPem, canonical);

      const res = await makeRequest(baseUrl, {
        method: 'POST',
        path: target,
        headers: {
          'x-device-id': deviceId,
          'x-timestamp': timestamp,
          'x-sequence': sequence,
          'x-signature': signature,
          'content-type': 'application/json'
        },
        body: rawBody
      });

      assert.equal(res.status, 200);
      assert.equal(businessHandlerInvoked, true, 'Business handler must be invoked on valid request');
      assert.equal(res.json().sequence, '1');
    });

    it('rejects request with missing security headers with 401 MISSING_SECURITY_HEADERS', async () => {
      const res = await makeRequest(baseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'x-device-id': deviceId
          // Missing X-Timestamp and X-Sequence!
        },
        body: Buffer.from('{}')
      });

      assert.equal(res.status, 401);
      assert.equal(res.json().error, 'MISSING_SECURITY_HEADERS');
      assert.equal(businessHandlerInvoked, false, 'Business handler must NOT be reached!');
    });

    it('rejects request with 1-bit whitespace tampered body with 401 INVALID_SIGNATURE', async () => {
      const originalBody = Buffer.from('{\n  "card": "star"\n}', 'utf8');
      const tamperedBody = Buffer.from('{\r\n  "card": "star"\n}', 'utf8'); // CR added
      const target = '/api/tarot/read';
      const timestamp = String(fixedNow);
      const sequence = '2';

      // Signed over originalBody
      const canonical = buildCanonicalBuffer(timestamp, sequence, 'POST', target, originalBody);
      const signature = signCanonical(fixture.leafPrivateKeyPem, canonical);

      // Sent over wire with tamperedBody
      const res = await makeRequest(baseUrl, {
        method: 'POST',
        path: target,
        headers: {
          'x-device-id': deviceId,
          'x-timestamp': timestamp,
          'x-sequence': sequence,
          'x-signature': signature,
          'content-type': 'application/json'
        },
        body: tamperedBody
      });

      assert.equal(res.status, 401);
      assert.equal(res.json().error, 'INVALID_SIGNATURE');
      assert.equal(businessHandlerInvoked, false, 'Business handler must NEVER be reached on tampered body');
    });

    it('rejects replay attack with 401 REPLAY_DETECTED', async () => {
      const rawBody = Buffer.from('{"draw":true}', 'utf8');
      const target = '/api/tarot/read';
      const timestamp = String(fixedNow);
      const sequence = '10';

      const canonical = buildCanonicalBuffer(timestamp, sequence, 'POST', target, rawBody);
      const signature = signCanonical(fixture.leafPrivateKeyPem, canonical);

      // 1. Initial request succeeds
      const r1 = await makeRequest(baseUrl, {
        method: 'POST',
        path: target,
        headers: {
          'x-device-id': deviceId,
          'x-timestamp': timestamp,
          'x-sequence': sequence,
          'x-signature': signature,
          'content-type': 'application/json'
        },
        body: rawBody
      });
      assert.equal(r1.status, 200);

      // 2. Replay of same payload and sequence fails
      const r2 = await makeRequest(baseUrl, {
        method: 'POST',
        path: target,
        headers: {
          'x-device-id': deviceId,
          'x-timestamp': timestamp,
          'x-sequence': sequence,
          'x-signature': signature,
          'content-type': 'application/json'
        },
        body: rawBody
      });
      assert.equal(r2.status, 401);
      assert.equal(r2.json().error, 'REPLAY_DETECTED');
    });

    it('rejects expired timestamp with 401 EXPIRED_TIMESTAMP', async () => {
      const rawBody = Buffer.from('{}', 'utf8');
      const target = '/api/tarot/read';
      const expiredTimestamp = String(fixedNow - 20000); // 20s ago (> 15s window)
      const sequence = '20';

      const canonical = buildCanonicalBuffer(expiredTimestamp, sequence, 'POST', target, rawBody);
      const signature = signCanonical(fixture.leafPrivateKeyPem, canonical);

      const res = await makeRequest(baseUrl, {
        method: 'POST',
        path: target,
        headers: {
          'x-device-id': deviceId,
          'x-timestamp': expiredTimestamp,
          'x-sequence': sequence,
          'x-signature': signature,
          'content-type': 'application/json'
        },
        body: rawBody
      });

      assert.equal(res.status, 401);
      assert.equal(res.json().error, 'EXPIRED_TIMESTAMP');
      assert.equal(businessHandlerInvoked, false);
    });

    it('supports sequence > 2^53 successfully over HTTP', async () => {
      const hugeSequence = '9007199254740995'; // > 2^53
      const rawBody = Buffer.from('{"bigint":true}', 'utf8');
      const target = '/api/tarot/read';
      const timestamp = String(fixedNow);

      const canonical = buildCanonicalBuffer(timestamp, hugeSequence, 'POST', target, rawBody);
      const signature = signCanonical(fixture.leafPrivateKeyPem, canonical);

      const res = await makeRequest(baseUrl, {
        method: 'POST',
        path: target,
        headers: {
          'x-device-id': deviceId,
          'x-timestamp': timestamp,
          'x-sequence': hugeSequence,
          'x-signature': signature,
          'content-type': 'application/json'
        },
        body: rawBody
      });

      assert.equal(res.status, 200);
      assert.equal(res.json().sequence, hugeSequence);
    });
  });
});
