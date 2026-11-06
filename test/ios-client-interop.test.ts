import test, { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { execSync } from 'node:child_process';
import * as asn1js from 'asn1js';
import { createServer } from '../src/http/server.js';
import { SecurityService } from '../src/core/security-service.js';
import { MemorySecurityStore } from '../src/store/memory.js';
import { IOSSecurityProvider } from '../src/platform/ios.js';
import { buildCanonicalBuffer } from '../src/core/canonical.js';
import { SecurityError } from '../src/contracts.js';
import {
  createIosAttestationFixture,
  createIosAssertion,
  createAppleAttestRootCA,
  createReceiptCA,
  encodeCbor,
  type CAEntity,
  type IosAttestationFixture,
} from './helpers/ios-fixtures.js';

interface HttpRequestOptions {
  method?: string;
  path: string;
  headers?: Record<string, string | string[]>;
  body?: Buffer | string;
}

interface HttpResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  json: () => Record<string, unknown>;
}

function makeRequest(baseUrl: string, options: HttpRequestOptions): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const url = new URL(options.path, baseUrl);
    const req = http.request(
      url,
      {
        method: options.method ?? 'GET',
        headers: options.headers,
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
            json: () => JSON.parse(bodyStr) as Record<string, unknown>,
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

function getSwiftEnvironment(): { swiftBin: string; binPath: string; env: NodeJS.ProcessEnv } | null {
  const homeDir = process.env.HOME || '';
  const swiftlyBinDir = path.join(homeDir, '.local/share/swiftly/bin');
  const swiftlySwift = path.join(swiftlyBinDir, 'swift');
  const swiftlySwiftc = path.join(swiftlyBinDir, 'swiftc');

  if (fs.existsSync(swiftlySwift)) {
    return {
      swiftBin: swiftlySwift,
      binPath: fs.existsSync(swiftlySwiftc) ? swiftlySwiftc : swiftlySwift,
      env: {
        ...process.env,
        SWIFTLY_HOME_DIR: path.join(homeDir, '.local/share/swiftly'),
        SWIFTLY_BIN_DIR: swiftlyBinDir,
        SWIFTLY_TOOLCHAINS_DIR: path.join(homeDir, '.local/share/swiftly/toolchains'),
        PATH: `${swiftlyBinDir}:${process.env.PATH || ''}`,
      },
    };
  }

  try {
    const whichSwift = execSync('which swift', {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (whichSwift && fs.existsSync(whichSwift)) {
      return { swiftBin: whichSwift, binPath: whichSwift, env: process.env };
    }
  } catch {
    // swift not found in PATH
  }

  return null;
}

describe('iOS Client & Backend Interoperability Test Suite', () => {
  const appId = 'TEAMID123.com.astrology.tarot';
  let currentNow: number;
  let rootCA: CAEntity;
  let receiptRootCA: CAEntity;
  let store: MemorySecurityStore;
  let fixture: IosAttestationFixture;
  let provider: IOSSecurityProvider;
  let service: SecurityService;
  let server: http.Server;
  let serverBaseUrl: string;
  let registeredDeviceId: string;

  before(async () => {
    currentNow = 1729800000000;
    rootCA = await createAppleAttestRootCA({ now: currentNow });
    receiptRootCA = await createReceiptCA({ now: currentNow });
    store = new MemorySecurityStore({ now: () => currentNow });

    fixture = await createIosAttestationFixture({
      appId,
      now: currentNow,
      environment: 'production',
      rootCA,
      receiptRootCA,
    });

    provider = new IOSSecurityProvider({
      trustAnchors: [fixture.rootCertPem],
      appId,
      environment: 'production',
      receiptVerifier: fixture.receiptVerifier,
      now: () => currentNow,
    });

    service = new SecurityService({
      store,
      providers: [provider],
      now: () => currentNow,
    });

    // Register a valid iOS device for subsequent interoperability tests
    const challengeResult = await service.issueChallenge('ios');
    const registrationFixture = await createIosAttestationFixture({
      appId,
      challenge: challengeResult.challenge,
      now: currentNow,
      environment: 'production',
      rootCA,
      receiptRootCA,
    });

    const regResult = await service.registerDevice({
      challenge: challengeResult.challenge,
      attestationObject: registrationFixture.attestationObjectBase64,
      keyId: registrationFixture.keyId,
    });
    registeredDeviceId = regResult.deviceId;
    fixture = registrationFixture;

    // Start HTTP server for wire-level integration tests
    server = createServer({
      securityService: service,
      store,
    });

    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        if (typeof addr === 'object' && addr !== null) {
          serverBaseUrl = `http://127.0.0.1:${addr.port}`;
        }
        resolve();
      });
    });
  });

  after(async () => {
    await store.close();
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  });

  // =========================================================================
  // 1. CANONICAL PAYLOAD FORMATTING & HASHING
  // =========================================================================
  describe('1. Canonical Payload Formatting & Hashing of iOS Request', () => {
    it('constructs canonical buffer adhering strictly to timestamp:sequence:METHOD:target:bodyHash', () => {
      const timestamp = String(currentNow);
      const sequence = '1';
      const method = 'POST';
      const target = '/api/tarot/read';
      const rawBody = Buffer.from(JSON.stringify({ question: 'Tarot test' }));
      const expectedBodyHash = crypto.createHash('sha256').update(rawBody).digest('hex');

      const canonical = buildCanonicalBuffer(timestamp, sequence, method, target, rawBody);
      const expectedString = `${timestamp}:${sequence}:${method}:${target}:${expectedBodyHash}`;

      assert.equal(canonical.toString('utf8'), expectedString);
    });

    it('correctly hashes empty body using sha256 empty hash (e3b0c442...)', () => {
      const timestamp = String(currentNow);
      const sequence = '2';
      const method = 'GET';
      const target = '/api/tarot/status';
      const rawBody = Buffer.alloc(0);

      const canonical = buildCanonicalBuffer(timestamp, sequence, method, target, rawBody);
      const expectedString = `${timestamp}:${sequence}:${method}:${target}:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`;

      assert.equal(canonical.toString('utf8'), expectedString);
    });

    it('preserves query string order and percent-encoding strictly as wire format without normalization', () => {
      const timestamp = String(currentNow);
      const sequence = '3';
      const method = 'POST';
      const target = '/api/tarot/read?cards=3&topic=career%20and%20finance';
      const rawBody = Buffer.from('{}');
      const expectedBodyHash = crypto.createHash('sha256').update(rawBody).digest('hex');

      const canonical = buildCanonicalBuffer(timestamp, sequence, method, target, rawBody);
      const expectedString = `${timestamp}:${sequence}:${method}:${target}:${expectedBodyHash}`;

      assert.equal(canonical.toString('utf8'), expectedString);
    });

    it('fails signature verification if canonical body hash differs from wire payload (401 INVALID_SIGNATURE)', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const sequence = '100';
      const wireBody = Buffer.from('{"tampered":true}');
      const originalBody = Buffer.from('{"tampered":false}');

      // Client signed over originalBody
      const canonicalClient = buildCanonicalBuffer(timestamp, sequence, 'POST', '/api/tarot/read', originalBody);
      const assertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonicalClient,
        counter: 1,
        flags: 0x40,
      });

      // Server builds canonical over wireBody
      const canonicalServer = buildCanonicalBuffer(timestamp, sequence, 'POST', '/api/tarot/read', wireBody);

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical: canonicalServer,
            assertion: assertion.assertionBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });
  });

  // =========================================================================
  // 2. DETAILED BITFIELD & LENGTH ENFORCEMENT ON authenticatorData[32]
  // =========================================================================
  describe('2. iOS AuthenticatorData Bitfield & Length Enforcement (docs/IOS_REQUEST_VERIFICATION_SPEC.md)', () => {
    it('accepts valid flags: 0x00, 0x01 (UP), 0x04 (UV), 0x05 (UP+UV), 0x40 (AT), 0x41 (AT+UP), 0x44 (AT+UV), 0x45 (AT+UP+UV)', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const validFlags = [
        0x00, // No flags
        0x01, // UP only
        0x04, // UV only
        0x05, // UP + UV
        0x40, // AT only (standard iOS DCAppAttestService)
        0x41, // AT + UP
        0x44, // AT + UV
        0x45, // AT + UP + UV
      ];

      let counter = 10;
      for (const flag of validFlags) {
        counter += 1;
        const timestamp = String(currentNow);
        const seq = String(counter);
        const canonical = buildCanonicalBuffer(timestamp, seq, 'POST', '/api/tarot/read', Buffer.from('{}'));

        const assertion = createIosAssertion({
          appId,
          privateKeyPem: fixture.leafPrivateKeyPem,
          canonicalBuffer: canonical,
          counter,
          flags: flag,
        });

        // Set device signCount strictly below counter
        dev.signCount = counter - 1;

        const res = await provider.verifyRequest(dev, {
          canonical,
          assertion: assertion.assertionBase64,
        });
        assert.equal(res.signCount, counter);
      }
    });

    it('rejects each forbidden/reserved flag individually: RFU1 (0x02), BE (0x08), BS (0x10), RFU2 (0x20) with 401 UNSUPPORTED_AUTHENTICATOR_FLAGS', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const forbiddenFlags = [
        0x02, // RFU1 alone
        0x08, // BE (Backup Eligibility) alone
        0x10, // BS (Backup State) alone
        0x20, // RFU2 alone
        0x42, // AT + RFU1
        0x48, // AT + BE
        0x50, // AT + BS
        0x60, // AT + RFU2
        0x7a, // Combined mask 0x3a with AT (0x40 | 0x3a)
      ];

      let counter = 50;
      for (const badFlag of forbiddenFlags) {
        counter += 1;
        const timestamp = String(currentNow);
        const seq = String(counter);
        const canonical = buildCanonicalBuffer(timestamp, seq, 'POST', '/api/tarot/read', Buffer.from('{}'));

        const assertion = createIosAssertion({
          appId,
          privateKeyPem: fixture.leafPrivateKeyPem,
          canonicalBuffer: canonical,
          counter,
          flags: badFlag,
        });

        dev.signCount = counter - 1;

        await assert.rejects(
          async () => {
            await provider.verifyRequest(dev, {
              canonical,
              assertion: assertion.assertionBase64,
            });
          },
          (err: unknown) => {
            assert.ok(err instanceof SecurityError);
            assert.equal(err.code, 'UNSUPPORTED_AUTHENTICATOR_FLAGS');
            assert.equal(err.status, 401);
            return true;
          }
        );
      }
    });

    it('rejects authenticatorData shorter than 37 bytes with 401 INVALID_AUTHENTICATOR_DATA', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const clientDataHash = crypto.createHash('sha256').update(canonical).digest();

      // 36 bytes (1 byte short)
      const shortAuthData = Buffer.alloc(36, 0x11);
      const composite = Buffer.concat([shortAuthData, clientDataHash]);
      const sig = crypto.sign('sha256', composite, crypto.createPrivateKey(fixture.leafPrivateKeyPem));

      const map = new Map<string, unknown>();
      map.set('signature', sig);
      map.set('authenticatorData', shortAuthData);
      const shortAssertionBase64 = encodeCbor(map).toString('base64');

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: shortAssertionBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_AUTHENTICATOR_DATA');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects authenticatorData longer than 37 bytes when ED=0 with 401 INVALID_AUTHENTICATOR_DATA_LENGTH (credential smuggling prevention)', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      // 38 bytes (1 extra trailing byte)
      const smuggledAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 100,
        flags: 0x40, // ED is 0
        extraAuthData: Buffer.from([0x00]),
      });

      dev.signCount = 99;

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: smuggledAssertion.assertionBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_AUTHENTICATOR_DATA_LENGTH');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects authenticatorData with ED=1 when extension data is missing (401 MISSING_EXTENSION_DATA)', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      // Flags 0xc0 (AT | ED) but only 37 bytes total (no extension data follows)
      const missingExtAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 101,
        flags: 0xc0,
      });

      dev.signCount = 100;

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: missingExtAssertion.assertionBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MISSING_EXTENSION_DATA');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('accepts authenticatorData with ED=1 when followed by a single valid CBOR Map', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      // Valid extension map
      const extMap = new Map<string, unknown>();
      extMap.set('apple_validation_category_01', 1);
      extMap.set('apple_bundle_version_01', '1.0.0');
      const extBytes = encodeCbor(extMap);

      const validExtAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 102,
        flags: 0xc0,
        extraAuthData: extBytes,
      });

      dev.signCount = 101;

      const res = await provider.verifyRequest(dev, {
        canonical,
        assertion: validExtAssertion.assertionBase64,
      });
      assert.equal(res.signCount, 102);
    });

    it('rejects authenticatorData with ED=1 when extension data is not a CBOR Map (401 INVALID_EXTENSION_DATA)', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      // Extension is CBOR Array instead of Map
      const extArrayBytes = encodeCbor(['not', 'a', 'map']);

      const invalidExtAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 103,
        flags: 0xc0,
        extraAuthData: extArrayBytes,
      });

      dev.signCount = 102;

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: invalidExtAssertion.assertionBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_EXTENSION_DATA');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });
  });

  // =========================================================================
  // 3. STRICT CBOR DECODING & INJECTION/SMUGGLING GUARDS
  // =========================================================================
  describe('3. Strict CBOR Decoding & Payload Injection Guards', () => {
    it('rejects payload that is not CBOR (random binary garbage)', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const canonical = buildCanonicalBuffer(String(currentNow), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const garbageBase64 = Buffer.from('this is totally random binary garbage 12345').toString('base64');

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: garbageBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.status, 400);
          return true;
        }
      );
    });

    it('rejects payload that is JSON instead of CBOR', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const canonical = buildCanonicalBuffer(String(currentNow), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const jsonBase64 = Buffer.from(JSON.stringify({ signature: 'xyz', authenticatorData: 'abc' })).toString('base64');

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: jsonBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.status, 400);
          return true;
        }
      );
    });

    it('rejects CBOR Array instead of Map with 401 INVALID_ASSERTION_FORMAT', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const canonical = buildCanonicalBuffer(String(currentNow), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const arrayCbor = encodeCbor([Buffer.alloc(64, 0x01), Buffer.alloc(37, 0x02)]).toString('base64');

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: arrayCbor,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_ASSERTION_FORMAT');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects CBOR Map missing "signature" with 401 INVALID_ASSERTION_FORMAT', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const canonical = buildCanonicalBuffer(String(currentNow), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const map = new Map<string, unknown>();
      map.set('authenticatorData', Buffer.alloc(37, 0x11));
      const cborBase64 = encodeCbor(map).toString('base64');

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: cborBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_ASSERTION_FORMAT');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects CBOR Map missing "authenticatorData" with 401 INVALID_ASSERTION_FORMAT', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const canonical = buildCanonicalBuffer(String(currentNow), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const map = new Map<string, unknown>();
      map.set('signature', Buffer.alloc(64, 0x22));
      const cborBase64 = encodeCbor(map).toString('base64');

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: cborBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_ASSERTION_FORMAT');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects CBOR Map containing injected extra keys (injection/smuggling prevention) with 401 INVALID_ASSERTION_FORMAT', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const canonical = buildCanonicalBuffer(String(currentNow), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      const map = new Map<string, unknown>();
      map.set('signature', Buffer.alloc(64, 0x01));
      map.set('authenticatorData', Buffer.alloc(37, 0x02));
      map.set('smuggledKey', 'unauthorized_payload');
      const smuggledCborBase64 = encodeCbor(map).toString('base64');

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: smuggledCborBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_ASSERTION_FORMAT');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });
  });

  // =========================================================================
  // 4. ASN.1 DER ECDSA P-256 SIGNATURE VERIFICATION
  // =========================================================================
  describe('4. ASN.1 DER ECDSA P-256 Signature Verification', () => {
    it('verifies valid ECDSA P-256 DER signature cleanly', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const assertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 120,
        flags: 0x40,
      });

      dev.signCount = 119;

      const res = await provider.verifyRequest(dev, {
        canonical,
        assertion: assertion.assertionBase64,
      });
      assert.equal(res.signCount, 120);
    });

    it('rejects tampered ECDSA P-256 signature with 401 INVALID_SIGNATURE', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const corruptedAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 121,
        flags: 0x40,
        corruptSignature: true,
      });

      dev.signCount = 120;

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: corruptedAssertion.assertionBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects malformed DER signature: outer ASN.1 tag is not SEQUENCE with 401 MALFORMED_DER_SIGNATURE', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      // Outer tag is SET (0x31) instead of SEQUENCE (0x30)
      const setDer = Buffer.from(new asn1js.Set({
        value: [
          new asn1js.Integer({ value: 12345 }),
          new asn1js.Integer({ value: 67890 }),
        ],
      }).toBER(false));

      const map = new Map<string, unknown>();
      map.set('signature', setDer);
      map.set('authenticatorData', Buffer.alloc(37, 0x11));
      const badTagAssertion = encodeCbor(map).toString('base64');

      dev.signCount = 0;

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: badTagAssertion,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MALFORMED_DER_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects malformed DER signature: SEQUENCE contains 1 integer or 3 integers with 401 MALFORMED_DER_SIGNATURE', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      // 1 integer (with length >= 8 bytes so it reaches ASN.1 structure check)
      const derOneInt = Buffer.from(new asn1js.Sequence({
        value: [new asn1js.Integer({ valueHex: new Uint8Array(Buffer.alloc(16, 0x11)).buffer })],
      }).toBER(false));

      const map1 = new Map<string, unknown>();
      map1.set('signature', derOneInt);
      map1.set('authenticatorData', Buffer.alloc(37, 0x11));

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: encodeCbor(map1).toString('base64'),
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MALFORMED_DER_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );

      // 3 integers
      const derThreeInt = Buffer.from(new asn1js.Sequence({
        value: [
          new asn1js.Integer({ value: 1 }),
          new asn1js.Integer({ value: 2 }),
          new asn1js.Integer({ value: 3 }),
        ],
      }).toBER(false));

      const map3 = new Map<string, unknown>();
      map3.set('signature', derThreeInt);
      map3.set('authenticatorData', Buffer.alloc(37, 0x11));

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: encodeCbor(map3).toString('base64'),
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MALFORMED_DER_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects malformed DER signature: element is not ASN.1 Integer with 401 MALFORMED_DER_SIGNATURE', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      const derNonInt = Buffer.from(new asn1js.Sequence({
        value: [
          new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3]).buffer }),
          new asn1js.Integer({ value: 67890 }),
        ],
      }).toBER(false));

      const map = new Map<string, unknown>();
      map.set('signature', derNonInt);
      map.set('authenticatorData', Buffer.alloc(37, 0x11));

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: encodeCbor(map).toString('base64'),
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MALFORMED_DER_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects signature shorter than 8 bytes with 401 INVALID_SIGNATURE_LENGTH', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      const map = new Map<string, unknown>();
      map.set('signature', Buffer.alloc(7, 0x30)); // 7 bytes (< 8)
      map.set('authenticatorData', Buffer.alloc(37, 0x11));

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: encodeCbor(map).toString('base64'),
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE_LENGTH');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects signature longer than 72 bytes with 401 INVALID_SIGNATURE_LENGTH', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      const map = new Map<string, unknown>();
      map.set('signature', Buffer.alloc(73, 0x30)); // 73 bytes (> 72)
      map.set('authenticatorData', Buffer.alloc(37, 0x11));

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: encodeCbor(map).toString('base64'),
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE_LENGTH');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });
  });

  // =========================================================================
  // 5. FULL LIFECYCLE: REGISTRATION (PROD VS DEV) & MONOTONIC SIGNCOUNT
  // =========================================================================
  describe('5. Full Lifecycle: Registration (Production vs Development) & Monotonic SignCount', () => {
    it('executes complete production registration flow and confirms initial signCount = 0', async () => {
      const ch = await service.issueChallenge('ios');
      const prodFixture = await createIosAttestationFixture({
        appId,
        challenge: ch.challenge,
        now: currentNow,
        environment: 'production',
        rootCA,
        receiptRootCA,
      });

      const regResult = await service.registerDevice({
        challenge: ch.challenge,
        attestationObject: prodFixture.attestationObjectBase64,
        keyId: prodFixture.keyId,
      });

      assert.equal(regResult.device.platform, 'ios');
      assert.equal(regResult.device.signCount, 0);
      assert.equal(regResult.device.metadata.environment, 'production');
    });

    it('executes complete development registration flow (AAGUID appattestdevelop)', async () => {
      const devProvider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        environment: 'development',
        receiptVerifier: fixture.receiptVerifier,
        now: () => currentNow,
      });

      const devStore = new MemorySecurityStore({ now: () => currentNow });
      const devService = new SecurityService({
        store: devStore,
        providers: [devProvider],
        now: () => currentNow,
      });

      const ch = await devService.issueChallenge('ios');
      const devFixture = await createIosAttestationFixture({
        appId,
        challenge: ch.challenge,
        now: currentNow,
        environment: 'development',
        rootCA,
        receiptRootCA,
      });

      const regResult = await devService.registerDevice({
        challenge: ch.challenge,
        attestationObject: devFixture.attestationObjectBase64,
        keyId: devFixture.keyId,
      });

      assert.equal(regResult.device.platform, 'ios');
      assert.equal(regResult.device.metadata.environment, 'development');
    });

    it('enforces monotonic signCount across consecutive requests (0 -> 1 -> 2)', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);
      dev.signCount = 0;

      const timestamp = String(currentNow);

      // Request 1: counter = 1
      const c1 = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', Buffer.from('{"req":1}'));
      const a1 = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: c1,
        counter: 1,
        flags: 0x40,
      });

      const res1 = await provider.verifyRequest(dev, {
        canonical: c1,
        assertion: a1.assertionBase64,
      });
      assert.equal(res1.signCount, 1);
      dev.signCount = 1;

      // Request 2: counter = 2
      const c2 = buildCanonicalBuffer(timestamp, '2', 'POST', '/api/tarot/read', Buffer.from('{"req":2}'));
      const a2 = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: c2,
        counter: 2,
        flags: 0x40,
      });

      const res2 = await provider.verifyRequest(dev, {
        canonical: c2,
        assertion: a2.assertionBase64,
      });
      assert.equal(res2.signCount, 2);
      dev.signCount = 2;

      // Equal signCount (2 == 2) -> rejected
      const equalAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: c2,
        counter: 2,
        flags: 0x40,
      });

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical: c2,
            assertion: equalAssertion.assertionBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'SIGN_COUNT_NOT_INCREASED');
          assert.equal(err.status, 401);
          return true;
        }
      );

      // Decremented signCount (1 < 2) -> rejected
      const lowerAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: c2,
        counter: 1,
        flags: 0x40,
      });

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical: c2,
            assertion: lowerAssertion.assertionBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'SIGN_COUNT_NOT_INCREASED');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });
  });

  // =========================================================================
  // 6. ANTI-REPLAY SEQUENCE TEST FOR IOS (BigInt, strictly monotonic, leading zeros)
  // =========================================================================
  describe('6. Anti-Replay Sequence Test for iOS', () => {
    it('accepts strictly advancing sequence numbers across requests', async () => {
      const timestamp = String(currentNow);
      const body = Buffer.from('{"step":1}');

      // Sequence 1
      const c1 = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', body);
      const a1 = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: c1,
        counter: 200,
        flags: 0x40,
      });

      const res1 = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': timestamp,
          'X-Sequence': '1',
          'X-Assertion': a1.assertionBase64,
        },
        body,
      });
      assert.equal(res1.status, 200);

      // Sequence 2
      const c2 = buildCanonicalBuffer(timestamp, '2', 'POST', '/api/tarot/read', body);
      const a2 = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: c2,
        counter: 201,
        flags: 0x40,
      });

      const res2 = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': timestamp,
          'X-Sequence': '2',
          'X-Assertion': a2.assertionBase64,
        },
        body,
      });
      assert.equal(res2.status, 200);
    });

    it('rejects duplicate sequence (replay attempt) with 401 REPLAY_DETECTED', async () => {
      const timestamp = String(currentNow);
      const body = Buffer.from('{"step":"duplicate"}');

      const c = buildCanonicalBuffer(timestamp, '2', 'POST', '/api/tarot/read', body);
      const a = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: c,
        counter: 202,
        flags: 0x40,
      });

      const res = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': timestamp,
          'X-Sequence': '2',
          'X-Assertion': a.assertionBase64,
        },
        body,
      });

      assert.equal(res.status, 401);
      assert.equal(res.json().error, 'REPLAY_DETECTED');
    });

    it('rejects decrementing sequence (backward jump) with 401 REPLAY_DETECTED', async () => {
      const timestamp = String(currentNow);
      const body = Buffer.from('{"step":"decrement"}');

      const c = buildCanonicalBuffer(timestamp, '1', 'POST', '/api/tarot/read', body);
      const a = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: c,
        counter: 203,
        flags: 0x40,
      });

      const res = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': timestamp,
          'X-Sequence': '1',
          'X-Assertion': a.assertionBase64,
        },
        body,
      });

      assert.equal(res.status, 401);
      assert.equal(res.json().error, 'REPLAY_DETECTED');
    });

    it('rejects sequences with leading zeros (e.g. "01", "005", "0") with 400 INVALID_SEQUENCE', async () => {
      const timestamp = String(currentNow);
      const body = Buffer.from('{}');

      for (const badSeq of ['01', '005', '0', '000']) {
        const c = buildCanonicalBuffer(timestamp, badSeq, 'POST', '/api/tarot/read', body);
        const a = createIosAssertion({
          appId,
          privateKeyPem: fixture.leafPrivateKeyPem,
          canonicalBuffer: c,
          counter: 205,
          flags: 0x40,
        });

        const res = await makeRequest(serverBaseUrl, {
          method: 'POST',
          path: '/api/tarot/read',
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'X-Device-Id': registeredDeviceId,
            'X-Timestamp': timestamp,
            'X-Sequence': badSeq,
            'X-Assertion': a.assertionBase64,
          },
          body,
        });

        assert.equal(res.status, 400);
        assert.equal(res.json().error, 'INVALID_SEQUENCE');
      }
    });

    it('correctly handles BigInt sequence exceeding 2^53 - 1 without IEEE 754 precision loss', async () => {
      const timestamp = String(currentNow);
      const body = Buffer.from('{"bigint":true}');

      const bigSeq1 = '9007199254740993';
      const bigSeq2 = '9007199254740994';

      const c1 = buildCanonicalBuffer(timestamp, bigSeq1, 'POST', '/api/tarot/read', body);
      const a1 = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: c1,
        counter: 210,
        flags: 0x40,
      });

      const res1 = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': timestamp,
          'X-Sequence': bigSeq1,
          'X-Assertion': a1.assertionBase64,
        },
        body,
      });
      assert.equal(res1.status, 200);

      const c2 = buildCanonicalBuffer(timestamp, bigSeq2, 'POST', '/api/tarot/read', body);
      const a2 = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: c2,
        counter: 211,
        flags: 0x40,
      });

      const res2 = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': timestamp,
          'X-Sequence': bigSeq2,
          'X-Assertion': a2.assertionBase64,
        },
        body,
      });
      assert.equal(res2.status, 200);
    });

    it('rejects sequence exceeding MAX_INT64 with 400 INVALID_SEQUENCE', async () => {
      const timestamp = String(currentNow);
      const body = Buffer.from('{}');
      const overflowSeq = '9223372036854775808'; // MAX_INT64 + 1

      const c = buildCanonicalBuffer(timestamp, overflowSeq, 'POST', '/api/tarot/read', body);
      const a = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: c,
        counter: 212,
        flags: 0x40,
      });

      const res = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': timestamp,
          'X-Sequence': overflowSeq,
          'X-Assertion': a.assertionBase64,
        },
        body,
      });

      assert.equal(res.status, 400);
      assert.equal(res.json().error, 'INVALID_SEQUENCE');
    });
  });

  // =========================================================================
  // 7. DYNAMIC CLOCK OFFSET COMPENSATION (401 EXPIRED & RETRY FRESH)
  // =========================================================================
  describe('7. Dynamic Clock Offset Compensation Tests', () => {
    it('rejects timestamp outside ±15s skew window with 401 EXPIRED_TIMESTAMP and recovers via offset', async () => {
      const skewedClientTime = currentNow - 25000; // 25s in the past (exceeds 15s max skew)
      const body = Buffer.from('{}');
      const seq = '9007199254741000';

      const cSkewed = buildCanonicalBuffer(String(skewedClientTime), seq, 'POST', '/api/tarot/read', body);
      const aSkewed = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: cSkewed,
        counter: 220,
        flags: 0x40,
      });

      const res1 = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': String(skewedClientTime),
          'X-Sequence': seq,
          'X-Assertion': aSkewed.assertionBase64,
        },
        body,
      });

      assert.equal(res1.status, 401);
      assert.equal(res1.json().error, 'EXPIRED_TIMESTAMP');

      // Client compensation simulation
      const challengeRes = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/auth/challenge',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ platform: 'ios' }),
      });
      const serverTime = Number(challengeRes.json().serverTime);
      const clockOffsetMs = serverTime - skewedClientTime;

      // Compensate timestamp
      const compensatedTime = skewedClientTime + clockOffsetMs;
      const nextSeq = '9007199254741001';
      const cCompensated = buildCanonicalBuffer(String(compensatedTime), nextSeq, 'POST', '/api/tarot/read', body);
      const aCompensated = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: cCompensated,
        counter: 221,
        flags: 0x40,
      });

      const res2 = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': String(compensatedTime),
          'X-Sequence': nextSeq,
          'X-Assertion': aCompensated.assertionBase64,
        },
        body,
      });

      assert.equal(res2.status, 200);
    });

    it('rejects timestamp in quarantine with 401 RETRY_WITH_FRESH_TIMESTAMP and succeeds on retry', async () => {
      const quarantinedTime = currentNow;
      (store as any).isQuarantined = (ts: number) => ts === quarantinedTime;

      const body = Buffer.from('{}');
      const seq = '9007199254741010';

      const cQuarantined = buildCanonicalBuffer(String(quarantinedTime), seq, 'POST', '/api/tarot/read', body);
      const aQuarantined = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: cQuarantined,
        counter: 230,
        flags: 0x40,
      });

      const res1 = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': String(quarantinedTime),
          'X-Sequence': seq,
          'X-Assertion': aQuarantined.assertionBase64,
        },
        body,
      });

      assert.equal(res1.status, 401);
      assert.equal(res1.json().error, 'RETRY_WITH_FRESH_TIMESTAMP');

      // Client retry logic: generate fresh timestamp outside quarantine
      const freshTime = currentNow + 1000;
      const nextSeq = '9007199254741011';
      const cFresh = buildCanonicalBuffer(String(freshTime), nextSeq, 'POST', '/api/tarot/read', body);
      const aFresh = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: cFresh,
        counter: 231,
        flags: 0x40,
      });

      const res2 = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': String(freshTime),
          'X-Sequence': nextSeq,
          'X-Assertion': aFresh.assertionBase64,
        },
        body,
      });

      assert.equal(res2.status, 200);

      delete (store as any).isQuarantined;
    });
  });

  // =========================================================================
  // 8. PAYLOAD BOUNDS & HEADER ENFORCEMENT
  // =========================================================================
  describe('8. Payload Bounds & Header Enforcement', () => {
    it('rejects assertion payload exceeding 8192 bytes with 401 ASSERTION_TOO_LARGE', async () => {
      const timestamp = String(currentNow);
      const seq = '9007199254741020';
      const body = Buffer.from('{}');

      const oversizedMap = new Map<string, unknown>();
      oversizedMap.set('signature', Buffer.alloc(64, 0x01));
      oversizedMap.set('authenticatorData', Buffer.alloc(37, 0x02));
      oversizedMap.set('oversizedPadding', Buffer.alloc(8500, 0xaa));
      const oversizedAssertionBase64 = encodeCbor(oversizedMap).toString('base64');

      assert.ok(Buffer.byteLength(oversizedAssertionBase64) > 8192);

      const res = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': timestamp,
          'X-Sequence': seq,
          'X-Assertion': oversizedAssertionBase64,
        },
        body,
      });

      assert.equal(res.status, 401);
      assert.equal(res.json().error, 'ASSERTION_TOO_LARGE');
    });

    it('rejects request with missing X-Assertion header with 401 MISSING_ASSERTION', async () => {
      const timestamp = String(currentNow);
      const seq = '9007199254741030';
      const body = Buffer.from('{}');

      const res = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': timestamp,
          'X-Sequence': seq,
        },
        body,
      });

      assert.equal(res.status, 401);
      assert.equal(res.json().error, 'MISSING_ASSERTION');
    });

    it('rejects request with empty X-Assertion header with 401 MISSING_ASSERTION', async () => {
      const timestamp = String(currentNow);
      const seq = '9007199254741031';
      const body = Buffer.from('{}');

      const res = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': timestamp,
          'X-Sequence': seq,
          'X-Assertion': '',
        },
        body,
      });

      assert.equal(res.status, 401);
      assert.equal(res.json().error, 'MISSING_ASSERTION');
    });

    it('rejects request sending X-Signature instead of X-Assertion for iOS with 401 MISSING_ASSERTION', async () => {
      const timestamp = String(currentNow);
      const seq = '9007199254741040';
      const body = Buffer.from('{}');

      const res = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': timestamp,
          'X-Sequence': seq,
          'X-Signature': Buffer.alloc(64, 0x11).toString('base64'),
        },
        body,
      });

      assert.equal(res.status, 401);
      assert.equal(res.json().error, 'MISSING_ASSERTION');
    });

    it('rejects malformed non-canonical base64 in X-Assertion with 401 NON_CANONICAL_BASE64_ASSERTION or INVALID_BASE64_ASSERTION', async () => {
      const timestamp = String(currentNow);
      const seq = '9007199254741041';
      const body = Buffer.from('{}');

      const res = await makeRequest(serverBaseUrl, {
        method: 'POST',
        path: '/api/tarot/read',
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'X-Device-Id': registeredDeviceId,
          'X-Timestamp': timestamp,
          'X-Sequence': seq,
          'X-Assertion': 'not-valid-base64!@#$',
        },
        body,
      });

      assert.equal(res.status, 401);
      assert.ok(
        res.json().error === 'INVALID_BASE64_ASSERTION' ||
        res.json().error === 'NON_CANONICAL_BASE64_ASSERTION'
      );
    });
  });

  // =========================================================================
  // 9. AAGUID & APP ID & FRAUD RECEIPT SECURITY CHECKS
  // =========================================================================
  describe('9. AAGUID & App ID & Fraud Receipt Security Checks', () => {
    it('rejects registration with AAGUID mismatch (403 AAGUID_MISMATCH)', async () => {
      const ch = await service.issueChallenge('ios');
      const badAaguidFixture = await createIosAttestationFixture({
        appId,
        challenge: ch.challenge,
        now: currentNow,
        environment: 'production',
        wrongAaguid: true,
        rootCA,
        receiptRootCA,
      });

      await assert.rejects(
        async () => {
          await service.registerDevice({
            challenge: ch.challenge,
            attestationObject: badAaguidFixture.attestationObjectBase64,
            keyId: badAaguidFixture.keyId,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'AAGUID_MISMATCH');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects registration with App ID mismatch in authData (401 RP_ID_MISMATCH)', async () => {
      const ch = await service.issueChallenge('ios');
      const badAppIdFixture = await createIosAttestationFixture({
        appId,
        challenge: ch.challenge,
        now: currentNow,
        environment: 'production',
        wrongAppIdInAuthData: true,
        rootCA,
        receiptRootCA,
      });

      await assert.rejects(
        async () => {
          await service.registerDevice({
            challenge: ch.challenge,
            attestationObject: badAppIdFixture.attestationObjectBase64,
            keyId: badAppIdFixture.keyId,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'RP_ID_MISMATCH');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects registration with App ID mismatch in CMS fraud receipt (403 RECEIPT_APP_ID_MISMATCH)', async () => {
      const ch = await service.issueChallenge('ios');
      const badReceiptFixture = await createIosAttestationFixture({
        appId,
        challenge: ch.challenge,
        now: currentNow,
        environment: 'production',
        wrongReceiptAppId: 'ROGUE.com.attacker',
        rootCA,
        receiptRootCA,
      });

      await assert.rejects(
        async () => {
          await service.registerDevice({
            challenge: ch.challenge,
            attestationObject: badReceiptFixture.attestationObjectBase64,
            keyId: badReceiptFixture.keyId,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'RECEIPT_APP_ID_MISMATCH');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects request assertion when rpIdHash in authenticatorData does not match expected App ID (401 RP_ID_MISMATCH)', async () => {
      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '80', 'POST', '/api/tarot/read', Buffer.from('{}'));

      const wrongAppIdAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 280,
        flags: 0x40,
        wrongAppId: true,
      });

      dev.signCount = 279;

      await assert.rejects(
        async () => {
          await provider.verifyRequest(dev, {
            canonical,
            assertion: wrongAppIdAssertion.assertionBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'RP_ID_MISMATCH');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects request assertion when device record App ID does not match provider App ID (403 APP_ID_MISMATCH)', async () => {
      const mismatchedProvider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId: 'OTHERTEAM999.com.other.bundle',
        environment: 'production',
        receiptVerifier: fixture.receiptVerifier,
        now: () => currentNow,
      });

      const dev = await store.getDevice(registeredDeviceId);
      assert.ok(dev);

      const timestamp = String(currentNow);
      const canonical = buildCanonicalBuffer(timestamp, '81', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const assertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 281,
        flags: 0x40,
      });

      dev.signCount = 280;

      await assert.rejects(
        async () => {
          await mismatchedProvider.verifyRequest(dev, {
            canonical,
            assertion: assertion.assertionBase64,
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'APP_ID_MISMATCH');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });
  });

  // =========================================================================
  // 10. SWIFT CLIENT INTEGRATION & PACKAGE TESTS
  // =========================================================================
  describe('10. Swift Client Integration & Package Tests', () => {
    it('detects Swift on host and executes swift test on demo/swift', (t) => {
      const swiftInfo = getSwiftEnvironment();

      if (!swiftInfo) {
        t.skip('Swift not found on this system; skipping Swift client integration test.');
        return;
      }

      const packageDir = path.resolve('demo/swift');
      assert.ok(fs.existsSync(path.join(packageDir, 'Package.swift')), 'demo/swift/Package.swift must exist');

      try {
        const cmd = `"${swiftInfo.swiftBin}" test --package-path "${packageDir}"`;
        const output = execSync(cmd, {
          env: swiftInfo.env,
          stdio: 'pipe',
        });
        const outStr = output.toString('utf8');
        assert.ok(outStr.includes('passed'), 'Swift test suite must pass');
      } catch (err: unknown) {
        const execErr = err as { stdout?: Buffer; stderr?: Buffer; message?: string };
        const errMsg = execErr.stderr?.toString('utf8') || execErr.stdout?.toString('utf8') || execErr.message;
        assert.fail(`Swift test failed for demo/swift: ${errMsg}`);
      }
    });

    it('gracefully skips if Swift binary is missing or not installed on the system', (t) => {
      const mockMissingSwift: { swiftBin: string; env: NodeJS.ProcessEnv } | null = null;
      if (!mockMissingSwift) {
        t.skip('Swift environment not detected; gracefully skipped as expected.');
        return;
      }
      assert.fail('Should not be executed when Swift is null');
    });
  });
});
