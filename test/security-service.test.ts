import test, { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
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
import { AndroidSecurityProvider } from '../src/platform/android.js';

class MockAndroidProvider implements DeviceSecurityProvider {
  readonly platform = 'android' as const;
  public registrationError: Error | null = null;
  public requestError: Error | null = null;

  async verifyRegistration(
    input: RegistrationInput,
    context: { challenge: Buffer }
  ): Promise<VerifiedRegistration> {
    if (this.registrationError) {
      throw this.registrationError;
    }

    if (!input.certificateChain || input.certificateChain.length === 0) {
      throw new SecurityError('INVALID_CERTIFICATE_CHAIN', 400);
    }

    // In a real provider, leaf public key is extracted from chain[0]
    const leafDer = Buffer.from(input.certificateChain[0], 'base64');
    const leafCert = new crypto.X509Certificate(leafDer);
    const publicKeyPem = leafCert.publicKey.export({ type: 'spki', format: 'pem' }) as string;

    return {
      publicKeyPem,
      metadata: { verifiedChallenge: context.challenge.toString('utf8') }
    };
  }

  async verifyRequest(device: DeviceRecord, proof: RequestProof): Promise<{ signCount?: number }> {
    if (this.requestError) {
      throw this.requestError;
    }

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

describe('SecurityService (Core Lifecycle & Invariant Tests)', () => {
  let store: MemorySecurityStore;
  let provider: MockAndroidProvider;
  let service: SecurityService;
  let fixedNow: number;
  let fixture: Awaited<ReturnType<typeof createAttestationChain>>;

  beforeEach(async () => {
    fixedNow = 1729800000000;
    store = new MemorySecurityStore();
    provider = new MockAndroidProvider();
    service = new SecurityService({
      store,
      providers: [provider],
      now: () => fixedNow
    });
    fixture = await createAttestationChain();
  });

  describe('issueChallenge', () => {
    it('issues a cryptographically random 32-byte hex challenge with 60s TTL', async () => {
      const result = await service.issueChallenge('android');

      assert.equal(typeof result.challenge, 'string');
      assert.equal(result.challenge.length, 64, 'Must be 64-char hex string (32 bytes)');
      assert.match(result.challenge, /^[0-9a-f]{64}$/);
      assert.equal(result.platform, 'android');
      assert.equal(result.expiresAt, fixedNow + 60000);
    });

    it('rejects unsupported platform when issuing challenge', async () => {
      await assert.rejects(
        async () => {
          await service.issueChallenge('windows' as any);
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_PLATFORM');
          assert.equal(err.status, 400);
          return true;
        }
      );
    });
  });

  describe('registerDevice', () => {
    it('successfully registers device by consuming challenge and persists record', async () => {
      const challengeResult = await service.issueChallenge('android');

      const registerResult = await service.registerDevice({
        challenge: challengeResult.challenge,
        certificateChain: fixture.chain
      });

      assert.ok(registerResult.deviceId);
      assert.equal(registerResult.deviceId, fixture.deviceId);
      assert.equal(registerResult.device.platform, 'android');
      assert.equal(registerResult.device.lastSequence, '0');
      assert.equal(registerResult.device.registeredAt, fixedNow);

      // Verify device was stored
      const stored = await store.getDevice(registerResult.deviceId);
      assert.ok(stored);
      assert.equal(stored.deviceId, registerResult.deviceId);
    });

    it('enforces single-use challenge consumption (replay registration fails)', async () => {
      const challengeResult = await service.issueChallenge('android');

      // First registration succeeds
      await service.registerDevice({
        challenge: challengeResult.challenge,
        certificateChain: fixture.chain
      });

      // Second registration with same challenge fails with INVALID_CHALLENGE (401)
      await assert.rejects(
        async () => {
          await service.registerDevice({
            challenge: challengeResult.challenge,
            certificateChain: fixture.chain
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_CHALLENGE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('prevents re-registration from overwriting or resetting sequence (DEVICE_ALREADY_REGISTERED 409)', async () => {
      // 1. Register device
      const ch1 = await service.issueChallenge('android');
      const reg = await service.registerDevice({
        challenge: ch1.challenge,
        certificateChain: fixture.chain
      });

      // 2. Advance sequence to 42
      const commitRes = await store.commitSequence(reg.deviceId, reg.device.publicKeyPem, '42');
      assert.equal(commitRes.ok, true, 'Initial sequence commit to 42 must succeed');

      // 3. Issue a new challenge and try to re-register the same hardware key
      const ch2 = await service.issueChallenge('android');
      await assert.rejects(
        async () => {
          await service.registerDevice({
            challenge: ch2.challenge,
            certificateChain: fixture.chain
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'DEVICE_ALREADY_REGISTERED');
          assert.equal(err.status, 409);
          return true;
        }
      );

      // 4. Verify sequence was NOT reset to 0
      const current = await store.getDevice(reg.deviceId);
      assert.equal(current?.lastSequence, '42', 'Sequence must remain 42');
    });
  });

  describe('authenticateRequest', () => {
    let deviceId: string;

    beforeEach(async () => {
      const ch = await service.issueChallenge('android');
      const reg = await service.registerDevice({
        challenge: ch.challenge,
        certificateChain: fixture.chain
      });
      deviceId = reg.deviceId;
    });

    it('authenticates valid signed request and advances sequence', async () => {
      const rawBody = Buffer.from('{"tarot":"the-fool"}', 'utf8');
      const target = '/api/tarot/read';
      const timestamp = String(fixedNow);
      const sequence = '1';

      const canonical = buildCanonicalBuffer(timestamp, sequence, 'POST', target, rawBody);
      const signature = signCanonical(fixture.leafPrivateKeyPem, canonical);

      const auth = await service.authenticateRequest({
        deviceId,
        timestamp,
        sequence,
        signature,
        method: 'POST',
        requestTarget: target,
        rawBody
      });

      assert.equal(auth.device.deviceId, deviceId);
      assert.equal(auth.sequence, '1');
      assert.equal(auth.device.lastSequence, '1');

      // Verify store was updated
      const stored = await store.getDevice(deviceId);
      assert.equal(stored?.lastSequence, '1');
    });

    it('CRITICAL INVARIANT: invalid signature MUST NOT advance sequence or burn counter', async () => {
      const rawBody = Buffer.from('{"tarot":"card"}', 'utf8');
      const target = '/api/tarot/read';
      const timestamp = String(fixedNow);
      const sequence = '1';

      // 1. Submit request with INVALID signature
      const invalidSignature = Buffer.from('invalid-signature-bytes').toString('base64');

      await assert.rejects(
        async () => {
          await service.authenticateRequest({
            deviceId,
            timestamp,
            sequence,
            signature: invalidSignature,
            method: 'POST',
            requestTarget: target,
            rawBody
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );

      // 2. CRITICAL CHECK: Verify that lastSequence in store did NOT advance to 1 (must still be '0')
      const stored = await store.getDevice(deviceId);
      assert.equal(stored?.lastSequence, '0', 'Invalid signature must not advance stored sequence!');

      // 3. Client re-signs the SAME sequence '1' with correct signature and it succeeds!
      const validCanonical = buildCanonicalBuffer(timestamp, sequence, 'POST', target, rawBody);
      const validSignature = signCanonical(fixture.leafPrivateKeyPem, validCanonical);

      const authOk = await service.authenticateRequest({
        deviceId,
        timestamp,
        sequence,
        signature: validSignature,
        method: 'POST',
        requestTarget: target,
        rawBody
      });
      assert.equal(authOk.sequence, '1');

      const updated = await store.getDevice(deviceId);
      assert.equal(updated?.lastSequence, '1');
    });

    it('rejects replay of previously committed sequence (REPLAY_DETECTED 401)', async () => {
      const rawBody = Buffer.from('{}', 'utf8');
      const target = '/api/tarot/read';
      const timestamp = String(fixedNow);

      // 1. First request with sequence 5 succeeds
      const canon1 = buildCanonicalBuffer(timestamp, '5', 'POST', target, rawBody);
      const sig1 = signCanonical(fixture.leafPrivateKeyPem, canon1);

      await service.authenticateRequest({
        deviceId,
        timestamp,
        sequence: '5',
        signature: sig1,
        method: 'POST',
        requestTarget: target,
        rawBody
      });

      // 2. Replay with sequence 5 fails
      await assert.rejects(
        async () => {
          await service.authenticateRequest({
            deviceId,
            timestamp,
            sequence: '5',
            signature: sig1,
            method: 'POST',
            requestTarget: target,
            rawBody
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'REPLAY_DETECTED');
          assert.equal(err.status, 401);
          return true;
        }
      );

      // 3. Regressive sequence 3 fails
      const canon3 = buildCanonicalBuffer(timestamp, '3', 'POST', target, rawBody);
      const sig3 = signCanonical(fixture.leafPrivateKeyPem, canon3);
      await assert.rejects(
        async () => {
          await service.authenticateRequest({
            deviceId,
            timestamp,
            sequence: '3',
            signature: sig3,
            method: 'POST',
            requestTarget: target,
            rawBody
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'REPLAY_DETECTED');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects request from unregistered device with DEVICE_NOT_REGISTERED (401)', async () => {
      const unknownDeviceId = 'non-existent-device-id';
      const rawBody = Buffer.alloc(0);
      const target = '/api/tarot/read';
      const timestamp = String(fixedNow);

      await assert.rejects(
        async () => {
          await service.authenticateRequest({
            deviceId: unknownDeviceId,
            timestamp,
            sequence: '1',
            signature: 'dummy-sig',
            method: 'POST',
            requestTarget: target,
            rawBody
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'DEVICE_NOT_REGISTERED');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects request with missing signature header for Android device with MISSING_SIGNATURE (401)', async () => {
      const rawBody = Buffer.alloc(0);
      const target = '/api/tarot/read';
      const timestamp = String(fixedNow);

      await assert.rejects(
        async () => {
          await service.authenticateRequest({
            deviceId,
            timestamp,
            sequence: '1',
            signature: undefined, // Missing signature!
            method: 'POST',
            requestTarget: target,
            rawBody
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MISSING_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('guarantees only 1 winner when 20 concurrent requests fire with the same sequence', async () => {
      const rawBody = Buffer.from('{"concurrent":true}', 'utf8');
      const target = '/api/tarot/read';
      const timestamp = String(fixedNow);
      const sequence = '100';

      const canonical = buildCanonicalBuffer(timestamp, sequence, 'POST', target, rawBody);
      const signature = signCanonical(fixture.leafPrivateKeyPem, canonical);

      const promises = Array.from({ length: 20 }, () =>
        service
          .authenticateRequest({
            deviceId,
            timestamp,
            sequence,
            signature,
            method: 'POST',
            requestTarget: target,
            rawBody
          })
          .then(
            () => ({ ok: true }),
            (err) => ({ ok: false, error: err })
          )
      );

      const results = await Promise.all(promises);
      const successes = results.filter((r) => r.ok);
      const failures = results.filter((r): r is { ok: false; error: any } => !r.ok);

      assert.equal(successes.length, 1, 'Exactly one concurrent request must succeed');
      assert.equal(failures.length, 19, '19 concurrent requests must fail');

      for (const f of failures) {
        assert.ok(f.error instanceof SecurityError);
        assert.equal(f.error.code, 'REPLAY_DETECTED');
        assert.equal(f.error.status, 401);
      }
    });
  });

  describe('End-to-End SecurityService with REAL AndroidSecurityProvider', () => {
    it('executes complete registration and request authentication through real Android provider', async () => {
      const realFixture = await createAttestationChain({ now: fixedNow });
      const emptyRevocations = {
        async getRevokedSerials() { return new Set<string>(); }
      };

      const realProvider = new AndroidSecurityProvider({
        trustAnchors: [realFixture.rootCertPem],
        expectedPackageName: realFixture.expectedPackageName,
        expectedSignerDigests: realFixture.expectedSignerDigests,
        revocationSource: emptyRevocations,
        now: () => fixedNow
      });

      const realService = new SecurityService({
        store,
        providers: [realProvider],
        now: () => fixedNow
      });

      // 1. Issue challenge
      const chResult = await realService.issueChallenge('android');
      assert.equal(typeof chResult.challenge, 'string');

      // 2. Register device with real provider verifying cryptographic attestation chain
      const regFixture = await createAttestationChain({
        now: fixedNow,
        rootCA: realFixture.rootCA,
        intermediateCA: realFixture.intermediateCA,
        challengeHex: chResult.challenge
      });

      const regResult = await realService.registerDevice({
        challenge: chResult.challenge,
        certificateChain: regFixture.chain
      });

      assert.equal(regResult.deviceId, regFixture.deviceId);
      assert.equal(regResult.device.platform, 'android');
      assert.equal(regResult.device.lastSequence, '0');

      // 3. Authenticate incoming request signed by real leaf key
      const rawBody = Buffer.from('{"tarot":"the-star"}', 'utf8');
      const target = '/api/tarot/read';
      const timestamp = String(fixedNow);
      const sequence = '1';

      const canonical = buildCanonicalBuffer(timestamp, sequence, 'POST', target, rawBody);
      const signature = signCanonical(regFixture.leafPrivateKeyPem, canonical);

      const auth = await realService.authenticateRequest({
        deviceId: regResult.deviceId,
        timestamp,
        sequence,
        signature,
        method: 'POST',
        requestTarget: target,
        rawBody
      });

      assert.equal(auth.device.deviceId, regResult.deviceId);
      assert.equal(auth.sequence, '1');

      // 4. Replay of same sequence is rejected
      await assert.rejects(
        () => realService.authenticateRequest({
          deviceId: regResult.deviceId,
          timestamp,
          sequence,
          signature,
          method: 'POST',
          requestTarget: target,
          rawBody
        }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'REPLAY_DETECTED');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });
  });
});
