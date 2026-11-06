import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createClient } from 'redis';
import { IOSSecurityProvider } from '../src/platform/ios.js';
import { SecurityService } from '../src/core/security-service.js';
import { MemorySecurityStore } from '../src/store/memory.js';
import { RedisSecurityStore } from '../src/store/redis.js';
import { SecurityError } from '../src/contracts.js';
import { buildCanonicalBuffer } from '../src/core/canonical.js';
import {
  createIosAttestationFixture,
  createIosAssertion,
  createAppleAttestRootCA,
  encodeCbor
} from './helpers/ios-fixtures.js';
import { checkRedisAvailable } from './helpers/redis-probe.js';

const REDIS_URL = process.env.REDIS_TEST_URL;

describe('IOSSecurityProvider (Unit & Cryptographic Invariants)', () => {
  const appId = 'TEAMID123.com.astrology.tarot';
  const now = 1729800000000;

  describe('Happy Path: Synthetic Valid Apple App Attest Registration & Assertion', () => {
    it('successfully verifies valid synthetic production attestation chain and extracts EC SPKI PEM', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        environment: 'production'
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        environment: 'production',
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const result = await provider.verifyRegistration(
        {
          challenge: fixture.challengeHex,
          attestationObject: fixture.attestationObjectBase64,
          keyId: fixture.keyId
        },
        { challenge: fixture.challenge }
      );

      assert.ok(result.publicKeyPem.includes('-----BEGIN PUBLIC KEY-----'));
      assert.equal(result.keyId, fixture.keyId);
      assert.equal(result.signCount, 0);
      assert.equal(result.metadata.platform, 'ios');
      assert.equal(result.metadata.environment, 'production');
      assert.equal(result.metadata.appId, appId);
      assert.ok(result.metadata.receipt);
    });

    it('successfully verifies valid development environment attestation (AAGUID appattestdevelop)', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        environment: 'development'
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        environment: 'development',
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const result = await provider.verifyRegistration(
        {
          challenge: fixture.challengeHex,
          attestationObject: fixture.attestationObjectBase64,
          keyId: fixture.keyId
        },
        { challenge: fixture.challenge }
      );

      assert.equal(result.metadata.environment, 'development');
    });

    it('successfully verifies valid request assertion and advances counter (0 -> 1 -> 2)', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const verified = await provider.verifyRegistration(
        {
          challenge: fixture.challengeHex,
          attestationObject: fixture.attestationObjectBase64,
          keyId: fixture.keyId
        },
        { challenge: fixture.challenge }
      );

      const device = {
        deviceId: 'ios-dev-1',
        platform: 'ios' as const,
        publicKeyPem: verified.publicKeyPem,
        lastSequence: '0',
        signCount: 0,
        registeredAt: now,
        metadata: verified.metadata
      };

      // 1. First assertion: counter 1
      const canonical1 = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{"req":1}'));
      const assertion1 = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical1,
        counter: 1
      });

      const res1 = await provider.verifyRequest(device, {
        canonical: canonical1,
        assertion: assertion1.assertionBase64
      });
      assert.equal(res1.signCount, 1);
      device.signCount = 1;

      // 2. Second assertion: counter 2
      const canonical2 = buildCanonicalBuffer(String(now), '2', 'POST', '/api/tarot/read', Buffer.from('{"req":2}'));
      const assertion2 = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical2,
        counter: 2
      });

      const res2 = await provider.verifyRequest(device, {
        canonical: canonical2,
        assertion: assertion2.assertionBase64
      });
      assert.equal(res2.signCount, 2);
    });

    it('accepts assertion with flags=0 as legitimate without user presence requirement', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const verified = await provider.verifyRegistration(
        {
          challenge: fixture.challengeHex,
          attestationObject: fixture.attestationObjectBase64,
          keyId: fixture.keyId
        },
        { challenge: fixture.challenge }
      );

      const device = {
        deviceId: 'ios-dev-up-test',
        platform: 'ios' as const,
        publicKeyPem: verified.publicKeyPem,
        lastSequence: '0',
        signCount: 0,
        registeredAt: now,
        metadata: verified.metadata
      };

      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const assertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1,
        flags: 0 // No UP flag set
      });

      const res = await provider.verifyRequest(device, {
        canonical,
        assertion: assertion.assertionBase64
      });
      assert.equal(res.signCount, 1);
    });

    it('accepts legacy iOS attestation without 2026 app properties extensions by default', async () => {
      // No validationCategory or bundleVersion provided
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        requireAppProperties: false,
        now: () => now
      });

      const result = await provider.verifyRegistration(
        {
          challenge: fixture.challengeHex,
          attestationObject: fixture.attestationObjectBase64,
          keyId: fixture.keyId
        },
        { challenge: fixture.challenge }
      );

      assert.equal(result.metadata.validationCategory, undefined);
      assert.equal(result.metadata.bundleVersion, undefined);
    });

    it('parses and accepts 2026 Apple extensions (validationCategory & bundleVersion) when valid', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        validationCategory: 1,
        bundleVersion: '2.1.0'
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        allowedValidationCategories: [1, 2],
        minimumBundleVersion: '2.0.0',
        requireAppProperties: true,
        now: () => now
      });

      const result = await provider.verifyRegistration(
        {
          challenge: fixture.challengeHex,
          attestationObject: fixture.attestationObjectBase64,
          keyId: fixture.keyId
        },
        { challenge: fixture.challenge }
      );

      assert.equal(result.metadata.validationCategory, 1);
      assert.equal(result.metadata.bundleVersion, '2.1.0');
    });
  });

  describe('Attestation Invariants & Negative Tests', () => {
    it('rejects challenge mismatch between hardware attestation and server context (403 ATTESTATION_CHALLENGE_MISMATCH)', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      // Different server challenge
      const differentChallenge = crypto.randomBytes(32);

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: differentChallenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'ATTESTATION_CHALLENGE_MISMATCH');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects attestation with missing Apple nonce extension 1.2.840.113635.100.8.2', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        omitNonceExtension: true
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MISSING_ATTESTATION_NONCE_EXTENSION');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects corrupted nonce (even 1-bit alteration) with 403 ATTESTATION_CHALLENGE_MISMATCH', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        corruptNonce: true
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'ATTESTATION_CHALLENGE_MISMATCH');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects leaf key that is RSA instead of EC P-256 with 403 ATTESTED_KEY_NOT_EC', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        leafKeyType: 'RSA'
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'ATTESTED_KEY_NOT_EC');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects chain with untrusted Root CA', async () => {
      const untrustedRoot = await createAppleAttestRootCA({ now });
      const trustedRoot = await createAppleAttestRootCA({ now });

      const fixture = await createIosAttestationFixture({
        appId,
        now,
        rootCA: untrustedRoot
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [trustedRoot.certPem], // Expects trustedRoot
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'UNTRUSTED_ROOT_CA');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects mismatched appId in authData rpIdHash with 401 RP_ID_MISMATCH', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        wrongAppIdInAuthData: true
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'RP_ID_MISMATCH');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects AAGUID environment mismatch (e.g. dev AAGUID in production provider) with 403 AAGUID_MISMATCH', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        environment: 'development' // Created with 'appattestdevelop' AAGUID
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        environment: 'production', // Provider configured for production!
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'AAGUID_MISMATCH');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects credentialId mismatch with 400 CREDENTIAL_ID_MISMATCH', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        wrongCredId: true
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'CREDENTIAL_ID_MISMATCH');
          assert.equal(err.status, 400);
          return true;
        }
      );
    });

    it('rejects COSE key mismatch with 400 COSE_KEY_MISMATCH', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        wrongCoseKey: true
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'COSE_KEY_MISMATCH');
          assert.equal(err.status, 400);
          return true;
        }
      );
    });

    it('rejects initial signCount !== 0 on registration with 400 INVALID_SIGN_COUNT', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        initialSignCount: 5 // Non-zero initial signCount!
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGN_COUNT');
          assert.equal(err.status, 400);
          return true;
        }
      );
    });

    it('rejects registration authData with missing AT flag (0x40)', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        flags: 0 // AT bit not set!
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'ATTESTED_CREDENTIAL_DATA_FLAG_MISSING');
          assert.equal(err.status, 400);
          return true;
        }
      );
    });

    it('rejects missing receipt in attStmt with 400 MISSING_APP_ATTEST_RECEIPT', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        omitReceipt: true
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MISSING_APP_ATTEST_RECEIPT');
          assert.equal(err.status, 400);
          return true;
        }
      );
    });

    it('rejects duplicate CBOR map keys with 400 DUPLICATE_CBOR_KEY', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        duplicateCborKey: true
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'DUPLICATE_CBOR_KEY');
          assert.equal(err.status, 400);
          return true;
        }
      );
    });

    it('rejects oversize attestation payload (> 256 KB) with 400 ATTESTATION_OBJECT_TOO_LARGE', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        oversizeAttestation: true
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'ATTESTATION_OBJECT_TOO_LARGE');
          assert.equal(err.status, 400);
          return true;
        }
      );
    });

    it('rejects registration when requireAppProperties is true but extensions are missing with 403 MISSING_APP_PROPERTIES', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now
        // No validationCategory or bundleVersion
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        requireAppProperties: true, // Strict mode requires 2026 properties
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MISSING_APP_PROPERTIES');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects disallowed validation category with 403 VALIDATION_CATEGORY_NOT_ALLOWED', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        validationCategory: 3 // Category 3
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        allowedValidationCategories: [1, 2], // Only 1 and 2 allowed
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'VALIDATION_CATEGORY_NOT_ALLOWED');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects bundle version lower than minimumBundleVersion with 403 BUNDLE_VERSION_TOO_LOW', async () => {
      const fixture = await createIosAttestationFixture({
        appId,
        now,
        bundleVersion: '1.9.5' // Lower than minimum
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        minimumBundleVersion: '2.0.0',
        now: () => now
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: fixture.challengeHex,
              attestationObject: fixture.attestationObjectBase64,
              keyId: fixture.keyId
            },
            { challenge: fixture.challenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'BUNDLE_VERSION_TOO_LOW');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });
  });

  describe('Assertion Invariants & Negative Tests', () => {
    function createVerifiedIosDevice(fixture: any, options: { signCount?: number; appId?: string; environment?: string } = {}) {
      return {
        deviceId: 'ios-dev-fixture-1',
        platform: 'ios' as const,
        publicKeyPem: fixture.leafPublicKeyPem,
        lastSequence: '0',
        signCount: options.signCount ?? 0,
        registeredAt: now,
        metadata: {
          platform: 'ios',
          appId: options.appId ?? fixture.appId,
          environment: options.environment ?? 'production'
        }
      };
    }

    it('rejects non-monotonic counter rollback or replay (counter <= previousCounter) with 401 SIGN_COUNT_NOT_INCREASED', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 5 });

      // Attacker attempts counter 5 (replay) or 4 (rollback)
      const canonical = buildCanonicalBuffer(String(now), '6', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const replayAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 5
      });

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, assertion: replayAssertion.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'SIGN_COUNT_NOT_INCREASED');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects assertion signed with incorrect double-hash composite with 401 INVALID_SIGNATURE', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });

      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const doubleHashedAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1,
        doubleHash: true // Incorrect double hashing!
      });

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, assertion: doubleHashedAssertion.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('accepts assertion with AT flag set (0x40) when length is 37 bytes', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });

      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const assertionWithAt = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1,
        flags: 0x40 // iOS DCAppAttestService sets AT flag in assertions
      });

      const result = await provider.verifyRequest(device, { canonical, assertion: assertionWithAt.assertionBase64 });
      assert.equal(result.signCount, 1);
    });

    it('rejects assertion with AT flag set (0x40) when length > 37 bytes and ED is clear with 401 INVALID_AUTHENTICATOR_DATA_LENGTH', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });

      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const rogueAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1,
        flags: 0x40, // AT flag set, ED clear
        extraAuthData: Buffer.alloc(16, 0xaa) // Extra credential data attached (> 37 bytes)
      });

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, assertion: rogueAssertion.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_AUTHENTICATOR_DATA_LENGTH');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects assertion with unsupported flags individually (0x02, 0x08, 0x10, 0x20) and combined with AT with 401 UNSUPPORTED_AUTHENTICATOR_FLAGS', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });
      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      const badFlags = [
        0x02, // RFU bit 1
        0x08, // WebAuthn L3 BE bit 3
        0x10, // WebAuthn L3 BS bit 4
        0x20, // RFU bit 5
        0x40 | 0x02, // AT + RFU bit 1
        0x40 | 0x08, // AT + BE bit 3
        0x40 | 0x10, // AT + BS bit 4
        0x40 | 0x20  // AT + RFU bit 5
      ];

      for (const flags of badFlags) {
        const rogueAssertion = createIosAssertion({
          appId,
          privateKeyPem: fixture.leafPrivateKeyPem,
          canonicalBuffer: canonical,
          counter: 1,
          flags
        });

        await assert.rejects(
          () => provider.verifyRequest(device, { canonical, assertion: rogueAssertion.assertionBase64 }),
          (err: unknown) => {
            assert.ok(err instanceof SecurityError, `Expected SecurityError for flags 0x${flags.toString(16)}`);
            assert.equal(err.code, 'UNSUPPORTED_AUTHENTICATOR_FLAGS');
            assert.equal(err.status, 401);
            return true;
          }
        );
      }
    });

    it('accepts assertion with AT + ED flags set (0xc0) and valid CBOR extension map', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });
      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      // Extension data: empty CBOR map ({})
      const emptyExtMapBytes = encodeCbor(new Map());
      const assertionWithAtAndEd = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1,
        flags: 0x40 | 0x80, // AT (0x40) + ED (0x80)
        extraAuthData: emptyExtMapBytes
      });

      const result = await provider.verifyRequest(device, { canonical, assertion: assertionWithAtAndEd.assertionBase64 });
      assert.equal(result.signCount, 1);
    });

    it('rejects assertion with AT + ED flags set (0xc0) when extension data is missing with 401 MISSING_EXTENSION_DATA', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });
      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      const assertionMissingExt = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1,
        flags: 0x40 | 0x80 // ED set but no extra bytes (length === 37)
      });

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, assertion: assertionMissingExt.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MISSING_EXTENSION_DATA');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects assertion with AT + ED flags set (0xc0) when extension data is not a CBOR map with 401 INVALID_EXTENSION_DATA', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });
      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      // Extension data: CBOR array instead of map
      const nonMapExtBytes = encodeCbor([1, 2, 3]);
      const assertionNonMap = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1,
        flags: 0x40 | 0x80,
        extraAuthData: nonMapExtBytes
      });

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, assertion: assertionNonMap.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_EXTENSION_DATA');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects assertion with AT + ED flags set (0xc0) when extension data has multiple CBOR items with 401 INVALID_EXTENSION_DATA', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });
      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      // Extension data: two concatenated CBOR maps
      const multiExtBytes = Buffer.concat([encodeCbor(new Map()), encodeCbor(new Map())]);
      const assertionMulti = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1,
        flags: 0x40 | 0x80,
        extraAuthData: multiExtBytes
      });

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, assertion: assertionMulti.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_EXTENSION_DATA');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects assertion with AT + ED flags set (0xc0) when requireAppProperties is true but extension map is empty with 403 MISSING_APP_PROPERTIES', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        requireAppProperties: true, // Requires validationCategory and bundleVersion
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });
      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));

      // Empty map
      const emptyExtMapBytes = encodeCbor(new Map());
      const assertionEmptyExt = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1,
        flags: 0x40 | 0x80,
        extraAuthData: emptyExtMapBytes
      });

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, assertion: assertionEmptyExt.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MISSING_APP_PROPERTIES');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects assertion with invalid signature length (< 8 or > 72 bytes) with 401 INVALID_SIGNATURE_LENGTH', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });

      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const shortSigAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1,
        invalidSignatureLength: true
      });

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, assertion: shortSigAssertion.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE_LENGTH');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects assertion with malformed DER signature (67 bytes invalid ASN.1) with 401 MALFORMED_DER_SIGNATURE', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });

      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const malformedAssertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1,
        malformedDerSignature: true
      });

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, assertion: malformedAssertion.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MALFORMED_DER_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects assertion signed with a different key with 401 INVALID_SIGNATURE', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });

      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{}'));
      const otherKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const otherPrivPem = otherKey.privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;

      const wrongKeyAssertion = createIosAssertion({
        appId,
        privateKeyPem: otherPrivPem, // Signed by different key!
        canonicalBuffer: canonical,
        counter: 1
      });

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, assertion: wrongKeyAssertion.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects assertion when canonical buffer is tampered (even 1-bit mutation) with 401 INVALID_SIGNATURE', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const device = createVerifiedIosDevice(fixture, { signCount: 0 });

      const originalCanonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{"card":"sun"}'));
      const assertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: originalCanonical,
        counter: 1
      });

      // 1-bit tampered canonical buffer
      const tamperedCanonical = Buffer.from(originalCanonical);
      tamperedCanonical[tamperedCanonical.length - 1] ^= 0x01;

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical: tamperedCanonical, assertion: assertion.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects assertion when device stored metadata is missing appId with 403 APP_ID_MISMATCH', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      // Otherwise valid device and valid signed assertion, but metadata.appId is absent
      const device = createVerifiedIosDevice(fixture, { signCount: 0 });
      delete (device.metadata as any).appId;

      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{"card":"sun"}'));
      const assertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1
      });

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, assertion: assertion.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'APP_ID_MISMATCH');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects assertion when device stored metadata is missing environment with 403 ENVIRONMENT_MISMATCH', async () => {
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      // Otherwise valid device and valid signed assertion, but metadata.environment is absent
      const device = createVerifiedIosDevice(fixture, { signCount: 0 });
      delete (device.metadata as any).environment;

      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', '/api/tarot/read', Buffer.from('{"card":"sun"}'));
      const assertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1
      });

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, assertion: assertion.assertionBase64 }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'ENVIRONMENT_MISMATCH');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });
  });

  describe('End-to-End SecurityService & Store Concurrency Invariants', () => {
    it('executes full iOS lifecycle (issue challenge -> register device -> monotonic request auth) via SecurityService', async () => {
      const store = new MemorySecurityStore({ now: () => now });
      const fixture = await createIosAttestationFixture({ appId, now });
      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const service = new SecurityService({
        store,
        providers: [provider],
        now: () => now
      });

      // 1. Issue challenge
      const chResult = await service.issueChallenge('ios');
      assert.equal(typeof chResult.challenge, 'string');

      // 2. Register device with challenge
      const regFixture = await createIosAttestationFixture({
        appId,
        now,
        challenge: chResult.challenge,
        rootCA: await createAppleAttestRootCA({ now })
      });

      const providerWithAnchor = new IOSSecurityProvider({
        trustAnchors: [regFixture.rootCertPem],
        appId,
        receiptVerifier: regFixture.receiptVerifier,
        now: () => now
      });

      const serviceWithAnchor = new SecurityService({
        store,
        providers: [providerWithAnchor],
        now: () => now
      });

      const regResult = await serviceWithAnchor.registerDevice({
        challenge: chResult.challenge,
        attestationObject: regFixture.attestationObjectBase64,
        keyId: regFixture.keyId
      });

      assert.equal(regResult.device.platform, 'ios');
      assert.equal(regResult.device.lastSequence, '0');
      assert.equal(regResult.device.signCount, 0);

      // 3. First authenticated request: sequence 1, counter 1
      const rawBody1 = Buffer.from('{"fortune":"good"}', 'utf8');
      const target = '/api/tarot/read';
      const canonical1 = buildCanonicalBuffer(String(now), '1', 'POST', target, rawBody1);
      const assertion1 = createIosAssertion({
        appId,
        privateKeyPem: regFixture.leafPrivateKeyPem,
        canonicalBuffer: canonical1,
        counter: 1
      });

      const authResult1 = await serviceWithAnchor.authenticateRequest({
        deviceId: regResult.deviceId,
        timestamp: String(now),
        sequence: '1',
        assertion: assertion1.assertionBase64,
        method: 'POST',
        requestTarget: target,
        rawBody: rawBody1
      });

      assert.equal(authResult1.device.lastSequence, '1');
      assert.equal(authResult1.device.signCount, 1);

      // 4. Second authenticated request: sequence 2, counter 2
      const rawBody2 = Buffer.from('{"fortune":"great"}', 'utf8');
      const canonical2 = buildCanonicalBuffer(String(now), '2', 'POST', target, rawBody2);
      const assertion2 = createIosAssertion({
        appId,
        privateKeyPem: regFixture.leafPrivateKeyPem,
        canonicalBuffer: canonical2,
        counter: 2
      });

      const authResult2 = await serviceWithAnchor.authenticateRequest({
        deviceId: regResult.deviceId,
        timestamp: String(now),
        sequence: '2',
        assertion: assertion2.assertionBase64,
        method: 'POST',
        requestTarget: target,
        rawBody: rawBody2
      });

      assert.equal(authResult2.device.lastSequence, '2');
      assert.equal(authResult2.device.signCount, 2);

      // 5. Replay sequence 2 fails closed
      await assert.rejects(
        () =>
          serviceWithAnchor.authenticateRequest({
            deviceId: regResult.deviceId,
            timestamp: String(now),
            sequence: '2',
            assertion: assertion2.assertionBase64,
            method: 'POST',
            requestTarget: target,
            rawBody: rawBody2
          }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.ok(
            err.code === 'SIGN_COUNT_NOT_INCREASED' || err.code === 'REPLAY_DETECTED',
            `Expected SIGN_COUNT_NOT_INCREASED or REPLAY_DETECTED but got ${err.code}`
          );
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('guarantees only 1 winner when 20 concurrent iOS requests fire with the same counter/sequence (MemoryStore)', async () => {
      const store = new MemorySecurityStore({ now: () => now });
      const fixture = await createIosAttestationFixture({ appId, now });
      const deviceId = 'ios-race-dev-mem';

      await store.createDeviceNX({
        deviceId,
        platform: 'ios',
        publicKeyPem: fixture.leafPublicKeyPem,
        lastSequence: '0',
        signCount: 0,
        registeredAt: now,
        keyId: fixture.keyId,
        metadata: { appId, environment: 'production', platform: 'ios' }
      });

      const provider = new IOSSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        appId,
        receiptVerifier: fixture.receiptVerifier,
        now: () => now
      });

      const service = new SecurityService({
        store,
        providers: [provider],
        now: () => now
      });

      const rawBody = Buffer.from('{"race":"test"}', 'utf8');
      const target = '/api/tarot/read';
      const canonical = buildCanonicalBuffer(String(now), '1', 'POST', target, rawBody);
      const assertion = createIosAssertion({
        appId,
        privateKeyPem: fixture.leafPrivateKeyPem,
        canonicalBuffer: canonical,
        counter: 1
      });

      const reqHeaders = {
        'x-device-id': deviceId,
        'x-timestamp': String(now),
        'x-sequence': '1',
        'x-assertion': assertion.assertionBase64
      };

      const promises = Array.from({ length: 20 }, () =>
        service.authenticateRequest({
          deviceId,
          timestamp: String(now),
          sequence: '1',
          assertion: assertion.assertionBase64,
          method: 'POST',
          requestTarget: target,
          rawBody
        })
      );

      const settled = await Promise.allSettled(promises);
      const successes = settled.filter((r) => r.status === 'fulfilled');
      const failures = settled.filter(
        (r): r is PromiseRejectedResult => r.status === 'rejected'
      );

      assert.equal(successes.length, 1, 'Exactly 1 concurrent request must win CAS sequence advance');
      assert.equal(failures.length, 19, '19 concurrent requests must fail with REPLAY_DETECTED');

      for (const f of failures) {
        assert.ok(f.reason instanceof SecurityError);
        assert.ok(
          f.reason.code === 'COUNTER_ROLLBACK' || f.reason.code === 'REPLAY_DETECTED',
          `Expected COUNTER_ROLLBACK or REPLAY_DETECTED but got ${f.reason.code}`
        );
        assert.equal(f.reason.status, 401);
      }
    });

    describe('Redis Concurrency Race (Real Redis Integration)', async () => {
      const isRedisAvailable = await checkRedisAvailable(REDIS_URL);

      if (!isRedisAvailable) {
        it.skip('Skipping Redis concurrency race: REDIS_TEST_URL not reachable', () => {});
        return;
      }

      const redisUrl = REDIS_URL!;

      it('guarantees only 1 winner when 20 concurrent iOS requests fire with the same counter/sequence (RedisStore)', async () => {
        const prefix = `test:sec:ios-race:${crypto.randomUUID()}:`;
        const store = new RedisSecurityStore({ url: redisUrl, keyPrefix: prefix });
        const fixture = await createIosAttestationFixture({ appId, now });
        const deviceId = 'ios-race-dev-redis';

        const rawClient = createClient({ url: redisUrl });
        rawClient.on('error', () => {});
        await rawClient.connect();

        try {
          await store.createDeviceNX({
            deviceId,
            platform: 'ios',
            publicKeyPem: fixture.leafPublicKeyPem,
            lastSequence: '0',
            signCount: 0,
            registeredAt: now,
            keyId: fixture.keyId,
            metadata: { appId, environment: 'production', platform: 'ios' }
          });

          const provider = new IOSSecurityProvider({
            trustAnchors: [fixture.rootCertPem],
            appId,
            receiptVerifier: fixture.receiptVerifier,
            now: () => now
          });

          const service = new SecurityService({
            store,
            providers: [provider],
            now: () => now
          });

          const rawBody = Buffer.from('{"race":"test"}', 'utf8');
          const target = '/api/tarot/read';
          const canonical = buildCanonicalBuffer(String(now), '1', 'POST', target, rawBody);
          const assertion = createIosAssertion({
            appId,
            privateKeyPem: fixture.leafPrivateKeyPem,
            canonicalBuffer: canonical,
            counter: 1
          });

          const reqHeaders = {
            'x-device-id': deviceId,
            'x-timestamp': String(now),
            'x-sequence': '1',
            'x-assertion': assertion.assertionBase64
          };

          const promises = Array.from({ length: 20 }, () =>
            service.authenticateRequest({
              deviceId,
              timestamp: String(now),
              sequence: '1',
              assertion: assertion.assertionBase64,
              method: 'POST',
              requestTarget: target,
              rawBody
            })
          );

          const settled = await Promise.allSettled(promises);
          const successes = settled.filter((r) => r.status === 'fulfilled');
          const failures = settled.filter(
            (r): r is PromiseRejectedResult => r.status === 'rejected'
          );

          assert.equal(successes.length, 1, 'Exactly 1 concurrent request must win CAS in Redis Lua');
          assert.equal(failures.length, 19, '19 concurrent requests must fail with REPLAY_DETECTED');

          for (const f of failures) {
            assert.ok(f.reason instanceof SecurityError);
            assert.equal(f.reason.code, 'REPLAY_DETECTED');
            assert.equal(f.reason.status, 401);
          }
        } finally {
          const keys = await rawClient.keys(`${prefix}*`);
          if (keys.length > 0) {
            await rawClient.del(keys);
          }
          await rawClient.quit();
          await store.close();
        }
      });
    });
  });
});
