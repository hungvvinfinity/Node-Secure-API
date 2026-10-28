import test, { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { AndroidSecurityProvider, type RevocationSource } from '../src/platform/android.js';
import { SecurityError, type DeviceRecord } from '../src/contracts.js';
import {
  createAttestationChain,
  signCanonical
} from './helpers/crypto-fixtures.js';

class MockRevocationSource implements RevocationSource {
  public revokedSerials = new Set<string>();
  public shouldFail = false;

  async getRevokedSerials(): Promise<Set<string>> {
    if (this.shouldFail) {
      throw new Error('Revocation endpoint offline');
    }
    return new Set(this.revokedSerials);
  }
}

describe('AndroidSecurityProvider (Unit & Cryptographic Invariants)', () => {
  let revocationSource: MockRevocationSource;
  let fixedNow: number;

  beforeEach(() => {
    fixedNow = Date.now();
    revocationSource = new MockRevocationSource();
  });

  describe('Happy Path: Synthetic Valid TEE & StrongBox Hardware Attestation', () => {
    it('successfully verifies valid synthetic TEE attestation chain and extracts EC P-256 SPKI PEM', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        attestationSecurityLevel: 1, // TEE
        keymasterSecurityLevel: 1,
        packageName: 'com.astrology.tarot',
        packageVersion: 200n
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        minimumVersion: 100n,
        revocationSource,
        now: () => fixedNow
      });

      const challengeContext = {
        challenge: Buffer.from(fixture.challenge, 'utf8')
      };

      const result = await provider.verifyRegistration(
        { challenge: fixture.challenge, certificateChain: fixture.chain },
        challengeContext
      );

      assert.ok(result.publicKeyPem.includes('-----BEGIN PUBLIC KEY-----'));
      assert.equal(result.metadata.platform, 'android');
      assert.equal(result.metadata.attestationSecurityLevel, 'TEE');
      assert.equal(result.metadata.packageName, 'com.astrology.tarot');
      assert.equal(result.metadata.packageVersion, '200');
      assert.equal(result.metadata.deviceLocked, true);
      assert.equal(result.metadata.verifiedBootState, 'VERIFIED');
    });

    it('successfully verifies valid synthetic StrongBox hardware attestation chain', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        attestationSecurityLevel: 2, // StrongBox
        keymasterSecurityLevel: 2,
        packageName: 'com.astrology.tarot',
        packageVersion: 100n
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      const result = await provider.verifyRegistration(
        { challenge: fixture.challenge, certificateChain: fixture.chain },
        { challenge: Buffer.from(fixture.challenge, 'utf8') }
      );

      assert.equal(result.metadata.attestationSecurityLevel, 'StrongBox');
      assert.equal(result.metadata.keymasterSecurityLevel, 'StrongBox');
    });

    it('successfully verifies valid request proof with ECDSA P-256 DER signature', async () => {
      const fixture = await createAttestationChain({ now: fixedNow });
      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      const device: DeviceRecord = {
        deviceId: fixture.deviceId,
        platform: 'android',
        publicKeyPem: fixture.leafPublicKeyPem,
        lastSequence: '0',
        registeredAt: fixedNow,
        metadata: {}
      };

      const canonical = Buffer.from('1729800000000:1:POST:/api/tarot/read:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      const signature = signCanonical(fixture.leafPrivateKeyPem, canonical);

      const verifyRes = await provider.verifyRequest(device, { canonical, signature });
      assert.equal(verifyRes.signCount, undefined);
    });
  });

  describe('Hardware Enforcement (SecurityLevel)', () => {
    it('rejects Software level in attestationSecurityLevel with 403 HARDWARE_TEE_REQUIRED', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        attestationSecurityLevel: 0, // Software level
        keymasterSecurityLevel: 1
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'HARDWARE_TEE_REQUIRED');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects Software level in keymasterSecurityLevel with 403 HARDWARE_TEE_REQUIRED', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        attestationSecurityLevel: 1,
        keymasterSecurityLevel: 0 // Software level
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'HARDWARE_TEE_REQUIRED');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });
  });

  describe('Challenge Verification', () => {
    it('rejects challenge mismatch between hardware attestation and server context', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        challengeHex: '1'.repeat(64)
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      // Provide mismatched server challenge context
      const wrongContext = {
        challenge: Buffer.from('2'.repeat(64), 'utf8')
      };

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          wrongContext
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'ATTESTATION_CHALLENGE_MISMATCH');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });
  });

  describe('Root of Trust & Bootloader State (Tag 704)', () => {
    it('rejects unlocked bootloader (deviceLocked = false) with 403 DEVICE_NOT_LOCKED', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        deviceLocked: false
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'DEVICE_NOT_LOCKED');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects unverified boot state (SelfSigned=1, Unverified=2, Failed=3) with 403 BOOT_NOT_VERIFIED', async () => {
      for (const badBootState of [1, 2, 3]) {
        const fixture = await createAttestationChain({
          now: fixedNow,
          verifiedBootState: badBootState
        });

        const provider = new AndroidSecurityProvider({
          trustAnchors: [fixture.rootCertPem],
          expectedPackageName: fixture.expectedPackageName,
          expectedSignerDigests: fixture.expectedSignerDigests,
          revocationSource,
          now: () => fixedNow
        });

        await assert.rejects(
          () => provider.verifyRegistration(
            { challenge: fixture.challenge, certificateChain: fixture.chain },
            { challenge: Buffer.from(fixture.challenge, 'utf8') }
          ),
          (err: unknown) => {
            assert.ok(err instanceof SecurityError);
            assert.equal(err.code, 'BOOT_NOT_VERIFIED');
            assert.equal(err.status, 403);
            return true;
          }
        );
      }
    });

    it('rejects rootOfTrust located in softwareEnforced instead of hardwareEnforced', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        rootOfTrustInSoftware: true
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MISSING_ROOT_OF_TRUST');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });
  });

  describe('Application Identity & Tag 709 Verification', () => {
    it('rejects rogue package name with 403 PACKAGE_NAME_MISMATCH', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        packageName: 'com.attacker.evilapp' // Rogue app!
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: 'com.astrology.tarot', // Expect genuine app
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'PACKAGE_NAME_MISMATCH');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects app version lower than minimumVersion with 403 PACKAGE_VERSION_TOO_LOW', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        packageVersion: 99n // Lower than required 100n
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        minimumVersion: 100n, // Enforce min version 100
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'PACKAGE_VERSION_TOO_LOW');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('accepts app version code exceeding 2^53 BigInt with exact string representation', async () => {
      // Explicit odd value beyond 2^53: 2^53 + 1 = 9007199254740993n
      const hugeVersion = 9007199254740993n;
      const fixture = await createAttestationChain({
        now: fixedNow,
        packageVersion: hugeVersion
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        minimumVersion: 1000n,
        revocationSource,
        now: () => fixedNow
      });

      const result = await provider.verifyRegistration(
        { challenge: fixture.challenge, certificateChain: fixture.chain },
        { challenge: Buffer.from(fixture.challenge, 'utf8') }
      );

      assert.equal(result.metadata.packageVersion, '9007199254740993');
    });

    it('rejects signer certificate digest mismatch with 403 SIGNER_DIGEST_MISMATCH', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        signerDigestHex: 'b'.repeat(64) // Untrusted signer digest
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: ['a'.repeat(64)], // Genuine signer digest
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'SIGNER_DIGEST_MISMATCH');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects attestation with missing Tag 709 application ID', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        omitAppId: true
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MISSING_ATTESTATION_APPLICATION_ID');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });
  });

  describe('Key Mint Cryptographic Parameters', () => {
    it('rejects leaf key that is RSA instead of EC P-256 with 403 ATTESTED_KEY_NOT_EC', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        leafKeyType: 'RSA' // Prohibited leaf algorithm
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'ATTESTED_KEY_NOT_EC');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects key without SIGN purpose with 403 HARDWARE_PURPOSE_SIGN_REQUIRED', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        purpose: [0] // ENCRYPT instead of SIGN (2)
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'HARDWARE_PURPOSE_SIGN_REQUIRED');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects key with origin IMPORTED with 403 HARDWARE_ORIGIN_GENERATED_REQUIRED', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        origin: 2 // IMPORTED (2) instead of GENERATED (0)
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'HARDWARE_ORIGIN_GENERATED_REQUIRED');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects key without SHA-256 digest with 403 HARDWARE_DIGEST_SHA256_REQUIRED', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        digest: [2] // SHA-1 (2) instead of SHA-256 (4)
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'HARDWARE_DIGEST_SHA256_REQUIRED');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });
  });

  describe('Chain Cryptography, Trust Anchors & Revocation', () => {
    it('rejects chain with untrusted Root CA (not in trustAnchors)', async () => {
      const genuineFixture = await createAttestationChain({ now: fixedNow });
      const untrustedRootFixture = await createAttestationChain({ now: fixedNow });

      // Configure provider with genuine root, but present chain signed by untrusted root
      const provider = new AndroidSecurityProvider({
        trustAnchors: [genuineFixture.rootCertPem],
        expectedPackageName: untrustedRootFixture.expectedPackageName,
        expectedSignerDigests: untrustedRootFixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: untrustedRootFixture.challenge, certificateChain: untrustedRootFixture.chain },
          { challenge: Buffer.from(untrustedRootFixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'UNTRUSTED_ROOT_CA');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects chain with broken signature (child not signed by parent)', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        corruptChainSignature: true
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          return true;
        }
      );
    });

    it('accepts expired leaf target certificate according to device-controlled Android attestation policy', async () => {
      // In Android Key Attestation upstream, leaf certificate validity is device-controlled
      // and therefore not rejected if expired; intermediates however must be strictly valid!
      const fixture = await createAttestationChain({
        now: fixedNow,
        leafExpired: true
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      const res = await provider.verifyRegistration(
        { challenge: fixture.challenge, certificateChain: fixture.chain },
        { challenge: Buffer.from(fixture.challenge, 'utf8') }
      );
      assert.ok(res.publicKeyPem.includes('-----BEGIN PUBLIC KEY-----'));
    });

    it('rejects expired non-factory intermediate certificate with 403 CERTIFICATE_EXPIRED', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        intermediateExpired: true
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'CERTIFICATE_EXPIRED');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects revoked certificate in chain', async () => {
      const fixture = await createAttestationChain({ now: fixedNow });

      // Revoke the leaf certificate serial number
      const leafSerialHex = BigInt('0x' + fixture.leaf.cert.serialNumber).toString(16);
      revocationSource.revokedSerials.add(leafSerialHex);

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'CERTIFICATE_REVOKED');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('fails closed with 503 REVOCATION_STATUS_UNAVAILABLE if revocation source fails', async () => {
      const fixture = await createAttestationChain({ now: fixedNow });
      revocationSource.shouldFail = true; // Simulated network failure

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'REVOCATION_STATUS_UNAVAILABLE');
          assert.equal(err.status, 503);
          return true;
        }
      );
    });

    it('rejects intermediate certificate lacking BasicConstraints isCA=true', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        intermediateNotCA: true
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INTERMEDIATE_NOT_CA');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('rejects leaf certificate missing attestation extension with 403 TARGET_MISSING_ATTESTATION_EXTENSION', async () => {
      const fixture = await createAttestationChain({
        now: fixedNow,
        omitAttestationExtension: true
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });

      await assert.rejects(
        () => provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: fixture.chain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'TARGET_MISSING_ATTESTATION_EXTENSION');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });
  });

  describe('Request Proof Verification (ECDSA DER)', () => {
    let fixture: Awaited<ReturnType<typeof createAttestationChain>>;
    let provider: AndroidSecurityProvider;
    let device: DeviceRecord;
    const canonical = Buffer.from('1729800000000:1:POST:/api/tarot/read:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

    beforeEach(async () => {
      fixture = await createAttestationChain({ now: fixedNow });
      provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => fixedNow
      });
      device = {
        deviceId: fixture.deviceId,
        platform: 'android',
        publicKeyPem: fixture.leafPublicKeyPem,
        lastSequence: '0',
        registeredAt: fixedNow,
        metadata: {}
      };
    });

    it('rejects non-base64 signature with 401 INVALID_BASE64_SIGNATURE', async () => {
      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, signature: 'not-valid-base64-!!!' }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_BASE64_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects signature with invalid length (< 8 or > 72 bytes) with 401 INVALID_SIGNATURE_LENGTH', async () => {
      // 7 bytes (under 8 bytes minimum for 2 DER INTEGERs)
      const shortSig = Buffer.alloc(7, 0x01).toString('base64');
      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, signature: shortSig }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE_LENGTH');
          assert.equal(err.status, 401);
          return true;
        }
      );

      // 73 bytes (over 72 bytes maximum for P-256 ECDSA DER)
      const longSig = Buffer.alloc(73, 0x01).toString('base64');
      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, signature: longSig }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE_LENGTH');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects malformed DER signature (67 bytes of invalid ASN.1) with 401 MALFORMED_DER_SIGNATURE', async () => {
      // 67 bytes is within 8..72 range, but contains invalid non-sequence ASN.1 bytes
      const malformed67Bytes = Buffer.alloc(67, 0xff).toString('base64');
      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, signature: malformed67Bytes }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MALFORMED_DER_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects tampered canonical buffer (even 1-bit alteration)', async () => {
      const signature = signCanonical(fixture.leafPrivateKeyPem, canonical);
      const tamperedCanonical = Buffer.from(canonical);
      tamperedCanonical[tamperedCanonical.length - 1] ^= 0x01; // Tamper 1 bit

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical: tamperedCanonical, signature }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });

    it('rejects signature signed by a different key with 401 INVALID_SIGNATURE', async () => {
      const otherFixture = await createAttestationChain({ now: fixedNow });
      const wrongSignature = signCanonical(otherFixture.leafPrivateKeyPem, canonical);

      await assert.rejects(
        () => provider.verifyRequest(device, { canonical, signature: wrongSignature }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_SIGNATURE');
          assert.equal(err.status, 401);
          return true;
        }
      );
    });
  });
});
