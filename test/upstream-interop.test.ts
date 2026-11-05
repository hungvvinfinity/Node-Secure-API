import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { AndroidSecurityProvider } from '../src/platform/android.js';
import {
  GOOGLE_HARDWARE_ATTESTATION_ROOTS,
  GOOGLE_ROOT_RSA_PEM,
  GOOGLE_ROOT_EC_PEM
} from '../src/platform/android-roots.js';
import {
  parseRevocationStatusJson,
  parseRootsJson,
  GoogleRevocationSource
} from '../src/platform/trust.js';
import {
  validateCertificateChain,
  parseProvisioningInfo,
  MAX_CERTIFICATES_ISSUED,
  ANDROID_PROVISIONING_INFO_OID
} from '../src/platform/x509.js';
import { X509Certificate as PeculiarX509Certificate } from '@peculiar/x509';
import { encode } from 'cbor-x';
import { SecurityError } from '../src/contracts.js';

function parsePemChain(pemText: string): string[] {
  const matches = pemText.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!matches || matches.length === 0) {
    throw new Error('No certificates found in PEM text');
  }
  return matches.map((cert) => {
    const clean = cert
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s+/g, '');
    return clean;
  });
}

describe('Upstream Interoperability & Real Hardware Attestation Tests', () => {
  // Empty isolated snapshot for historical chain tests (explicitly labeled: not live-device/current-CRL proof)
  const emptyRevocationSource = {
    async getRevokedSerials(): Promise<Set<string>> {
      return new Set<string>();
    }
  };

  describe('Caiman (Pixel 9 Pro SDK 36 TEE EC RKP)', () => {
    const caimanPemPath = path.join(
      process.cwd(),
      'test/fixtures/upstream/caiman/sdk36/TEE_EC_RKP.pem'
    );
    const caimanJsonPath = path.join(
      process.cwd(),
      'test/fixtures/upstream/caiman/sdk36/TEE_EC_RKP.json'
    );

    const caimanPem = fs.readFileSync(caimanPemPath, 'utf8');
    const caimanJson = JSON.parse(fs.readFileSync(caimanJsonPath, 'utf8'));
    const caimanChain = parsePemChain(caimanPem);

    // Historical timestamp from caiman attestation: 2025-09-26T17:01:20.964Z
    const caimanValidNow = 1758900680964;

    it('offline interoperability smoke: verifies caiman chain with official Google RSA Root CA at historical time 2025-09-26', async () => {
      // Expected challenge from JSON: base64 'ZDY4OGQ3NjMtNjExOC00Y2E2LTk0YjItZTZjZDllZDdlNGU0'
      const expectedChallenge = Buffer.from(caimanJson.attestationChallenge, 'base64');
      const expectedPackage = caimanJson.softwareEnforced.attestationApplicationId.packages[0].name;

      // SHA-256 digest of signing cert from JSON base64
      const expectedSignerDigest = Buffer.from(
        caimanJson.softwareEnforced.attestationApplicationId.signatures[0],
        'base64'
      ).toString('hex');

      const provider = new AndroidSecurityProvider({
        trustAnchors: [...GOOGLE_HARDWARE_ATTESTATION_ROOTS],
        expectedPackageName: expectedPackage,
        expectedSignerDigests: [expectedSignerDigest],
        minimumVersion: 0n,
        revocationSource: emptyRevocationSource,
        now: () => caimanValidNow
      });

      const result = await provider.verifyRegistration(
        {
          challenge: expectedChallenge.toString('utf8'),
          certificateChain: caimanChain
        },
        { challenge: expectedChallenge }
      );

      assert.ok(result.publicKeyPem.includes('-----BEGIN PUBLIC KEY-----'));
      assert.equal(result.metadata.platform, 'android');
      assert.equal(result.metadata.attestationSecurityLevel, 'TEE');
      assert.equal(result.metadata.packageName, 'com.google.android.attestation');
      assert.equal(result.metadata.deviceLocked, true);
      assert.equal(result.metadata.verifiedBootState, 'VERIFIED');
      assert.equal(result.metadata.provisioningMethod, 'REMOTELY_PROVISIONED');
      assert.equal(result.metadata.certificatesIssued, 64);
    });

    it('rejects expired RKP intermediate at current time (2026-10-28) with 403 CERTIFICATE_EXPIRED', async () => {
      const expectedChallenge = Buffer.from(caimanJson.attestationChallenge, 'base64');
      const expectedPackage = caimanJson.softwareEnforced.attestationApplicationId.packages[0].name;
      const expectedSignerDigest = Buffer.from(
        caimanJson.softwareEnforced.attestationApplicationId.signatures[0],
        'base64'
      ).toString('hex');

      // Validating at current time Date.now() where RKP intermediate is expired (> Oct 2025)
      const provider = new AndroidSecurityProvider({
        trustAnchors: [...GOOGLE_HARDWARE_ATTESTATION_ROOTS],
        expectedPackageName: expectedPackage,
        expectedSignerDigests: [expectedSignerDigest],
        revocationSource: emptyRevocationSource,
        now: () => Date.now()
      });

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: expectedChallenge.toString('utf8'),
              certificateChain: caimanChain
            },
            { challenge: expectedChallenge }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'CERTIFICATE_EXPIRED');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });
  });

  describe('Tegu (Pixel 9a SDK 36 TEE EC 2026 Root)', () => {
    const teguPemPath = path.join(
      process.cwd(),
      'test/fixtures/upstream/tegu/sdk36/TEE_EC_2026_ROOT.pem'
    );
    const teguJsonPath = path.join(
      process.cwd(),
      'test/fixtures/upstream/tegu/sdk36/TEE_EC_2026_ROOT.json'
    );

    const teguPem = fs.readFileSync(teguPemPath, 'utf8');
    // Strip comments if any in tegu JSON
    const rawTeguJson = fs.readFileSync(teguJsonPath, 'utf8').replace(/\/\/.*$/gm, '');
    const teguJson = JSON.parse(rawTeguJson);
    const teguChain = parsePemChain(teguPem);

    // Historical timestamp from tegu attestation: 2026-02-25T00:56:03.060Z
    const teguValidNow = 1771894563060;

    it('offline interoperability smoke: verifies tegu chain with new official 2026 Google EC Root CA at historical time 2026-02-25', async () => {
      const expectedChallenge = Buffer.from(teguJson.attestationChallenge, 'base64');
      const expectedPackage = teguJson.softwareEnforced.attestationApplicationId.packages[0].name;
      const expectedSignerDigest = Buffer.from(
        teguJson.softwareEnforced.attestationApplicationId.signatures[0],
        'base64'
      ).toString('hex');

      const provider = new AndroidSecurityProvider({
        trustAnchors: [GOOGLE_ROOT_EC_PEM],
        expectedPackageName: expectedPackage,
        expectedSignerDigests: [expectedSignerDigest],
        minimumVersion: 0n,
        revocationSource: emptyRevocationSource,
        now: () => teguValidNow
      });

      const result = await provider.verifyRegistration(
        {
          challenge: expectedChallenge.toString('utf8'),
          certificateChain: teguChain
        },
        { challenge: expectedChallenge }
      );

      assert.ok(result.publicKeyPem.includes('-----BEGIN PUBLIC KEY-----'));
      assert.equal(result.metadata.platform, 'android');
      assert.equal(result.metadata.attestationSecurityLevel, 'TEE');
      assert.equal(result.metadata.packageName, 'com.google.android.attestation');
      assert.equal(result.metadata.deviceLocked, true);
      assert.equal(result.metadata.verifiedBootState, 'VERIFIED');
      assert.equal(result.metadata.provisioningMethod, 'REMOTELY_PROVISIONED');
      assert.equal(result.metadata.certificatesIssued, 64);
    });
  });

  describe('Blueline (Pixel 3 SDK 28 Factory-Provisioned 4-Certificate Chain)', () => {
    const bluelinePemPath = path.join(
      process.cwd(),
      'test/fixtures/upstream/blueline/sdk28/TEE_EC_NONE.pem'
    );
    const bluelinePem = fs.readFileSync(bluelinePemPath, 'utf8');
    const bluelineChain = parsePemChain(bluelinePem);

    // blueline intermediates expire on 2028-07-20T20:33:28Z.
    // At future date 2029-01-01T00:00:00Z, the intermediates are strictly expired.
    const futureExpiredIntermediateDate = new Date('2029-01-01T00:00:00Z').getTime();

    it('proves 4-certificate factory chain with expired intermediate remains VALID under Android attestation policy', () => {
      assert.equal(bluelineChain.length, 4);

      // Validate chain with Android profile (which recognizes FACTORY_PROVISIONED via serialNumber in subject DN)
      const result = validateCertificateChain(bluelineChain, {
        trustAnchors: [...GOOGLE_HARDWARE_ATTESTATION_ROOTS],
        profile: 'android',
        now: futureExpiredIntermediateDate,
        revokedSerials: new Set<string>()
      });

      assert.ok(result.leafPublicKeyPem.includes('-----BEGIN PUBLIC KEY-----'));
      assert.equal(result.chain.length, 4);
    });

    it('proves the same expired factory intermediate is REJECTED under strict PKIX profile with 403 CERTIFICATE_EXPIRED', () => {
      assert.throws(
        () =>
          validateCertificateChain(bluelineChain, {
            trustAnchors: [...GOOGLE_HARDWARE_ATTESTATION_ROOTS],
            profile: 'strict',
            now: futureExpiredIntermediateDate,
            revokedSerials: new Set<string>()
          }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'CERTIFICATE_EXPIRED');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('proves revoked factory intermediate is strictly REJECTED even with factory exemption (403 CERTIFICATE_REVOKED)', () => {
      // Serial 0388266760658996859e normalized without leading zeros is 388266760658996859e
      const revokedSerial = '388266760658996859e';
      assert.throws(
        () =>
          validateCertificateChain(bluelineChain, {
            trustAnchors: [...GOOGLE_HARDWARE_ATTESTATION_ROOTS],
            profile: 'android',
            now: futureExpiredIntermediateDate,
            revokedSerials: new Set<string>([revokedSerial])
          }),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'CERTIFICATE_REVOKED');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });

    it('proves full AndroidSecurityProvider enforces HARDWARE_DIGEST_SHA256_REQUIRED on blueline DIGEST_NONE key without relaxing policy', async () => {
      const bluelineJsonPath = path.join(
        process.cwd(),
        'test/fixtures/upstream/blueline/sdk28/TEE_EC_NONE.json'
      );
      const bluelineJson = JSON.parse(fs.readFileSync(bluelineJsonPath, 'utf8'));
      const expectedChallenge = Buffer.from(bluelineJson.attestationChallenge, 'base64');
      const expectedPackage = bluelineJson.softwareEnforced.attestationApplicationId.packages[0].name;
      const expectedSignerDigest = Buffer.from(
        bluelineJson.softwareEnforced.attestationApplicationId.signatures[0],
        'base64'
      ).toString('hex');

      const provider = new AndroidSecurityProvider({
        trustAnchors: [...GOOGLE_HARDWARE_ATTESTATION_ROOTS],
        expectedPackageName: expectedPackage,
        expectedSignerDigests: [expectedSignerDigest],
        revocationSource: emptyRevocationSource,
        now: () => futureExpiredIntermediateDate
      });

      // Chain passes certificate validation, but hardwareEnforced digest list lacks SHA-256
      await assert.rejects(
        () =>
          provider.verifyRegistration(
            {
              challenge: expectedChallenge.toString('utf8'),
              certificateChain: bluelineChain
            },
            { challenge: expectedChallenge }
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

  describe('Trust & Revocation Helper Integrity (src/platform/trust.ts)', () => {
    it('parses valid revocation JSON with both REVOKED and SUSPENDED entries into lowercase hex serials', () => {
      const sampleJson = JSON.stringify({
        entries: {
          '0x1a2b': { status: 'REVOKED', reason: 'KEY_COMPROMISE' },
          '3c4d': { status: 'SUSPENDED', comment: 'Temporary hold' }
        }
      });

      const serials = parseRevocationStatusJson(sampleJson);
      assert.equal(serials.size, 2);
      assert.ok(serials.has('1a2b'));
      assert.ok(serials.has('3c4d'));
    });

    it('fails closed on malformed JSON or unknown status in revocation response', () => {
      assert.throws(
        () => parseRevocationStatusJson('not-json'),
        /MALFORMED_REVOCATION_STATUS/
      );

      assert.throws(
        () =>
          parseRevocationStatusJson(
            JSON.stringify({
              entries: {
                '1a': { status: 'UNKNOWN_STATUS_FLAG' }
              }
            })
          ),
        /MALFORMED_REVOCATION_STATUS/
      );
    });

    it('parses valid roots JSON array and rejects invalid certificate text', () => {
      const validRoots = JSON.stringify([GOOGLE_ROOT_RSA_PEM, GOOGLE_ROOT_EC_PEM]);
      const parsed = parseRootsJson(validRoots);
      assert.equal(parsed.length, 2);

      assert.throws(
        () => parseRootsJson(JSON.stringify(['not-a-certificate'])),
        /MALFORMED_ROOTS_RESPONSE/
      );
    });

    it('GoogleRevocationSource caches snapshot and fails closed when empty and unreachable', async () => {
      let callCount = 0;
      const mockFetch: typeof fetch = async () => {
        callCount++;
        return new Response(
          JSON.stringify({
            entries: {
              '10': { status: 'REVOKED' }
            }
          }),
          { status: 200, headers: { 'cache-control': 'public, max-age=60' } }
        );
      };

      let mockNow = 1000000;
      const source = new GoogleRevocationSource({
        fetchFn: mockFetch,
        now: () => mockNow
      });

      // 1. Initial fetch
      const serials1 = await source.getRevokedSerials();
      assert.equal(callCount, 1);
      assert.ok(serials1.has('10'));

      // 2. Second fetch within 60s TTL uses cache (no new HTTP call)
      mockNow += 30000;
      const serials2 = await source.getRevokedSerials();
      assert.equal(callCount, 1);
      assert.equal(serials2.size, 1);

      // 3. When stale and fetch fails, fails closed with REVOCATION_STATUS_UNAVAILABLE
      mockNow += 60000; // Cache expired
      const failingSource = new GoogleRevocationSource({
        fetchFn: async () => {
          throw new Error('Network error');
        },
        now: () => mockNow
      });

      await assert.rejects(
        () => failingSource.getRevokedSerials(),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'REVOCATION_STATUS_UNAVAILABLE');
          assert.equal(err.status, 503);
          return true;
        }
      );
    });
  });

  describe('Provisioning Info & certificatesIssued Bounds Regressions (commit 0e3ac2f)', () => {
    it('parses real Caiman RKP certificate provisioning info with certificatesIssued = 64', () => {
      const caimanPemPath = path.join(
        process.cwd(),
        'test/fixtures/upstream/caiman/sdk36/TEE_EC_RKP.pem'
      );
      const caimanPem = fs.readFileSync(caimanPemPath, 'utf8');
      const matches = caimanPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
      const match1 = matches[1];
      assert.ok(match1 !== undefined);
      const peculiarIntermediate = new PeculiarX509Certificate(match1);

      const info = parseProvisioningInfo(peculiarIntermediate);
      assert.ok(info !== null);
      assert.equal(info.certificatesIssued, 64);
    });

    it('returns null if certificate does not contain Provisioning Info extension', () => {
      const caimanPemPath = path.join(
        process.cwd(),
        'test/fixtures/upstream/caiman/sdk36/TEE_EC_RKP.pem'
      );
      const caimanPem = fs.readFileSync(caimanPemPath, 'utf8');
      const matches = caimanPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
      const match0 = matches[0];
      assert.ok(match0 !== undefined);
      // Leaf cert (match0) does not have Provisioning Info
      const peculiarLeaf = new PeculiarX509Certificate(match0);

      const info = parseProvisioningInfo(peculiarLeaf);
      assert.equal(info, null);
    });

    it('clamps negative certificatesIssued to 0 (upstream negative_certificates_issued)', () => {
      // Mock Peculiar cert with raw CBOR payload: { 1: -2147483649 }
      // Corresponds to hex: a1013a80000000
      const cborBytes = Buffer.from('a1013a80000000', 'hex');
      const fakeCert = {
        extensions: [
          {
            type: ANDROID_PROVISIONING_INFO_OID,
            value: new Uint8Array(cborBytes).buffer
          }
        ]
      } as unknown as PeculiarX509Certificate;

      const info = parseProvisioningInfo(fakeCert);
      assert.ok(info !== null);
      assert.equal(info.certificatesIssued, 0);
    });

    it('clamps negative -1 to 0', () => {
      const cborBytes = encode({ 1: -1 });
      const fakeCert = {
        extensions: [
          {
            type: ANDROID_PROVISIONING_INFO_OID,
            value: new Uint8Array(cborBytes).buffer
          }
        ]
      } as unknown as PeculiarX509Certificate;

      const info = parseProvisioningInfo(fakeCert);
      assert.ok(info !== null);
      assert.equal(info.certificatesIssued, 0);
    });

    it('clamps out-of-bounds certificatesIssued to MAX_CERTIFICATES_ISSUED (upstream out_of_bounds_certificates_issued)', () => {
      // Mock Peculiar cert with raw CBOR payload: { 1: 2147483648 } (Int.MAX_VALUE + 1)
      // Corresponds to hex: a1011a80000000
      const cborBytes = Buffer.from('a1011a80000000', 'hex');
      const fakeCert = {
        extensions: [
          {
            type: ANDROID_PROVISIONING_INFO_OID,
            value: new Uint8Array(cborBytes).buffer
          }
        ]
      } as unknown as PeculiarX509Certificate;

      const info = parseProvisioningInfo(fakeCert);
      assert.ok(info !== null);
      assert.equal(info.certificatesIssued, MAX_CERTIFICATES_ISSUED);
      assert.equal(info.certificatesIssued, 2147483647);
    });

    it('preserves exact Int.MAX_VALUE (2147483647)', () => {
      const cborBytes = encode({ 1: MAX_CERTIFICATES_ISSUED });
      const fakeCert = {
        extensions: [
          {
            type: ANDROID_PROVISIONING_INFO_OID,
            value: new Uint8Array(cborBytes).buffer
          }
        ]
      } as unknown as PeculiarX509Certificate;

      const info = parseProvisioningInfo(fakeCert);
      assert.ok(info !== null);
      assert.equal(info.certificatesIssued, 2147483647);
    });

    it('handles unsigned BigInt exceeding 64-bit integer safely by clamping', () => {
      const cborBytes = encode({ 1: 18446744073709551615n });
      const fakeCert = {
        extensions: [
          {
            type: ANDROID_PROVISIONING_INFO_OID,
            value: new Uint8Array(cborBytes).buffer
          }
        ]
      } as unknown as PeculiarX509Certificate;

      const info = parseProvisioningInfo(fakeCert);
      assert.ok(info !== null);
      assert.equal(info.certificatesIssued, MAX_CERTIFICATES_ISSUED);
    });
  });
});
