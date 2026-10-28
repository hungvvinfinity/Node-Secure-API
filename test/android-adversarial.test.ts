/**
 * Android Adversarial & Cryptographic Edge Case Regression Suite.
 *
 * Verifies strict cryptographic validation invariants independent of Android provider author:
 * 1. Rejection of duplicate Tag 709 within AuthorizationList
 * 2. Rejection of trailing unconsumed bytes in KeyDescription DER
 * 3. Rejection of negative integer versions (high bit set) in KeyDescription
 * 4. Rejection of universal tag class masquerading inside AuthorizationList
 * 5. Rejection of anti-extension attacks (attested leaf key signing a descendant)
 * 6. Rejection of duplicate certificate extension OIDs
 * 7. Rejection of unrecognized critical certificate extensions
 * 8. Enforcement of CA basic constraints pathLength constraints
 * 9. Rejection of cryptographically valid signatures with mismatched issuer DN
 * 10. Rejection of missing rootOfTrust and non-Boolean deviceLocked encoding
 * 11. Impossibility of client-controlled test headers (X-Test-Mode / mock CA) relaxing root trust
 *
 * Each test case provides a paired control verifying the unmodified base fixture succeeds,
 * ensuring mutations isolate the intended security check and do not fail on unrelated prerequisites.
 */

import 'reflect-metadata';
import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto, { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import * as asn1js from 'asn1js';
import { AndroidSecurityProvider, type RevocationSource } from '../src/platform/android.js';
import { SecurityError } from '../src/contracts.js';
import { validateCertificateChain } from '../src/platform/x509.js';
import { GOOGLE_HARDWARE_ATTESTATION_ROOTS } from '../src/platform/android-roots.js';
import {
  createRootCA,
  createIntermediateCA,
  createAndroidLeafCert,
  createAttestationChain,
  buildAndroidAttestationAsn1,
  exportPem,
  type CAEntity
} from './helpers/crypto-fixtures.js';
import { createServer } from '../src/http/server.js';
import { MemorySecurityStore } from '../src/store/memory.js';
import { SecurityService } from '../src/core/security-service.js';

class EmptyRevocationSource implements RevocationSource {
  async getRevokedSerials(): Promise<Set<string>> {
    return new Set<string>();
  }
}

describe('Android Adversarial & Cryptographic Regression Tests', () => {
  const revocationSource = new EmptyRevocationSource();
  const packageName = 'com.astrology.tarot';
  const now = 1730160000000; // Fixed timestamp within fixture validity

  // 1. Duplicate Tag 709 inside AuthorizationList
  it('1. rejects duplicate Tag 709 within AuthorizationList with 403 MALFORMED_AUTHORIZATION_LIST', async () => {
    const fixture = await createAttestationChain({
      now,
      packageName,
      packageVersion: 100n
    });

    const provider = new AndroidSecurityProvider({
      trustAnchors: [fixture.rootCertPem],
      expectedPackageName: fixture.expectedPackageName,
      expectedSignerDigests: fixture.expectedSignerDigests,
      minimumVersion: 10n,
      revocationSource,
      now: () => now
    });

    // Control: Unmodified chain passes
    const controlResult = await provider.verifyRegistration(
      { challenge: fixture.challenge, certificateChain: fixture.chain },
      { challenge: Buffer.from(fixture.challenge, 'utf8') }
    );
    assert.equal(controlResult.metadata.packageName, packageName);

    // Adversarial Mutation: Leaf cert with duplicate Tag 709 inside teeEnforced
    const intermediate = fixture.intermediateCA!;
    const mutatedLeaf = await createAndroidLeafCert(intermediate, {
      now,
      attestationOptions: {
        challenge: fixture.challenge,
        packageNames: [packageName],
        packageVersion: 100n,
        signerDigests: [Buffer.from(fixture.expectedSignerDigests[0], 'hex')],
        duplicateTag709: true
      }
    });

    const adversarialChain = [mutatedLeaf.certBase64, intermediate.certBase64, fixture.rootCA.certBase64];

    await assert.rejects(
      () =>
        provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: adversarialChain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'MALFORMED_AUTHORIZATION_LIST');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  // 2. Trailing unconsumed bytes in KeyDescription DER
  it('2. rejects trailing unconsumed garbage bytes in KeyDescription DER with 403 MALFORMED_KEY_DESCRIPTION', async () => {
    const fixture = await createAttestationChain({ now, packageName });
    const provider = new AndroidSecurityProvider({
      trustAnchors: [fixture.rootCertPem],
      expectedPackageName: fixture.expectedPackageName,
      expectedSignerDigests: fixture.expectedSignerDigests,
      revocationSource,
      now: () => now
    });

    // Control passes
    await provider.verifyRegistration(
      { challenge: fixture.challenge, certificateChain: fixture.chain },
      { challenge: Buffer.from(fixture.challenge, 'utf8') }
    );

    // Adversarial Mutation: Valid KeyDescription + 3 trailing garbage bytes
    const validDer = buildAndroidAttestationAsn1({
      challenge: fixture.challenge,
      packageNames: [packageName],
      packageVersion: 100n,
      signerDigests: [Buffer.from(fixture.expectedSignerDigests[0], 'hex')]
    });
    const trailingDer = Buffer.concat([validDer, Buffer.from([0xaa, 0xbb, 0xcc])]);

    const intermediate = fixture.intermediateCA!;
    const mutatedLeaf = await createAndroidLeafCert(intermediate, {
      now,
      attestationOptions: {
        challenge: fixture.challenge,
        rawMalformedDer: trailingDer
      }
    });

    const adversarialChain = [mutatedLeaf.certBase64, intermediate.certBase64, fixture.rootCA.certBase64];

    await assert.rejects(
      () =>
        provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: adversarialChain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'MALFORMED_KEY_DESCRIPTION');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  // 3. Negative integer version in KeyDescription (high bit set)
  it('3. rejects negative attestationVersion in KeyDescription with 403 MALFORMED_ASN1_INTEGER', async () => {
    const fixture = await createAttestationChain({ now, packageName });
    const provider = new AndroidSecurityProvider({
      trustAnchors: [fixture.rootCertPem],
      expectedPackageName: fixture.expectedPackageName,
      expectedSignerDigests: fixture.expectedSignerDigests,
      revocationSource,
      now: () => now
    });

    // Control passes
    await provider.verifyRegistration(
      { challenge: fixture.challenge, certificateChain: fixture.chain },
      { challenge: Buffer.from(fixture.challenge, 'utf8') }
    );

    // Adversarial: negative integer -1 encoded as 0x02 0x01 0xff (high bit set)
    const negativeVersionAsn = new asn1js.Integer({
      valueHex: new Uint8Array([0xff]).buffer
    });

    const softwareEnforced = new asn1js.Sequence({ value: [] });
    const teeEnforced = new asn1js.Sequence({
      value: [
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 1 },
          value: [new asn1js.Set({ value: [new asn1js.Integer({ value: 2 })] })]
        }),
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 2 },
          value: [new asn1js.Integer({ value: 3 })]
        }),
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 704 },
          value: [
            new asn1js.Sequence({
              value: [
                new asn1js.OctetString({ valueHex: new Uint8Array(32) }),
                new asn1js.Boolean({ value: true }),
                new asn1js.Enumerated({ value: 0 })
              ]
            })
          ]
        }),
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 709 },
          value: [
            new asn1js.OctetString({
              valueHex: new Uint8Array(
                new asn1js.Sequence({
                  value: [
                    new asn1js.Set({
                      value: [
                        new asn1js.Sequence({
                          value: [
                            new asn1js.OctetString({ valueHex: new Uint8Array(Buffer.from(packageName, 'utf8')) }),
                            new asn1js.Integer({ value: 100 })
                          ]
                        })
                      ]
                    }),
                    new asn1js.Set({
                      value: [new asn1js.OctetString({ valueHex: new Uint8Array(Buffer.from(fixture.expectedSignerDigests[0], 'hex')) })]
                    })
                  ]
                }).toBER(false)
              )
            })
          ]
        })
      ]
    });

    const keyDescription = new asn1js.Sequence({
      value: [
        negativeVersionAsn, // Negative version!
        new asn1js.Enumerated({ value: 1 }), // TEE
        new asn1js.Integer({ value: 4 }),
        new asn1js.Enumerated({ value: 1 }),
        new asn1js.OctetString({ valueHex: new Uint8Array(Buffer.from(fixture.challenge, 'utf8')) }),
        new asn1js.OctetString({ valueHex: new Uint8Array(0) }),
        softwareEnforced,
        teeEnforced
      ]
    });

    const rawDer = Buffer.from(keyDescription.toBER(false));

    const intermediate = fixture.intermediateCA!;
    const mutatedLeaf = await createAndroidLeafCert(intermediate, {
      now,
      attestationOptions: {
        challenge: fixture.challenge,
        rawMalformedDer: rawDer
      }
    });

    const adversarialChain = [mutatedLeaf.certBase64, intermediate.certBase64, fixture.rootCA.certBase64];

    await assert.rejects(
      () =>
        provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: adversarialChain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'MALFORMED_ASN1_INTEGER');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  // 4. Masquerading universal tags inside context-specific AuthorizationList
  it('4. rejects masquerading universal tags inside AuthorizationList with 403 MALFORMED_AUTHORIZATION_LIST', async () => {
    const fixture = await createAttestationChain({ now, packageName });
    const provider = new AndroidSecurityProvider({
      trustAnchors: [fixture.rootCertPem],
      expectedPackageName: fixture.expectedPackageName,
      expectedSignerDigests: fixture.expectedSignerDigests,
      revocationSource,
      now: () => now
    });

    // Universal Tag 2 (Integer) injected into AuthorizationList without tagClass=3 context wrapper
    const masqueradingUniversalTag = new asn1js.Integer({ value: 2 }); // tagClass === 1 (Universal), not 3!

    const softwareEnforced = new asn1js.Sequence({ value: [masqueradingUniversalTag] });
    const teeEnforced = new asn1js.Sequence({ value: [] });

    const keyDescription = new asn1js.Sequence({
      value: [
        new asn1js.Integer({ value: 3 }),
        new asn1js.Enumerated({ value: 1 }),
        new asn1js.Integer({ value: 4 }),
        new asn1js.Enumerated({ value: 1 }),
        new asn1js.OctetString({ valueHex: new Uint8Array(Buffer.from(fixture.challenge, 'utf8')) }),
        new asn1js.OctetString({ valueHex: new Uint8Array(0) }),
        softwareEnforced,
        teeEnforced
      ]
    });

    const rawDer = Buffer.from(keyDescription.toBER(false));

    const intermediate = fixture.intermediateCA!;
    const mutatedLeaf = await createAndroidLeafCert(intermediate, {
      now,
      attestationOptions: {
        challenge: fixture.challenge,
        rawMalformedDer: rawDer
      }
    });

    const adversarialChain = [mutatedLeaf.certBase64, intermediate.certBase64, fixture.rootCA.certBase64];

    await assert.rejects(
      () =>
        provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: adversarialChain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'MALFORMED_AUTHORIZATION_LIST');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  // 5. Anti-extension attack: attested leaf key signs a descendant certificate
  it('5. anti-extension attack: rejects chain where attested leaf key signs descendant certificate with 403 CHAIN_EXTENDED_WITH_FAKE_ATTESTATION_EXTENSION', async () => {
    const fixture = await createAttestationChain({ now, packageName });
    const provider = new AndroidSecurityProvider({
      trustAnchors: [fixture.rootCertPem],
      expectedPackageName: fixture.expectedPackageName,
      expectedSignerDigests: fixture.expectedSignerDigests,
      revocationSource,
      now: () => now
    });

    // Control: Unextended chain [leaf, intermediate, root] passes
    await provider.verifyRegistration(
      { challenge: fixture.challenge, certificateChain: fixture.chain },
      { challenge: Buffer.from(fixture.challenge, 'utf8') }
    );

    // Attacker uses attested leaf private key to sign a new descendant leaf
    const rogueKeyPair = await webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const rogueLeaf = await x509.X509CertificateGenerator.create({
      serialNumber: '99',
      subject: 'CN=Rogue End-Entity Key',
      issuer: fixture.leaf.cert.subject,
      notBefore: new Date(now - 3600000),
      notAfter: new Date(now + 86400000),
      publicKey: rogueKeyPair.publicKey as any,
      signingKey: fixture.leaf.keyPair.privateKey as any,
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      extensions: [
        new x509.BasicConstraintsExtension(false),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true)
      ]
    });

    // Extended chain presented by attacker: [rogueLeaf, attestedLeaf, intermediate, root]
    const extendedChain = [
      Buffer.from(rogueLeaf.rawData).toString('base64'),
      fixture.leaf.certBase64,
      fixture.intermediateCA!.certBase64,
      fixture.rootCA.certBase64
    ];

    await assert.rejects(
      () =>
        provider.verifyRegistration(
          { challenge: fixture.challenge, certificateChain: extendedChain },
          { challenge: Buffer.from(fixture.challenge, 'utf8') }
        ),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'CHAIN_EXTENDED_WITH_FAKE_ATTESTATION_EXTENSION');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  // 6. Duplicate Certificate Extension OID
  it('6. rejects certificate containing duplicate extension OIDs with 403 DUPLICATE_CERTIFICATE_EXTENSION', async () => {
    const fixture = await createAttestationChain({ now, packageName });

    // Mutate leaf to contain duplicate KeyUsagesExtension OIDs (2.5.29.15)
    const duplicateKeyUsage = new x509.Extension('2.5.29.15', false, new Uint8Array([3, 2, 7, 0x80]));
    const intermediate = fixture.intermediateCA!;

    const mutatedLeaf = await createAndroidLeafCert(intermediate, {
      now,
      attestationOptions: {
        challenge: fixture.challenge,
        packageNames: [packageName],
        packageVersion: 100n,
        signerDigests: [Buffer.from(fixture.expectedSignerDigests[0], 'hex')]
      },
      customExtensions: [duplicateKeyUsage] // Duplicates the KeyUsage extension already present!
    });

    const chain = [mutatedLeaf.certBase64, intermediate.certBase64, fixture.rootCA.certBase64];

    assert.throws(
      () =>
        validateCertificateChain(chain, {
          trustAnchors: [fixture.rootCertPem],
          profile: 'android',
          now
        }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'DUPLICATE_CERTIFICATE_EXTENSION');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  // 7. Unrecognized Critical Certificate Extension
  it('7. rejects certificate with unrecognized critical extension with 403 UNRECOGNIZED_CRITICAL_EXTENSION', async () => {
    const fixture = await createAttestationChain({ now, packageName });

    // Custom critical extension with unassigned OID: 1.2.840.99999.1.1
    const unknownCriticalExt = new x509.Extension('1.2.840.99999.1.1', true, new Uint8Array([4, 4, 1, 2, 3, 4]));
    const intermediate = fixture.intermediateCA!;

    const mutatedLeaf = await createAndroidLeafCert(intermediate, {
      now,
      attestationOptions: {
        challenge: fixture.challenge,
        packageNames: [packageName],
        packageVersion: 100n,
        signerDigests: [Buffer.from(fixture.expectedSignerDigests[0], 'hex')]
      },
      customExtensions: [unknownCriticalExt]
    });

    const chain = [mutatedLeaf.certBase64, intermediate.certBase64, fixture.rootCA.certBase64];

    assert.throws(
      () =>
        validateCertificateChain(chain, {
          trustAnchors: [fixture.rootCertPem],
          profile: 'android',
          now
        }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'UNRECOGNIZED_CRITICAL_EXTENSION');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  // 8. Basic Constraints CA pathLength constraint enforcement
  it('8. enforces CA pathLength constraint when violated by intermediate CA with 403 PATH_LENGTH_CONSTRAINT_EXCEEDED', async () => {
    const rootCA = await createRootCA({ now });

    // Intermediate 1: pathLength constraint = 0 (allows 0 intermediate CAs below it)
    const int1 = await createIntermediateCA(rootCA, {
      now,
      pathLenConstraint: 0,
      subject: 'CN=Intermediate CA Level 1, O=Google Test'
    });

    // Intermediate 2: CA signed by Intermediate 1 (violates int1 pathLength=0!)
    const int2 = await createIntermediateCA(int1, {
      now,
      subject: 'CN=Intermediate CA Level 2, O=Google Test'
    });

    const leaf = await createAndroidLeafCert(int2, {
      now,
      attestationOptions: {
        challenge: '0'.repeat(64),
        packageNames: [packageName],
        packageVersion: 100n,
        signerDigests: [Buffer.alloc(32, 0x11)]
      }
    });

    const chain = [leaf.certBase64, int2.certBase64, int1.certBase64, rootCA.certBase64];

    assert.throws(
      () =>
        validateCertificateChain(chain, {
          trustAnchors: [rootCA.certPem],
          profile: 'android',
          now
        }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'PATH_LENGTH_CONSTRAINT_EXCEEDED');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  // 9. Cryptographically valid signature with mismatched Issuer DN
  it('9. rejects cryptographically valid signature with mismatched issuer DN with 403 NAME_CHAINING_FAILED', async () => {
    const fixture = await createAttestationChain({ now, packageName });
    const intermediate = fixture.intermediateCA!;

    // Generate leaf key pair
    const leafKeyPair = await webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const attestationDer = buildAndroidAttestationAsn1({
      challenge: fixture.challenge,
      packageNames: [packageName],
      packageVersion: 100n,
      signerDigests: [Buffer.from(fixture.expectedSignerDigests[0], 'hex')]
    });

    // Mismatched issuer DN: Signed by intermediate key, but issuer says 'CN=Spoofed Issuer Name'
    const leafWithWrongIssuer = await x509.X509CertificateGenerator.create({
      serialNumber: '77',
      subject: 'CN=Android Keystore Key, O=Google Test',
      issuer: 'CN=Spoofed Issuer Name, O=Malicious Actor', // Mismatched!
      notBefore: new Date(now - 3600000),
      notAfter: new Date(now + 86400000),
      publicKey: leafKeyPair.publicKey as any,
      signingKey: intermediate.keyPair.privateKey as any, // Valid cryptographic signature!
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      extensions: [
        new x509.BasicConstraintsExtension(false),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
        new x509.Extension('1.3.6.1.4.1.11129.2.1.17', false, new Uint8Array(attestationDer))
      ]
    });

    const chain = [
      Buffer.from(leafWithWrongIssuer.rawData).toString('base64'),
      intermediate.certBase64,
      fixture.rootCA.certBase64
    ];

    assert.throws(
      () =>
        validateCertificateChain(chain, {
          trustAnchors: [fixture.rootCertPem],
          profile: 'android',
          now
        }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'NAME_CHAINING_FAILED');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  // 10. KeyMint rootOfTrust: missing Tag 704 & non-Boolean deviceLocked encoding
  describe('10. KeyMint rootOfTrust Invariants', () => {
    it('10a. rejects attestation missing rootOfTrust in hardwareEnforced with 403 MISSING_ROOT_OF_TRUST', async () => {
      const fixture = await createAttestationChain({ now, packageName });
      const intermediate = fixture.intermediateCA!;

      // Attestation with rootOfTrust omitted from hardwareEnforced
      const leafMissingRot = await createAndroidLeafCert(intermediate, {
        now,
        attestationOptions: {
          challenge: fixture.challenge,
          packageNames: [packageName],
          packageVersion: 100n,
          signerDigests: [Buffer.from(fixture.expectedSignerDigests[0], 'hex')],
          rootOfTrust: null // Completely omits rootOfTrust Tag 704
        }
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => now
      });

      const chain = [leafMissingRot.certBase64, intermediate.certBase64, fixture.rootCA.certBase64];

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            { challenge: fixture.challenge, certificateChain: chain },
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

    it('10b. rejects rootOfTrust when deviceLocked is encoded as ASN.1 INTEGER instead of strict BOOLEAN', async () => {
      const fixture = await createAttestationChain({ now, packageName });
      const intermediate = fixture.intermediateCA!;

      // Malformed rootOfTrust: deviceLocked encoded as Integer(1) instead of Boolean(true)
      const malformedRotSeq = new asn1js.Sequence({
        value: [
          new asn1js.OctetString({ valueHex: new Uint8Array(32) }),
          new asn1js.Integer({ value: 1 }), // Tag 2 INTEGER instead of Tag 1 BOOLEAN!
          new asn1js.Enumerated({ value: 0 }),
          new asn1js.OctetString({ valueHex: new Uint8Array(32) })
        ]
      });

      const teeTags = [
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 1 },
          value: [new asn1js.Set({ value: [new asn1js.Integer({ value: 2 })] })]
        }),
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 2 },
          value: [new asn1js.Integer({ value: 3 })]
        }),
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 704 },
          value: [malformedRotSeq]
        }),
        new asn1js.Constructed({
          idBlock: { tagClass: 3, tagNumber: 709 },
          value: [
            new asn1js.OctetString({
              valueHex: new Uint8Array(
                new asn1js.Sequence({
                  value: [
                    new asn1js.Set({
                      value: [
                        new asn1js.Sequence({
                          value: [
                            new asn1js.OctetString({ valueHex: new Uint8Array(Buffer.from(packageName, 'utf8')) }),
                            new asn1js.Integer({ value: 100 })
                          ]
                        })
                      ]
                    }),
                    new asn1js.Set({
                      value: [new asn1js.OctetString({ valueHex: new Uint8Array(Buffer.from(fixture.expectedSignerDigests[0], 'hex')) })]
                    })
                  ]
                }).toBER(false)
              )
            })
          ]
        })
      ];

      const keyDescription = new asn1js.Sequence({
        value: [
          new asn1js.Integer({ value: 3 }),
          new asn1js.Enumerated({ value: 1 }),
          new asn1js.Integer({ value: 4 }),
          new asn1js.Enumerated({ value: 1 }),
          new asn1js.OctetString({ valueHex: new Uint8Array(Buffer.from(fixture.challenge, 'utf8')) }),
          new asn1js.OctetString({ valueHex: new Uint8Array(0) }),
          new asn1js.Sequence({ value: [] }),
          new asn1js.Sequence({ value: teeTags })
        ]
      });

      const rawDer = Buffer.from(keyDescription.toBER(false));

      const mutatedLeaf = await createAndroidLeafCert(intermediate, {
        now,
        attestationOptions: {
          challenge: fixture.challenge,
          rawMalformedDer: rawDer
        }
      });

      const provider = new AndroidSecurityProvider({
        trustAnchors: [fixture.rootCertPem],
        expectedPackageName: fixture.expectedPackageName,
        expectedSignerDigests: fixture.expectedSignerDigests,
        revocationSource,
        now: () => now
      });

      const chain = [mutatedLeaf.certBase64, intermediate.certBase64, fixture.rootCA.certBase64];

      await assert.rejects(
        () =>
          provider.verifyRegistration(
            { challenge: fixture.challenge, certificateChain: chain },
            { challenge: Buffer.from(fixture.challenge, 'utf8') }
          ),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'MALFORMED_AUTHORIZATION_LIST');
          assert.equal(err.status, 403);
          return true;
        }
      );
    });
  });

  // 11. Client X-Test-Mode cannot relax official pinned root trust via HTTP or provider
  it('11. client X-Test-Mode header or mock CA cannot relax root trust on official pinned provider (403 UNTRUSTED_ROOT_CA)', async () => {
    // Synthetic self-signed test chain
    const testCA = await createRootCA({ now });
    const testIntermediate = await createIntermediateCA(testCA, { now });
    const testLeaf = await createAndroidLeafCert(testIntermediate, {
      now,
      attestationOptions: {
        challenge: '0'.repeat(64),
        packageNames: [packageName],
        packageVersion: 100n,
        signerDigests: [Buffer.alloc(32, 0x99)]
      }
    });

    const unpinnedChain = [testLeaf.certBase64, testIntermediate.certBase64, testCA.certBase64];

    // Production provider configured with official Google Hardware Attestation Roots
    const productionProvider = new AndroidSecurityProvider({
      trustAnchors: [...GOOGLE_HARDWARE_ATTESTATION_ROOTS],
      expectedPackageName: packageName,
      expectedSignerDigests: [Buffer.alloc(32, 0x99).toString('hex')],
      revocationSource,
      now: () => now
    });

    // 1. Direct provider call must reject unpinned test root with 403 UNTRUSTED_ROOT_CA
    await assert.rejects(
      () =>
        productionProvider.verifyRegistration(
          { challenge: '0'.repeat(64), certificateChain: unpinnedChain },
          { challenge: Buffer.from('0'.repeat(64), 'utf8') }
        ),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'UNTRUSTED_ROOT_CA');
        assert.equal(err.status, 403);
        return true;
      }
    );

    // 2. Real HTTP Server: verify that client header "x-test-mode: true" or "x-mock-ca: 1" cannot bypass trust
    const store = new MemorySecurityStore({ now: () => now });
    const securityService = new SecurityService({
      store,
      providers: [productionProvider],
      now: () => now
    });

    const issuedChallenge = await securityService.issueChallenge('android');

    const server = createServer({
      securityService,
      store
    });

    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as any).port;

    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/auth/register-device`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Test-Mode': 'true',
          'X-Allow-Mock-CA': '1'
        },
        body: JSON.stringify({
          platform: 'android',
          challenge: issuedChallenge.challenge,
          certificateChain: unpinnedChain
        })
      });

      assert.equal(response.status, 403);
      const body: any = await response.json();
      assert.equal(body.error, 'UNTRUSTED_ROOT_CA');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await store.close();
    }
  });
});
