import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { AppleReceiptVerifier } from '../src/platform/ios-receipt.js';
import { SecurityError } from '../src/contracts.js';
import {
  createReceiptCA,
  createReceiptSigner,
  createCmsReceipt
} from './helpers/ios-fixtures.js';

describe('AppleReceiptVerifier (CMS Fraud Receipt Cryptography & Policy Invariants)', () => {
  const appId = 'TEAMID123.com.astrology.tarot';
  const now = 1729800000000;

  it('successfully verifies valid CMS receipt signed by authorized receipt signer profile', async () => {
    const rootCA = await createReceiptCA({ now });
    const signer = await createReceiptSigner(rootCA, { now });

    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPem = ecKey.publicKey.export({ format: 'pem', type: 'spki' }) as string;

    const receipt = await createCmsReceipt({
      rootCA,
      signerCert: signer,
      appId,
      publicKeyPem: pubPem,
      now
    });

    const verifier = new AppleReceiptVerifier({
      trustAnchors: [rootCA.certPem],
      now: () => now
    });

    const result = await verifier.verify(receipt, {
      appId,
      publicKeyPem: pubPem
    });

    assert.equal(typeof result.receipt, 'string');
    assert.equal(typeof result.receiptCreatedAt, 'number');
    assert.ok(Math.abs(result.receiptCreatedAt - now) < 5000);
  });

  it('rejects arbitrary Apple-signed certificate lacking mandatory marker 1.2.840.113635.100.12.15', async () => {
    const rootCA = await createReceiptCA({ now });
    // Signer cert created WITHOUT the dedicated fraud receipt marker extension
    const arbitrarySigner = await createReceiptSigner(rootCA, {
      now,
      omitMarker: true
    });

    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPem = ecKey.publicKey.export({ format: 'pem', type: 'spki' }) as string;

    const receipt = await createCmsReceipt({
      rootCA,
      signerCert: arbitrarySigner,
      appId,
      publicKeyPem: pubPem,
      now
    });

    const verifier = new AppleReceiptVerifier({
      trustAnchors: [rootCA.certPem],
      now: () => now
    });

    await assert.rejects(
      () => verifier.verify(receipt, { appId, publicKeyPem: pubPem }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INVALID_RECEIPT_SIGNER_PROFILE');
        return true;
      }
    );
  });

  it('rejects marker 1.2.840.113635.100.12.15 with non-NULL ASN.1 value', async () => {
    const rootCA = await createReceiptCA({ now });
    // Marker value is not DER NULL (05 00)
    const badMarkerSigner = await createReceiptSigner(rootCA, {
      now,
      markerValueHex: '0101ff' // Boolean true instead of NULL
    });

    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPem = ecKey.publicKey.export({ format: 'pem', type: 'spki' }) as string;

    const receipt = await createCmsReceipt({
      rootCA,
      signerCert: badMarkerSigner,
      appId,
      publicKeyPem: pubPem,
      now
    });

    const verifier = new AppleReceiptVerifier({
      trustAnchors: [rootCA.certPem],
      now: () => now
    });

    await assert.rejects(
      () => verifier.verify(receipt, { appId, publicKeyPem: pubPem }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INVALID_RECEIPT_SIGNER_PROFILE');
        return true;
      }
    );
  });

  it('rejects receipt signer certificate where CA constraint is true', async () => {
    const rootCA = await createReceiptCA({ now });
    // Signer cert has basicConstraints isCA=true
    const caSigner = await createReceiptSigner(rootCA, {
      now,
      isCA: true
    });

    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPem = ecKey.publicKey.export({ format: 'pem', type: 'spki' }) as string;

    const receipt = await createCmsReceipt({
      rootCA,
      signerCert: caSigner,
      appId,
      publicKeyPem: pubPem,
      now
    });

    const verifier = new AppleReceiptVerifier({
      trustAnchors: [rootCA.certPem],
      now: () => now
    });

    await assert.rejects(
      () => verifier.verify(receipt, { appId, publicKeyPem: pubPem }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INVALID_RECEIPT_SIGNER_PROFILE');
        return true;
      }
    );
  });

  it('rejects receipt signed by untrusted Root CA', async () => {
    const rootCA1 = await createReceiptCA({ now });
    const signer1 = await createReceiptSigner(rootCA1, { now });

    const rootCA2 = await createReceiptCA({ now }); // Different root

    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPem = ecKey.publicKey.export({ format: 'pem', type: 'spki' }) as string;

    const receipt = await createCmsReceipt({
      rootCA: rootCA1,
      signerCert: signer1,
      appId,
      publicKeyPem: pubPem,
      now
    });

    const verifier = new AppleReceiptVerifier({
      trustAnchors: [rootCA2.certPem], // Anchor is rootCA2
      now: () => now
    });

    await assert.rejects(
      () => verifier.verify(receipt, { appId, publicKeyPem: pubPem }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INVALID_APP_ATTEST_RECEIPT');
        return true;
      }
    );
  });

  it('rejects receipt with corrupted CMS cryptographic signature', async () => {
    const rootCA = await createReceiptCA({ now });
    const signer = await createReceiptSigner(rootCA, { now });

    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPem = ecKey.publicKey.export({ format: 'pem', type: 'spki' }) as string;

    const receipt = await createCmsReceipt({
      rootCA,
      signerCert: signer,
      appId,
      publicKeyPem: pubPem,
      now,
      corruptSignature: true
    });

    const verifier = new AppleReceiptVerifier({
      trustAnchors: [rootCA.certPem],
      now: () => now
    });

    await assert.rejects(
      () => verifier.verify(receipt, { appId, publicKeyPem: pubPem }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INVALID_APP_ATTEST_RECEIPT');
        return true;
      }
    );
  });

  it('rejects receipt with mismatched appId in attribute 2 with RECEIPT_APP_ID_MISMATCH', async () => {
    const rootCA = await createReceiptCA({ now });
    const signer = await createReceiptSigner(rootCA, { now });

    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPem = ecKey.publicKey.export({ format: 'pem', type: 'spki' }) as string;

    const receipt = await createCmsReceipt({
      rootCA,
      signerCert: signer,
      appId: 'ROGUE.com.attacker',
      publicKeyPem: pubPem,
      now
    });

    const verifier = new AppleReceiptVerifier({
      trustAnchors: [rootCA.certPem],
      now: () => now
    });

    await assert.rejects(
      () => verifier.verify(receipt, { appId, publicKeyPem: pubPem }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'RECEIPT_APP_ID_MISMATCH');
        return true;
      }
    );
  });

  it('rejects receipt with mismatched public key in attribute 3 with RECEIPT_KEY_MISMATCH', async () => {
    const rootCA = await createReceiptCA({ now });
    const signer = await createReceiptSigner(rootCA, { now });

    const ecKeyA = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPemA = ecKeyA.publicKey.export({ format: 'pem', type: 'spki' }) as string;

    const ecKeyB = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPemB = ecKeyB.publicKey.export({ format: 'pem', type: 'spki' }) as string;

    // Receipt signs pubKeyA, but context has pubKeyB
    const receipt = await createCmsReceipt({
      rootCA,
      signerCert: signer,
      appId,
      publicKeyPem: pubPemA,
      now
    });

    const verifier = new AppleReceiptVerifier({
      trustAnchors: [rootCA.certPem],
      now: () => now
    });

    await assert.rejects(
      () => verifier.verify(receipt, { appId, publicKeyPem: pubPemB }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'RECEIPT_KEY_MISMATCH');
        return true;
      }
    );
  });

  it('rejects receipt where attribute 12 created timestamp is older than 5 minutes with RECEIPT_EXPIRED', async () => {
    const rootCA = await createReceiptCA({ now });
    const signer = await createReceiptSigner(rootCA, { now });

    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPem = ecKey.publicKey.export({ format: 'pem', type: 'spki' }) as string;

    // Created 6 minutes ago (> 300,000ms)
    const oldCreated = new Date(now - 360000).toISOString();

    const receipt = await createCmsReceipt({
      rootCA,
      signerCert: signer,
      appId,
      publicKeyPem: pubPem,
      now,
      createdAtIso: oldCreated
    });

    const verifier = new AppleReceiptVerifier({
      trustAnchors: [rootCA.certPem],
      now: () => now
    });

    await assert.rejects(
      () => verifier.verify(receipt, { appId, publicKeyPem: pubPem }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'RECEIPT_EXPIRED');
        return true;
      }
    );
  });

  it('rejects receipt where attribute 12 created timestamp is in the future (> 15s) with RECEIPT_EXPIRED', async () => {
    const rootCA = await createReceiptCA({ now });
    const signer = await createReceiptSigner(rootCA, { now });

    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPem = ecKey.publicKey.export({ format: 'pem', type: 'spki' }) as string;

    // Created 30 seconds into future (> 15,000ms clock skew allowance)
    const futureCreated = new Date(now + 30000).toISOString();

    const receipt = await createCmsReceipt({
      rootCA,
      signerCert: signer,
      appId,
      publicKeyPem: pubPem,
      now,
      createdAtIso: futureCreated
    });

    const verifier = new AppleReceiptVerifier({
      trustAnchors: [rootCA.certPem],
      now: () => now
    });

    await assert.rejects(
      () => verifier.verify(receipt, { appId, publicKeyPem: pubPem }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'RECEIPT_EXPIRED');
        return true;
      }
    );
  });

  it('rejects receipt with expired attribute 21 expiration timestamp with RECEIPT_EXPIRED', async () => {
    const rootCA = await createReceiptCA({ now });
    const signer = await createReceiptSigner(rootCA, { now });

    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPem = ecKey.publicKey.export({ format: 'pem', type: 'spki' }) as string;

    // Expired 1 second ago
    const expiredAt = new Date(now - 1000).toISOString();

    const receipt = await createCmsReceipt({
      rootCA,
      signerCert: signer,
      appId,
      publicKeyPem: pubPem,
      now,
      expiresAtIso: expiredAt
    });

    const verifier = new AppleReceiptVerifier({
      trustAnchors: [rootCA.certPem],
      now: () => now
    });

    await assert.rejects(
      () => verifier.verify(receipt, { appId, publicKeyPem: pubPem }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'RECEIPT_EXPIRED');
        return true;
      }
    );
  });
});
