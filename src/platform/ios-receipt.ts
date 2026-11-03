import { createPublicKey, type KeyObject, webcrypto, X509Certificate } from 'node:crypto';
import * as asn1 from 'asn1js';
import { Certificate, ContentInfo, CryptoEngine, SignedData, setEngine } from 'pkijs';
import { SecurityError } from '../contracts.js';

// Receipt signatures use Apple Root CA G3, a different anchor from App Attestation.
// Source: https://www.apple.com/certificateauthority/AppleRootCA-G3.cer, 2026-10-28.
// SHA256: 63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179.
export const APPLE_RECEIPT_ROOT = `-----BEGIN CERTIFICATE-----
MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwS
QXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcN
MTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBS
b290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9y
aXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49
AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtf
TjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517
IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySr
MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gA
MGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4
at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM
6BgD56KyKA==
-----END CERTIFICATE-----`;

setEngine('NodeWebCrypto', new CryptoEngine({ name: 'NodeWebCrypto', crypto: webcrypto as unknown as Crypto }));
const SHA2_OIDS = new Set(['2.16.840.1.101.3.4.2.1', '2.16.840.1.101.3.4.2.2', '2.16.840.1.101.3.4.2.3']);

function parse(bytes: Uint8Array): asn1.AsnType {
  const decoded = asn1.fromBER(bytes, { maxDepth: 32, maxNodes: 4096, maxContentLength: 128 * 1024 });
  if (decoded.offset !== bytes.byteLength) throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
  return decoded.result;
}

function octets(value: asn1.OctetString, depth = 0): Buffer {
  if (depth > 8) throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
  if (!value.idBlock.isConstructed) return Buffer.from(value.valueBlock.valueHexView);
  return Buffer.concat(value.valueBlock.value.map((part) => {
    if (!(part instanceof asn1.OctetString)) throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
    return octets(part, depth + 1);
  }));
}

function isoTime(text: string): number {
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(text)) return NaN;
  const value = Date.parse(text);
  // Date.parse normalizes impossible dates; reject that normalization explicitly.
  return Number.isFinite(value) && new Date(value).toISOString().slice(0, 19) === text.slice(0, 19) ? value : NaN;
}

export interface ReceiptContext { appId: string; publicKeyPem: string }
export interface ReceiptVerifier {
  verify(receipt: Buffer, context: ReceiptContext): Promise<{ receipt: string; receiptCreatedAt: number }>;
}

/** Trust roots are injectable in isolated tests; production uses the fixed Apple root. */
export class AppleReceiptVerifier implements ReceiptVerifier {
  private readonly anchors: Certificate[];
  constructor(private readonly options: { trustAnchors?: string[]; now?: () => number } = {}) {
    this.anchors = (options.trustAnchors ?? [APPLE_RECEIPT_ROOT]).map((pem) =>
      Certificate.fromBER(new X509Certificate(pem).raw));
    if (!this.anchors.length) throw new Error('Receipt trust anchors required');
  }

  async verify(receipt: Buffer, context: ReceiptContext): Promise<{ receipt: string; receiptCreatedAt: number }> {
    try {
      if (!receipt.length || receipt.length > 128 * 1024) throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
      const cms = new ContentInfo({ schema: parse(receipt) });
      if (cms.contentType !== '1.2.840.113549.1.7.2') throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
      const signed = new SignedData({ schema: cms.content });
      if (signed.signerInfos.length !== 1 || !signed.certificates?.length || signed.certificates.length > 8 ||
          signed.encapContentInfo.eContentType !== '1.2.840.113549.1.7.1' ||
          !(signed.encapContentInfo.eContent instanceof asn1.OctetString) ||
          !SHA2_OIDS.has(signed.signerInfos[0].digestAlgorithm.algorithmId)) {
        throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
      }
      const now = (this.options.now ?? Date.now)();
      const verified = await signed.verify({ signer: 0, checkChain: true, trustedCerts: this.anchors,
        checkDate: new Date(now), passedWhenNotRevValues: true, extendedMode: true });
      if (!verified.signatureVerified || !verified.signerCertificateVerified) {
        throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
      }
      // Root G3 also certifies other Apple signing products. Require the dedicated
      // App Attest fraud receipt signer profile, not merely any Apple-issued key.
      const signer = verified.signerCertificate;
      const markers = signer?.extensions?.filter(e => e.extnID === '1.2.840.113635.100.12.15') ?? [];
      if (!signer || markers.length !== 1 ||
          Buffer.from(markers[0].extnValue.valueBlock.valueHexView).toString('hex') !== '0500' ||
          new X509Certificate(Buffer.from(signer.toSchema(true).toBER())).ca) {
        throw new SecurityError('INVALID_RECEIPT_SIGNER_PROFILE');
      }
      const payload = parse(octets(signed.encapContentInfo.eContent));
      if (!(payload instanceof asn1.Set) || payload.valueBlock.value.length > 64) {
        throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
      }
      const attributes = new Map<number, Buffer>();
      for (const attribute of payload.valueBlock.value) {
        if (!(attribute instanceof asn1.Sequence)) throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
        const values = attribute.valueBlock.value;
        if (values.length !== 3 || !(values[0] instanceof asn1.Integer) ||
            !(values[1] instanceof asn1.Integer) || !(values[2] instanceof asn1.OctetString)) {
          throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
        }
        const field = values[0].valueBlock.valueDec;
        if (!Number.isSafeInteger(field) || field < 0 || attributes.has(field)) {
          throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
        }
        attributes.set(field, octets(values[2]));
      }
      if (attributes.get(2)?.toString('utf8') !== context.appId) throw new SecurityError('RECEIPT_APP_ID_MISMATCH');
      if (attributes.get(6)?.toString('ascii') !== 'ATTEST') throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
      const createdText = attributes.get(12)?.toString('ascii') ?? '';
      const createdAt = isoTime(createdText);
      if (!Number.isFinite(createdAt) || now - createdAt > 300_000 || createdAt - now > 15_000) {
        throw new SecurityError('RECEIPT_EXPIRED');
      }
      const expiration = attributes.get(21);
      if (expiration) {
        const expiresAt = isoTime(expiration.toString('ascii'));
        if (!Number.isFinite(expiresAt) || expiresAt <= now) throw new SecurityError('RECEIPT_EXPIRED');
      }
      const keyBytes = attributes.get(3);
      if (!keyBytes) throw new SecurityError('RECEIPT_KEY_MISMATCH');
      let receiptKey: KeyObject;
      // Apple's field 3 can contain the attested certificate (see Apple's 2026 example).
      try { receiptKey = new X509Certificate(keyBytes).publicKey; }
      catch { receiptKey = createPublicKey({ key: keyBytes, format: 'der', type: 'spki' }); }
      const storedKey = createPublicKey(context.publicKeyPem).export({ format: 'der', type: 'spki' });
      if (!receiptKey.export({ format: 'der', type: 'spki' }).equals(storedKey)) {
        throw new SecurityError('RECEIPT_KEY_MISMATCH');
      }
      return { receipt: receipt.toString('base64'), receiptCreatedAt: createdAt };
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError('INVALID_APP_ATTEST_RECEIPT');
    }
  }
}
