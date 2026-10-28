import 'reflect-metadata';
import crypto, { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import * as asn1js from 'asn1js';
import {
  Certificate,
  ContentInfo,
  CryptoEngine,
  SignedData,
  EncapsulatedContentInfo,
  SignerInfo,
  IssuerAndSerialNumber,
  setEngine
} from 'pkijs';
import { Encoder } from 'cbor-x';
const encoder = new Encoder({ mapsAsObjects: false, useRecords: false, tagUint8Array: false });
const encode = (val: any) => encoder.encode(val);
export const APPLE_APP_ATTEST_NONCE_OID = '1.2.840.113635.100.8.2';
import { AppleReceiptVerifier } from '../../src/platform/ios-receipt.js';

setEngine('NodeWebCrypto', new CryptoEngine({ name: 'NodeWebCrypto', crypto: webcrypto as any }));

export interface CAEntity {
  cert: x509.X509Certificate;
  certPem: string;
  certDer: Buffer;
  keyPair: any;
  privateKeyPem: string;
  publicKeyPem: string;
}

export async function exportPem(key: any, format: 'spki' | 'pkcs8'): Promise<string> {
  const exported = await (webcrypto.subtle as any).exportKey(format, key);
  const base64 = Buffer.from(exported).toString('base64');
  const type = format === 'spki' ? 'PUBLIC KEY' : 'PRIVATE KEY';
  const lines = base64.match(/.{1,64}/g)?.join('\n') || '';
  return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----`;
}

/**
 * Creates a synthetic Apple Receipt Root CA.
 */
export async function createReceiptCA(options: { now?: number; expired?: boolean } = {}): Promise<CAEntity> {
  const now = options.now ?? Date.now();
  const notBefore = options.expired ? new Date(now - 7200000) : new Date(now - 3600000);
  const notAfter = options.expired ? new Date(now - 3600000) : new Date(now + 86400000 * 365);

  const keyPair = await (webcrypto.subtle as any).generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.randomBytes(8).toString('hex'),
    name: 'CN=Apple Root CA - G3 Synthetic, O=Apple Inc., C=US',
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys: keyPair,
    extensions: [new x509.BasicConstraintsExtension(true, 1)]
  });

  return {
    cert,
    certPem: cert.toString('pem'),
    certDer: Buffer.from(cert.rawData),
    keyPair,
    privateKeyPem: await exportPem(keyPair.privateKey, 'pkcs8'),
    publicKeyPem: await exportPem(keyPair.publicKey, 'spki')
  };
}

/**
 * Creates a synthetic Apple Receipt Signer Certificate.
 * Mandatory extension 1.2.840.113635.100.12.15 must be DER NULL (05 00) and leaf must not be a CA.
 */
export async function createReceiptSigner(
  rootCA: CAEntity,
  options: {
    now?: number;
    omitMarker?: boolean;
    markerValueHex?: string;
    isCA?: boolean;
  } = {}
): Promise<CAEntity> {
  const now = options.now ?? Date.now();
  const notBefore = new Date(now - 3600000);
  const notAfter = new Date(now + 86400000 * 180);

  const keyPair = await (webcrypto.subtle as any).generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(options.isCA ?? false)
  ];

  if (!options.omitMarker) {
    const markerVal = options.markerValueHex
      ? Buffer.from(options.markerValueHex, 'hex')
      : new Uint8Array([0x05, 0x00]);
    extensions.push(
      new x509.Extension('1.2.840.113635.100.12.15', false, markerVal)
    );
  }

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: crypto.randomBytes(8).toString('hex'),
    subject: 'CN=Apple App Attest Receipt Signer, O=Apple Inc., C=US',
    issuer: rootCA.cert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey: keyPair.publicKey,
    signingKey: rootCA.keyPair.privateKey,
    extensions
  });

  return {
    cert,
    certPem: cert.toString('pem'),
    certDer: Buffer.from(cert.rawData),
    keyPair,
    privateKeyPem: await exportPem(keyPair.privateKey, 'pkcs8'),
    publicKeyPem: await exportPem(keyPair.publicKey, 'spki')
  };
}

/**
 * Creates a signed CMS App Attest Fraud Receipt.
 */
export async function createCmsReceipt(options: {
  rootCA: CAEntity;
  signerCert: CAEntity;
  appId: string;
  publicKeyPem: string;
  now?: number;
  createdAtIso?: string;
  expiresAtIso?: string;
  omitFields?: number[];
  customAttributes?: asn1js.Sequence[];
  corruptSignature?: boolean;
}): Promise<Buffer> {
  const now = options.now ?? Date.now();
  const pubKey = crypto.createPublicKey(options.publicKeyPem);
  const spkiDer = pubKey.export({ format: 'der', type: 'spki' });

  function makeAttr(fieldId: number, typeId: number, val: Buffer): asn1js.Sequence {
    return new asn1js.Sequence({
      value: [
        new asn1js.Integer({ value: fieldId }),
        new asn1js.Integer({ value: typeId }),
        new asn1js.OctetString({ valueHex: new Uint8Array(val).buffer })
      ]
    });
  }

  const attributes: asn1js.Sequence[] = [];

  const omit = new Set(options.omitFields ?? []);

  if (!omit.has(2)) {
    attributes.push(makeAttr(2, 1, Buffer.from(options.appId, 'utf8')));
  }
  if (!omit.has(3)) {
    attributes.push(makeAttr(3, 1, spkiDer));
  }
  if (!omit.has(6)) {
    attributes.push(makeAttr(6, 1, Buffer.from('ATTEST', 'ascii')));
  }
  if (!omit.has(12)) {
    const created = options.createdAtIso ?? new Date(now).toISOString();
    attributes.push(makeAttr(12, 1, Buffer.from(created, 'ascii')));
  }
  if (options.expiresAtIso && !omit.has(21)) {
    attributes.push(makeAttr(21, 1, Buffer.from(options.expiresAtIso, 'ascii')));
  }

  if (options.customAttributes) {
    attributes.push(...options.customAttributes);
  }

  const payloadSet = new asn1js.Set({ value: attributes });
  const payloadDer = Buffer.from(payloadSet.toBER());

  const pkijsSignerCert = Certificate.fromBER(new Uint8Array(options.signerCert.certDer).buffer as ArrayBuffer);
  const pkijsRootCert = Certificate.fromBER(new Uint8Array(options.rootCA.certDer).buffer as ArrayBuffer);

  const signedData = new SignedData({
    version: 1,
    encapContentInfo: new EncapsulatedContentInfo({
      eContentType: '1.2.840.113549.1.7.1',
      eContent: new asn1js.OctetString({ valueHex: new Uint8Array(payloadDer).buffer })
    }),
    certificates: [pkijsSignerCert, pkijsRootCert]
  });

  signedData.signerInfos.push(
    new SignerInfo({
      version: 1,
      sid: new IssuerAndSerialNumber({
        issuer: pkijsSignerCert.issuer,
        serialNumber: pkijsSignerCert.serialNumber
      })
    })
  );

  await signedData.sign(options.signerCert.keyPair.privateKey, 0, 'SHA-256');

  if (options.corruptSignature) {
    const rawSig = Buffer.from(signedData.signerInfos[0].signature.valueBlock.valueHexView);
    rawSig[rawSig.length - 1] ^= 0xff;
    signedData.signerInfos[0].signature = new asn1js.OctetString({
      valueHex: new Uint8Array(rawSig).buffer
    });
  }

  const contentInfo = new ContentInfo({
    contentType: '1.2.840.113549.1.7.2',
    content: signedData.toSchema(true)
  });

  return Buffer.from(contentInfo.toSchema().toBER(false));
}

/**
 * Creates a synthetic Apple App Attestation Root CA.
 */
export async function createAppleAttestRootCA(options: { now?: number; expired?: boolean } = {}): Promise<CAEntity> {
  const now = options.now ?? Date.now();
  const notBefore = options.expired ? new Date(now - 7200000) : new Date(now - 3600000);
  const notAfter = options.expired ? new Date(now - 3600000) : new Date(now + 86400000 * 365);

  const keyPair = await (webcrypto.subtle as any).generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: crypto.randomBytes(8).toString('hex'),
    name: 'CN=Apple App Attestation Root CA Synthetic, O=Apple Inc., C=US',
    notBefore,
    notAfter,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys: keyPair,
    extensions: [new x509.BasicConstraintsExtension(true, 1)]
  });

  return {
    cert,
    certPem: cert.toString('pem'),
    certDer: Buffer.from(cert.rawData),
    keyPair,
    privateKeyPem: await exportPem(keyPair.privateKey, 'pkcs8'),
    publicKeyPem: await exportPem(keyPair.publicKey, 'spki')
  };
}

export interface IosAttestationFixtureOptions {
  appId?: string;
  challenge?: string | Buffer;
  now?: number;
  environment?: 'production' | 'development';
  rootCA?: CAEntity;
  receiptRootCA?: CAEntity;
  receiptSigner?: CAEntity;
  validationCategory?: number;
  bundleVersion?: string;
  // Negative mutations
  omitReceipt?: boolean;
  corruptReceipt?: boolean;
  wrongReceiptAppId?: string;
  wrongReceiptKey?: boolean;
  expiredReceipt?: boolean;
  futureReceipt?: boolean;
  omitMarkerInReceiptSigner?: boolean;
  receiptSignerIsCA?: boolean;
  omitNonceExtension?: boolean;
  corruptNonce?: boolean;
  wrongAppIdInAuthData?: boolean;
  wrongAaguid?: boolean;
  wrongCredId?: boolean;
  wrongCoseKey?: boolean;
  flags?: number;
  initialSignCount?: number;
  duplicateCborKey?: boolean;
  oversizeAttestation?: boolean;
  leafKeyType?: 'EC' | 'RSA';
}

export interface IosAttestationFixture {
  attestationObjectBase64: string;
  keyId: string;
  appId: string;
  challengeHex: string;
  challenge: Buffer;
  leafPrivateKeyPem: string;
  leafPublicKeyPem: string;
  rootCertPem: string;
  receiptRootPem: string;
  receiptVerifier: AppleReceiptVerifier;
  leafNodeCert: crypto.X509Certificate;
}

/**
 * Builds a complete synthetic Apple App Attest attestation object and associated keys.
 */
export async function createIosAttestationFixture(
  options: IosAttestationFixtureOptions = {}
): Promise<IosAttestationFixture> {
  const now = options.now ?? Date.now();
  const appId = options.appId ?? 'TEAMID123.com.astrology.tarot';
  const environment = options.environment ?? 'production';
  const rawChallenge = options.challenge ?? crypto.randomBytes(32).toString('hex');
  const challengeHex = typeof rawChallenge === 'string' ? rawChallenge : rawChallenge.toString('hex');
  const challengeBuf = Buffer.from(challengeHex, 'utf8');

  // 1. Root and Intermediate / Attestation CAs
  const rootCA = options.rootCA ?? (await createAppleAttestRootCA({ now }));

  // 2. Leaf Client Key Pair
  let leafKeyPair: any;
  if (options.leafKeyType === 'RSA') {
    leafKeyPair = await (webcrypto.subtle as any).generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: 'SHA-256'
      },
      true,
      ['sign', 'verify']
    );
  } else {
    leafKeyPair = await (webcrypto.subtle as any).generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
  }

  const leafPrivateKeyPem = await exportPem(leafKeyPair.privateKey, 'pkcs8');
  const leafPublicKeyPem = await exportPem(leafKeyPair.publicKey, 'spki');

  // Extract EC coordinates and uncompressed point (0x04 || X || Y)
  let xBuf: Buffer;
  let yBuf: Buffer;
  if (options.leafKeyType === 'RSA') {
    xBuf = crypto.randomBytes(32);
    yBuf = crypto.randomBytes(32);
  } else {
    const jwk = await (webcrypto.subtle as any).exportKey('jwk', leafKeyPair.publicKey);
    xBuf = Buffer.from(jwk.x, 'base64url');
    yBuf = Buffer.from(jwk.y, 'base64url');
  }
  const uncompressedLeafPoint = Buffer.concat([Buffer.from([0x04]), xBuf, yBuf]);
  const calculatedKeyIdBuf = crypto.createHash('sha256').update(uncompressedLeafPoint).digest();
  const keyIdBase64 = calculatedKeyIdBuf.toString('base64');

  // 3. Authenticator Data (authData)
  const authAppId = options.wrongAppIdInAuthData ? 'WRONG.com.attacker' : appId;
  const rpIdHash = crypto.createHash('sha256').update(authAppId, 'utf8').digest();

  const hasExtensions = options.validationCategory !== undefined || options.bundleVersion !== undefined;
  const defaultFlags = hasExtensions ? 0xc0 : 0x40; // 0xc0 = AT (0x40) | ED (0x80)
  const flagsByte = options.flags !== undefined ? options.flags : defaultFlags;
  const signCountInt = options.initialSignCount !== undefined ? options.initialSignCount : 0;
  const signCountBuf = Buffer.alloc(4);
  signCountBuf.writeUInt32BE(signCountInt, 0);

  const aaguid = options.wrongAaguid
    ? Buffer.alloc(16, 0xff)
    : environment === 'development'
      ? Buffer.from('appattestdevelop', 'ascii')
      : Buffer.from('61707061747465737400000000000000', 'hex');

  const credIdLenBuf = Buffer.alloc(2);
  credIdLenBuf.writeUInt16BE(32, 0);

  const credId = options.wrongCredId
    ? crypto.randomBytes(32)
    : calculatedKeyIdBuf;

  // COSE Key Map
  const coseKeyMap = new Map<number, unknown>([
    [1, 2], // kty: 2 (EC2)
    [3, -7], // alg: -7 (ES256)
    [-1, 1], // crv: 1 (P-256)
    [-2, options.wrongCoseKey ? crypto.randomBytes(32) : xBuf],
    [-3, options.wrongCoseKey ? crypto.randomBytes(32) : yBuf]
  ]);
  const coseKeyBytes = encode(coseKeyMap);

  let extensionsBytes = Buffer.alloc(0);
  if (options.validationCategory !== undefined || options.bundleVersion !== undefined) {
    const extMap = new Map<string, unknown>();
    if (options.validationCategory !== undefined) {
      extMap.set('apple_validation_category_01', options.validationCategory);
    }
    if (options.bundleVersion !== undefined) {
      extMap.set('apple_bundle_version_01', options.bundleVersion);
    }
    extensionsBytes = Buffer.from(encode(extMap));
  }

  const authData = Buffer.concat([
    rpIdHash,
    Buffer.from([flagsByte]),
    signCountBuf,
    aaguid,
    credIdLenBuf,
    credId,
    coseKeyBytes,
    extensionsBytes
  ]);

  // 4. Calculate Nonce: SHA256(authData || SHA256(challengeUTF8))
  const challengeHash = crypto.createHash('sha256').update(challengeBuf).digest();
  let nonce = crypto.createHash('sha256').update(Buffer.concat([authData, challengeHash])).digest();

  if (options.corruptNonce) {
    const corrupted = Buffer.from(nonce);
    corrupted[0] ^= 0x01;
    nonce = corrupted;
  }

  // 5. Build Leaf Certificate with Apple Nonce Extension
  // Extension value: SEQUENCE { [1] EXPLICIT OCTET STRING (32 bytes nonce) }
  const nonceSeq = new asn1js.Sequence({
    value: [
      new asn1js.Constructed({
        idBlock: {
          tagClass: 3, // Context-specific
          tagNumber: 1
        },
        value: [
          new asn1js.OctetString({
            valueHex: new Uint8Array(nonce).buffer
          })
        ]
      })
    ]
  });
  const nonceExtDer = Buffer.from(nonceSeq.toBER(false));

  const leafExtensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(false)
  ];
  if (!options.omitNonceExtension) {
    leafExtensions.push(
      new x509.Extension(APPLE_APP_ATTEST_NONCE_OID, true, nonceExtDer)
    );
  }

  const leafCert = await x509.X509CertificateGenerator.create({
    serialNumber: crypto.randomBytes(8).toString('hex'),
    subject: 'CN=Apple App Attest Leaf, O=Apple Inc., C=US',
    issuer: rootCA.cert.subject,
    notBefore: new Date(now - 3600000),
    notAfter: new Date(now + 86400000 * 30),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey: leafKeyPair.publicKey,
    signingKey: rootCA.keyPair.privateKey,
    extensions: leafExtensions
  });

  const leafNodeCert = new crypto.X509Certificate(Buffer.from(leafCert.rawData));

  // 6. Build CMS Receipt
  const receiptRoot = options.receiptRootCA ?? (await createReceiptCA({ now }));
  const receiptSigner =
    options.receiptSigner ??
    (await createReceiptSigner(receiptRoot, {
      now,
      omitMarker: options.omitMarkerInReceiptSigner,
      isCA: options.receiptSignerIsCA
    }));

  const receiptTargetKeyPem = options.wrongReceiptKey
    ? (await exportPem(
        (
          await (webcrypto.subtle as any).generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['sign', 'verify']
          )
        ).publicKey,
        'spki'
      ))
    : leafPublicKeyPem;

  const receiptCreatedAtIso = options.expiredReceipt
    ? new Date(now - 600000).toISOString() // 10 minutes ago (> 5m allowed)
    : options.futureReceipt
      ? new Date(now + 30000).toISOString() // 30s in future (> 15s allowed)
      : new Date(now).toISOString();

  let receiptDer: any = Buffer.alloc(0);
  if (!options.omitReceipt) {
    receiptDer = await createCmsReceipt({
      rootCA: receiptRoot,
      signerCert: receiptSigner,
      appId: options.wrongReceiptAppId ?? appId,
      publicKeyPem: receiptTargetKeyPem,
      now,
      createdAtIso: receiptCreatedAtIso,
      corruptSignature: options.corruptReceipt
    });
  }

  // 7. Assemble Attestation Object (CBOR)
  const attStmtMap = new Map<string, unknown>();
  attStmtMap.set('x5c', [Buffer.from(leafCert.rawData), Buffer.from(rootCA.cert.rawData)]);
  if (!options.omitReceipt) {
    attStmtMap.set('receipt', receiptDer);
  }

  let attestationObjectBytes: Buffer;
  if (options.duplicateCborKey) {
    // Manually create raw CBOR buffer with duplicate key
    const rawFmt = encode({ fmt: 'apple-appattest' });
    const rawDup = Buffer.concat([
      Buffer.from([0xa4]), // map with 4 items
      encode('fmt'), encode('apple-appattest'),
      encode('fmt'), encode('apple-appattest'),
      encode('attStmt'), encode(attStmtMap),
      encode('authData'), encode(authData)
    ]);
    attestationObjectBytes = rawDup;
  } else if (options.oversizeAttestation) {
    attestationObjectBytes = Buffer.alloc(260 * 1024, 0x55);
  } else {
    const attObjMap = new Map<string, unknown>();
    attObjMap.set('fmt', 'apple-appattest');
    attObjMap.set('attStmt', attStmtMap);
    attObjMap.set('authData', authData);
    attestationObjectBytes = Buffer.from(encode(attObjMap));
  }

  const receiptVerifier = new AppleReceiptVerifier({
    trustAnchors: [receiptRoot.certPem],
    now: () => now
  });

  return {
    attestationObjectBase64: attestationObjectBytes.toString('base64'),
    keyId: keyIdBase64,
    appId,
    challengeHex,
    challenge: challengeBuf,
    leafPrivateKeyPem,
    leafPublicKeyPem,
    rootCertPem: rootCA.certPem,
    receiptRootPem: receiptRoot.certPem,
    receiptVerifier,
    leafNodeCert
  };
}

export interface IosAssertionOptions {
  appId: string;
  privateKeyPem: string;
  canonicalBuffer: Buffer;
  counter: number;
  flags?: number;
  wrongAppId?: boolean;
  doubleHash?: boolean;
  corruptSignature?: boolean;
  invalidSignatureLength?: boolean;
  malformedDerSignature?: boolean;
  duplicateCborKey?: boolean;
}

/**
 * Builds a valid or tampered Apple App Attest assertion CBOR object.
 */
export function createIosAssertion(options: IosAssertionOptions): { assertionBase64: string; counter: number } {
  const appId = options.wrongAppId ? 'WRONG.com.attacker' : options.appId;
  const rpIdHash = crypto.createHash('sha256').update(appId, 'utf8').digest();

  const flagsByte = options.flags !== undefined ? options.flags : 0; // Assertion flags: 0 (or 0x01 UP), NO AT
  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32BE(options.counter, 0);

  const authenticatorData = Buffer.concat([
    rpIdHash,
    Buffer.from([flagsByte]),
    counterBuf
  ]);

  const clientDataHash = crypto.createHash('sha256').update(options.canonicalBuffer).digest();

  // Signature input composite: concat(authenticatorData, SHA256(canonical))
  let composite = Buffer.concat([authenticatorData, clientDataHash]);

  if (options.doubleHash) {
    // Negative test: incorrectly hashing clientDataHash again or hashing composite
    composite = crypto.createHash('sha256').update(composite).digest();
  }

  let signatureDer = crypto.sign('sha256', composite, crypto.createPrivateKey(options.privateKeyPem));

  if (options.corruptSignature) {
    const corrupt = Buffer.from(signatureDer);
    corrupt[corrupt.length - 2] ^= 0x55;
    signatureDer = corrupt;
  } else if (options.invalidSignatureLength) {
    signatureDer = Buffer.alloc(7, 0xaa);
  } else if (options.malformedDerSignature) {
    signatureDer = Buffer.alloc(67, 0xbb);
  }

  const assertionMap = new Map<string, unknown>();
  assertionMap.set('signature', signatureDer);
  assertionMap.set('authenticatorData', authenticatorData);

  const cborBytes = encode(assertionMap);
  return {
    assertionBase64: Buffer.from(cborBytes).toString('base64'),
    counter: options.counter
  };
}
