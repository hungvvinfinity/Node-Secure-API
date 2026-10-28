import 'reflect-metadata';
import * as x509 from '@peculiar/x509';
import * as asn1js from 'asn1js';
import crypto, { webcrypto } from 'node:crypto';

export const ANDROID_ATTESTATION_OID = '1.3.6.1.4.1.11129.2.1.17';

export type AnyCryptoKey = webcrypto.CryptoKey | CryptoKey;
export type AnyCryptoKeyPair = webcrypto.CryptoKeyPair | CryptoKeyPair;

export interface RootCAOptions {
  keyType?: 'EC' | 'RSA';
  subject?: string;
  serialNumber?: string;
  notBefore?: Date;
  notAfter?: Date;
  isCA?: boolean;
  now?: number;
}

export interface CAEntity {
  cert: x509.X509Certificate;
  certPem: string;
  certDer: Buffer;
  certBase64: string;
  keyPair: any;
  privateKeyPem: string;
  publicKeyPem: string;
}

export interface IntermediateCAOptions {
  subject?: string;
  serialNumber?: string;
  notBefore?: Date;
  notAfter?: Date;
  pathLenConstraint?: number;
  isCA?: boolean;
  now?: number;
}

export interface AttestationAsn1Options {
  attestationVersion?: number;
  attestationSecurityLevel?: number; // 0=Software, 1=TEE, 2=StrongBox
  keymasterVersion?: number;
  keymasterSecurityLevel?: number; // 0=Software, 1=TEE, 2=StrongBox
  challenge: Buffer | string;
  uniqueId?: Buffer;
  // AuthorizationList fields:
  purpose?: number[] | null; // e.g. [2] for SIGN
  algorithm?: number | null; // e.g. 3 for EC
  keySize?: number | null; // e.g. 256
  digest?: number[] | null; // e.g. [4] for SHA-256
  ecCurve?: number | null; // e.g. 1 for P-256
  origin?: number | null; // e.g. 0 for GENERATED
  // Root of trust
  rootOfTrust?: {
    verifiedBootKey?: Buffer;
    deviceLocked?: boolean;
    verifiedBootState?: number; // 0=Verified, 1=SelfSigned, 2=Unverified, 3=Failed
    verifiedBootHash?: Buffer;
  } | null;
  rootOfTrustInSoftware?: boolean;
  // Attestation Application Id (Tag 709)
  packageNames?: string[];
  packageVersion?: bigint | number;
  signerDigests?: Buffer[];
  appIdInSoftware?: boolean;
  omitAppId?: boolean;
  // Corruptions / Mutations:
  duplicateTag709?: boolean;
  rawMalformedDer?: Buffer;
}

export interface LeafCertOptions {
  keyPair?: any;
  keyType?: 'EC' | 'RSA';
  subject?: string;
  serialNumber?: string;
  notBefore?: Date;
  notAfter?: Date;
  attestationOptions?: AttestationAsn1Options;
  omitAttestationExtension?: boolean;
  customExtensions?: x509.Extension[];
  now?: number;
}

export async function exportPem(key: any, format: 'spki' | 'pkcs8'): Promise<string> {
  const exported = await (webcrypto.subtle as any).exportKey(format, key);
  const base64 = Buffer.from(exported).toString('base64');
  const type = format === 'spki' ? 'PUBLIC KEY' : 'PRIVATE KEY';
  const lines = base64.match(/.{1,64}/g)?.join('\n') || '';
  return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----`;
}

/**
 * Creates a self-signed Root CA.
 */
export async function createRootCA(options: RootCAOptions = {}): Promise<CAEntity> {
  const keyType = options.keyType ?? 'EC';
  let keyPair: any;
  let signingAlgorithm: any;

  if (keyType === 'RSA') {
    keyPair = await webcrypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['sign', 'verify']
    );
    signingAlgorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  } else {
    keyPair = await webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    signingAlgorithm = { name: 'ECDSA', hash: 'SHA-256' };
  }

  const isCA = options.isCA !== false;
  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(isCA, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)
  ];

  const now = options.now ?? Date.now();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: options.serialNumber ?? '01',
    name: options.subject ?? 'CN=Google Hardware Attestation Root CA Test',
    notBefore: options.notBefore ?? new Date(now - 3600000),
    notAfter: options.notAfter ?? new Date(now + 365 * 86400000),
    keys: keyPair as any,
    signingAlgorithm,
    extensions
  });

  const certPem = cert.toString('pem');
  const certDer = Buffer.from(cert.rawData);
  const certBase64 = certDer.toString('base64');
  const privateKeyPem = await exportPem(keyPair.privateKey, 'pkcs8');
  const publicKeyPem = await exportPem(keyPair.publicKey, 'spki');

  return {
    cert,
    certPem,
    certDer,
    certBase64,
    keyPair,
    privateKeyPem,
    publicKeyPem
  };
}

/**
 * Creates an Intermediate CA signed by the given issuer CA.
 */
export async function createIntermediateCA(
  issuer: CAEntity,
  options: IntermediateCAOptions = {}
): Promise<CAEntity> {
  const keyPair: any = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const isCA = options.isCA !== false;
  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(isCA, options.pathLenConstraint, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true)
  ];

  const now = options.now ?? Date.now();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: options.serialNumber ?? '02',
    subject: options.subject ?? 'CN=Google Hardware Attestation Intermediate CA Test',
    issuer: issuer.cert.subject,
    notBefore: options.notBefore ?? new Date(now - 3600000),
    notAfter: options.notAfter ?? new Date(now + 180 * 86400000),
    publicKey: keyPair.publicKey,
    signingKey: issuer.keyPair.privateKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions
  });

  const certPem = cert.toString('pem');
  const certDer = Buffer.from(cert.rawData);
  const certBase64 = certDer.toString('base64');
  const privateKeyPem = await exportPem(keyPair.privateKey, 'pkcs8');
  const publicKeyPem = await exportPem(keyPair.publicKey, 'spki');

  return {
    cert,
    certPem,
    certDer,
    certBase64,
    keyPair,
    privateKeyPem,
    publicKeyPem
  };
}

/**
 * Constructs the ASN.1 DER buffer for the KeyDescription extension.
 */
export function buildAndroidAttestationAsn1(options: AttestationAsn1Options): Buffer {
  if (options.rawMalformedDer) {
    return options.rawMalformedDer;
  }

  function makeContextTag(tagNumber: number, inner: asn1js.BaseBlock): asn1js.Constructed {
    return new asn1js.Constructed({
      idBlock: { tagClass: 3, tagNumber },
      value: [inner]
    });
  }

  const teeTags: asn1js.Constructed[] = [];
  const softwareTags: asn1js.Constructed[] = [];

  // Tag 1: purpose [1] EXPLICIT SET OF INTEGER
  if (options.purpose !== null) {
    const purposes = options.purpose ?? [2]; // Default: KM_PURPOSE_SIGN = 2
    teeTags.push(
      makeContextTag(
        1,
        new asn1js.Set({
          value: purposes.map((p) => new asn1js.Integer({ value: p }))
        })
      )
    );
  }

  // Tag 2: algorithm [2] EXPLICIT INTEGER (KM_ALGORITHM_EC = 3)
  if (options.algorithm !== null) {
    teeTags.push(makeContextTag(2, new asn1js.Integer({ value: options.algorithm ?? 3 })));
  }

  // Tag 3: keySize [3] EXPLICIT INTEGER (256)
  if (options.keySize !== null) {
    teeTags.push(makeContextTag(3, new asn1js.Integer({ value: options.keySize ?? 256 })));
  }

  // Tag 5: digest [5] EXPLICIT SET OF INTEGER (KM_DIGEST_SHA_2_256 = 4)
  if (options.digest !== null) {
    const digests = options.digest ?? [4];
    teeTags.push(
      makeContextTag(
        5,
        new asn1js.Set({
          value: digests.map((d) => new asn1js.Integer({ value: d }))
        })
      )
    );
  }

  // Tag 10: ecCurve [10] EXPLICIT INTEGER (P-256 = 1)
  if (options.ecCurve !== null) {
    teeTags.push(makeContextTag(10, new asn1js.Integer({ value: options.ecCurve ?? 1 })));
  }

  // Tag 702: origin [702] EXPLICIT INTEGER (KM_ORIGIN_GENERATED = 0)
  if (options.origin !== null) {
    teeTags.push(makeContextTag(702, new asn1js.Integer({ value: options.origin ?? 0 })));
  }

  // Tag 704: rootOfTrust [704] EXPLICIT RootOfTrust
  if (options.rootOfTrust !== null) {
    const rot = options.rootOfTrust ?? {};
    const bootKey = rot.verifiedBootKey ?? Buffer.alloc(32, 0x5a);
    const locked = rot.deviceLocked !== false;
    const bootState = rot.verifiedBootState ?? 0; // 0 = Verified
    const bootHash = rot.verifiedBootHash ?? Buffer.alloc(32, 0x6b);

    const rotSeq = new asn1js.Sequence({
      value: [
        new asn1js.OctetString({ valueHex: new Uint8Array(bootKey) }),
        new asn1js.Boolean({ value: locked }),
        new asn1js.Enumerated({ value: bootState }),
        new asn1js.OctetString({ valueHex: new Uint8Array(bootHash) })
      ]
    });

    const rotTag = makeContextTag(704, rotSeq);
    if (options.rootOfTrustInSoftware) {
      softwareTags.push(rotTag);
    } else {
      teeTags.push(rotTag);
    }
  }

  // Tag 709: attestationApplicationId [709] EXPLICIT OCTET STRING
  if (!options.omitAppId) {
    const packageNames = options.packageNames ?? ['com.astrology.tarot'];
    const packageVersion = options.packageVersion ?? 100n;
    const defaultSignerDigest = crypto.createHash('sha256').update('dummy-apk-cert').digest();
    const signerDigests = options.signerDigests ?? [defaultSignerDigest];

    const packageRecords = packageNames.map(
      (pkg) =>
        new asn1js.Sequence({
          value: [
            new asn1js.OctetString({ valueHex: new Uint8Array(Buffer.from(pkg, 'utf8')) }),
            bigIntToAsn1Integer(packageVersion)
          ]
        })
    );

    const sigOctets = signerDigests.map(
      (digest) => new asn1js.OctetString({ valueHex: new Uint8Array(digest) })
    );

    const appIdSeq = new asn1js.Sequence({
      value: [
        new asn1js.Set({ value: packageRecords }),
        new asn1js.Set({ value: sigOctets })
      ]
    });

    const appIdDer = Buffer.from(appIdSeq.toBER(false));
    const appIdTag = makeContextTag(
      709,
      new asn1js.OctetString({ valueHex: new Uint8Array(appIdDer) })
    );

    if (options.appIdInSoftware) {
      softwareTags.push(appIdTag);
      if (options.duplicateTag709) {
        softwareTags.push(appIdTag);
      }
    } else {
      teeTags.push(appIdTag);
      if (options.duplicateTag709) {
        teeTags.push(appIdTag);
      }
    }
  }

  const softwareEnforced = new asn1js.Sequence({ value: softwareTags });
  const teeEnforced = new asn1js.Sequence({ value: teeTags });

  const challengeBuf =
    typeof options.challenge === 'string'
      ? Buffer.from(options.challenge, 'utf8')
      : options.challenge;

  const keyDescription = new asn1js.Sequence({
    value: [
      new asn1js.Integer({ value: options.attestationVersion ?? 3 }),
      new asn1js.Enumerated({ value: options.attestationSecurityLevel ?? 1 }), // 1=TEE
      new asn1js.Integer({ value: options.keymasterVersion ?? 4 }),
      new asn1js.Enumerated({ value: options.keymasterSecurityLevel ?? 1 }), // 1=TEE
      new asn1js.OctetString({ valueHex: new Uint8Array(challengeBuf) }),
      new asn1js.OctetString({ valueHex: new Uint8Array(options.uniqueId ?? Buffer.alloc(0)) }),
      softwareEnforced,
      teeEnforced
    ]
  });

  return Buffer.from(keyDescription.toBER(false));
}

/**
 * Creates a leaf certificate signed by the issuer CA and containing the Android Attestation extension.
 */
export async function createAndroidLeafCert(
  issuer: CAEntity,
  options: LeafCertOptions = {}
): Promise<CAEntity> {
  let keyPair: any;
  if (options.keyPair) {
    keyPair = options.keyPair;
  } else if (options.keyType === 'RSA') {
    keyPair = await webcrypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['sign', 'verify']
    );
  } else {
    keyPair = await webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
  }

  const extensions: x509.Extension[] = [
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true)
  ];

  if (!options.omitAttestationExtension) {
    const attestationDer = buildAndroidAttestationAsn1(
      options.attestationOptions ?? { challenge: '0'.repeat(64) }
    );
    extensions.push(new x509.Extension(ANDROID_ATTESTATION_OID, false, new Uint8Array(attestationDer)));
  }

  if (options.customExtensions) {
    extensions.push(...options.customExtensions);
  }

  const now = options.now ?? Date.now();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: options.serialNumber ?? '03',
    subject: options.subject ?? 'CN=Android Keystore Key Test',
    issuer: issuer.cert.subject,
    notBefore: options.notBefore ?? new Date(now - 3600000),
    notAfter: options.notAfter ?? new Date(now + 90 * 86400000),
    publicKey: keyPair.publicKey,
    signingKey: issuer.keyPair.privateKey,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions
  });

  const certPem = cert.toString('pem');
  const certDer = Buffer.from(cert.rawData);
  const certBase64 = certDer.toString('base64');
  const privateKeyPem = await exportPem(keyPair.privateKey, 'pkcs8');
  const publicKeyPem = await exportPem(keyPair.publicKey, 'spki');

  return {
    cert,
    certPem,
    certDer,
    certBase64,
    keyPair,
    privateKeyPem,
    publicKeyPem
  };
}

export function bigIntToAsn1Integer(val: bigint | number): asn1js.Integer {
  const b = BigInt(val);
  if (b >= 0n && b <= 2147483647n) {
    return new asn1js.Integer({ value: Number(b) });
  }
  let hex = b.toString(16);
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }
  const buf = Buffer.from(hex, 'hex');
  // If positive and high bit of first byte is set (>= 0x80), in DER two's complement, prepend 0x00
  const finalBuf = (buf[0] & 0x80) !== 0 ? Buffer.concat([Buffer.from([0x00]), buf]) : buf;
  return new asn1js.Integer({ valueHex: new Uint8Array(finalBuf).buffer });
}

export interface CompleteAttestationFixtureOptions {
  now?: number;
  rootCA?: CAEntity;
  intermediateCA?: CAEntity;
  attestationSecurityLevel?: number; // 1=TEE, 2=StrongBox, 0=Software
  keymasterSecurityLevel?: number;
  challengeHex?: string;
  packageName?: string;
  packageVersion?: bigint | number;
  signerDigestHex?: string;
  deviceLocked?: boolean;
  verifiedBootState?: number;
  rootOfTrustInSoftware?: boolean;
  includeIntermediate?: boolean;
  leafKeyType?: 'EC' | 'RSA';
  omitAttestationExtension?: boolean;
  omitAppId?: boolean;
  duplicateTag709?: boolean;
  rawMalformedDer?: Buffer;
  rootExpired?: boolean;
  leafExpired?: boolean;
  leafNotYetValid?: boolean;
  intermediateExpired?: boolean;
  intermediateNotCA?: boolean;
  pathLenConstraint?: number;
  purpose?: number[] | null;
  algorithm?: number | null;
  origin?: number | null;
  digest?: number[] | null;
  ecCurve?: number | null;
  corruptChainSignature?: boolean;
}

export interface CompleteAttestationFixture {
  chain: string[]; // [leafBase64, (intermediateBase64), rootBase64]
  rootCA: CAEntity;
  intermediateCA?: CAEntity;
  leaf: CAEntity;
  challenge: string;
  expectedPackageName: string;
  expectedSignerDigests: string[];
  leafPrivateKeyPem: string;
  leafPublicKeyPem: string;
  rootCertPem: string;
  deviceId: string;
}

/**
 * Creates a complete verified attestation chain with all customizable parameters.
 */
export async function createAttestationChain(
  options: CompleteAttestationFixtureOptions = {}
): Promise<CompleteAttestationFixture> {
  const challenge = options.challengeHex ?? crypto.randomBytes(32).toString('hex');
  const packageName = options.packageName ?? 'com.astrology.tarot';
  const defaultDigest = crypto.createHash('sha256').update('test-apk-signing-cert').digest();
  const signerDigest = options.signerDigestHex
    ? Buffer.from(options.signerDigestHex, 'hex')
    : defaultDigest;

  const now = options.now ?? Date.now();
  const rootNotBefore = options.rootExpired ? new Date(now - 7200000) : new Date(now - 3600000);
  const rootNotAfter = options.rootExpired ? new Date(now - 3600000) : new Date(now + 365 * 86400000);

  const rootCA = options.rootCA ?? await createRootCA({
    notBefore: rootNotBefore,
    notAfter: rootNotAfter
  });

  let signingIssuer = rootCA;
  let intermediateCA: CAEntity | undefined = options.intermediateCA;

  if (!intermediateCA && options.includeIntermediate !== false) {
    const intNotBefore = options.intermediateExpired ? new Date(now - 7200000) : new Date(now - 3600000);
    const intNotAfter = options.intermediateExpired ? new Date(now - 3600000) : new Date(now + 180 * 86400000);

    intermediateCA = await createIntermediateCA(rootCA, {
      notBefore: intNotBefore,
      notAfter: intNotAfter,
      isCA: !options.intermediateNotCA,
      pathLenConstraint: options.pathLenConstraint
    });
  }
  if (intermediateCA) {
    signingIssuer = intermediateCA;
  }

  const leafNotBefore = options.leafNotYetValid
    ? new Date(now + 3600000)
    : options.leafExpired
    ? new Date(now - 7200000)
    : new Date(now - 3600000);

  const leafNotAfter = options.leafExpired
    ? new Date(now - 3600000)
    : new Date(now + 90 * 86400000);

  const leaf = await createAndroidLeafCert(signingIssuer, {
    keyType: options.leafKeyType,
    notBefore: leafNotBefore,
    notAfter: leafNotAfter,
    omitAttestationExtension: options.omitAttestationExtension,
    attestationOptions: {
      attestationSecurityLevel: options.attestationSecurityLevel ?? 1,
      keymasterSecurityLevel: options.keymasterSecurityLevel ?? 1,
      challenge,
      packageNames: [packageName],
      packageVersion: options.packageVersion ?? 100n,
      signerDigests: [signerDigest],
      omitAppId: options.omitAppId,
      duplicateTag709: options.duplicateTag709,
      rawMalformedDer: options.rawMalformedDer,
      purpose: options.purpose,
      algorithm: options.algorithm,
      origin: options.origin,
      digest: options.digest,
      ecCurve: options.ecCurve,
      rootOfTrust: {
        deviceLocked: options.deviceLocked !== false,
        verifiedBootState: options.verifiedBootState ?? 0
      },
      rootOfTrustInSoftware: options.rootOfTrustInSoftware
    }
  });

  const chain: string[] = [];
  if (options.corruptChainSignature) {
    // Corrupt one byte of leaf DER representation
    const corruptedDer = Buffer.from(leaf.certDer);
    corruptedDer[corruptedDer.length - 10] ^= 0xff;
    chain.push(corruptedDer.toString('base64'));
  } else {
    chain.push(leaf.certBase64);
  }

  if (intermediateCA) {
    chain.push(intermediateCA.certBase64);
  }
  chain.push(rootCA.certBase64);

  // Compute deviceId matching server derivation: SHA256("android:" + spkiDerBase64)
  const keyObj = crypto.createPublicKey(leaf.publicKeyPem);
  const spkiDer = keyObj.export({ type: 'spki', format: 'der' });
  const spkiDerBase64 = spkiDer.toString('base64');
  const deviceId = crypto.createHash('sha256').update(`android:${spkiDerBase64}`).digest('hex');

  return {
    chain,
    rootCA,
    intermediateCA,
    leaf,
    challenge,
    expectedPackageName: packageName,
    expectedSignerDigests: [signerDigest.toString('hex')],
    leafPrivateKeyPem: leaf.privateKeyPem,
    leafPublicKeyPem: leaf.publicKeyPem,
    rootCertPem: rootCA.certPem,
    deviceId
  };
}

/**
 * Signs a canonical buffer or string using the leaf private key with ECDSA SHA-256 (DER format).
 */
export function signCanonical(privateKeyPem: string, canonical: Buffer | string): string {
  const data = Buffer.isBuffer(canonical) ? canonical : Buffer.from(canonical, 'utf8');
  const signature = crypto.sign('sha256', data, privateKeyPem);
  return signature.toString('base64');
}

/**
 * Verifies ECDSA signature over canonical data.
 */
export function verifyCanonical(
  publicKeyPem: string,
  canonical: Buffer | string,
  signatureBase64: string
): boolean {
  try {
    const data = Buffer.isBuffer(canonical) ? canonical : Buffer.from(canonical, 'utf8');
    const sig = Buffer.from(signatureBase64, 'base64');
    return crypto.verify('sha256', data, publicKeyPem, sig);
  } catch {
    return false;
  }
}
