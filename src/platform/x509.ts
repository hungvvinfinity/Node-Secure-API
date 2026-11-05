/**
 * Shared X.509 Certificate Chain Validator for Android and iOS attestation.
 *
 * Implements:
 * - Signature chaining verification
 * - Subject/Issuer name chaining
 * - Basic constraints (CA flag, path length constraints)
 * - Key usage checks (keyCertSign on intermediates, non-CA leaf)
 * - Critical extension filtering (rejecting unknown critical extensions)
 * - Selective validity checks (handling Android factory-provisioned intermediate rules and leaf clock skew)
 * - SPKI-based trust anchor matching (compatible with Google RSA root reissuances)
 * - Serial number revocation check across all certificates in the chain
 * - Anti-extension attack protection (nearest-root attestation extension must be leaf only)
 * - Chain size and certificate DER bounds
 * - Sanitized public error codes
 */

import 'reflect-metadata';
import * as asn1 from 'asn1js';
import { decode } from 'cbor-x';
import {
  createPublicKey,
  KeyObject,
  X509Certificate as NodeX509Certificate,
} from 'node:crypto';
import {
  BasicConstraintsExtension,
  KeyUsagesExtension,
  X509Certificate as PeculiarX509Certificate,
} from '@peculiar/x509';
import { SecurityError } from '../contracts.js';
import { normalizeSerialNumber } from './trust.js';

export const ANDROID_KEY_ATTESTATION_OID = '1.3.6.1.4.1.11129.2.1.17';
export const ANDROID_PROVISIONING_INFO_OID = '1.3.6.1.4.1.11129.2.1.30';

// Known recognized standard X.509 and Android attestation extension OIDs
export const RECOGNIZED_EXTENSION_OIDS = new Set<string>([
  '2.5.29.14', // Subject Key Identifier
  '2.5.29.15', // Key Usage
  '2.5.29.19', // Basic Constraints
  '2.5.29.35', // Authority Key Identifier
  ANDROID_KEY_ATTESTATION_OID,
]);

export const MAX_CHAIN_CERTIFICATES = 10;
export const MAX_CERTIFICATE_BYTES = 16 * 1024; // 16 KB
export const MAX_TOTAL_CHAIN_BYTES = 64 * 1024; // 64 KB

export type ValidationProfile = 'android' | 'strict';

export type ProvisioningMethod =
  | 'FACTORY_PROVISIONED'
  | 'REMOTELY_PROVISIONED'
  | 'UNKNOWN';

export interface ProvisioningInfo {
  certificatesIssued: number;
}

/**
 * Maximum signed 32-bit integer for certificatesIssued (Int.MAX_VALUE).
 */
export const MAX_CERTIFICATES_ISSUED = 2147483647;

export interface ChainValidationOptions {
  trustAnchors: string[]; // PEM strings of trust anchors
  revokedSerials?: Set<string>;
  now?: number; // epoch ms
  profile?: ValidationProfile;
  understoodCriticalExtensions?: ReadonlySet<string>;
}

export interface ChainValidationResult {
  leafCert: NodeX509Certificate;
  leafPeculiarCert: PeculiarX509Certificate;
  leafPublicKeyPem: string;
  chain: NodeX509Certificate[];
  provisioningMethod: ProvisioningMethod;
  provisioningInfo?: ProvisioningInfo;
  trustAnchor: NodeX509Certificate;
}

/**
 * Normalizes a certificate serial number from Node/Peculiar hex format to unpadded lowercase hex.
 */
export function normalizeCertSerialNumber(serial: string): string {
  return normalizeSerialNumber(serial);
}

/**
 * Exports a public KeyObject as SPKI PEM string.
 */
export function exportSpkiPem(publicKey: KeyObject): string {
  return publicKey.export({ type: 'spki', format: 'pem' }).toString().trim();
}

/**
 * Parses raw certificate strings (PEM or base64 DER) into Node.js X509Certificate objects.
 * Validates bounded chain length, per-cert size, and total size.
 */
export function parseCertificateChain(chainInputs: string[]): {
  nodeCerts: NodeX509Certificate[];
  peculiarCerts: PeculiarX509Certificate[];
} {
  if (!Array.isArray(chainInputs) || chainInputs.length === 0) {
    throw new SecurityError('EMPTY_CERTIFICATE_CHAIN', 400);
  }

  if (chainInputs.length > MAX_CHAIN_CERTIFICATES) {
    throw new SecurityError('CERTIFICATE_CHAIN_TOO_LARGE', 400);
  }

  const nodeCerts: NodeX509Certificate[] = [];
  const peculiarCerts: PeculiarX509Certificate[] = [];
  let totalBytes = 0;

  for (let i = 0; i < chainInputs.length; i++) {
    if (typeof chainInputs[i] !== 'string' || chainInputs[i].length > 24 * 1024) {
      throw new SecurityError('INVALID_CERTIFICATE', 400);
    }
    const raw = chainInputs[i].trim();
    if (!raw) {
      throw new SecurityError('INVALID_CERTIFICATE', 400);
    }

    let certDer: Buffer;
    let b64: string;
    if (raw.startsWith('-----BEGIN CERTIFICATE-----')) {
      const match = raw.match(/^-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)\s+-----END CERTIFICATE-----$/);
      if (!match) throw new SecurityError('INVALID_CERTIFICATE', 400);
      b64 = match[1].replace(/\s/g, '');
    } else {
      b64 = raw;
    }
    certDer = Buffer.from(b64, 'base64');
    if (certDer.toString('base64') !== b64) throw new SecurityError('INVALID_CERTIFICATE', 400);

    if (certDer.byteLength === 0 || certDer.byteLength > MAX_CERTIFICATE_BYTES) {
      throw new SecurityError('INVALID_CERTIFICATE', 400);
    }

    totalBytes += certDer.byteLength;
    if (totalBytes > MAX_TOTAL_CHAIN_BYTES) {
      throw new SecurityError('CERTIFICATE_CHAIN_TOO_LARGE', 400);
    }

    try {
      const der = asn1.fromBER(certDer, { maxDepth: 24, maxNodes: 2048, maxContentLength: MAX_CERTIFICATE_BYTES });
      if (der.offset !== certDer.byteLength || !(der.result instanceof asn1.Sequence)) throw new Error('Invalid DER');
      const nodeCert = new NodeX509Certificate(certDer);
      const peculiarCert = new PeculiarX509Certificate(new Uint8Array(certDer).buffer);
      nodeCerts.push(nodeCert);
      peculiarCerts.push(peculiarCert);
    } catch {
      throw new SecurityError('INVALID_CERTIFICATE', 400);
    }
  }

  return { nodeCerts, peculiarCerts };
}

/**
 * Determines whether a certificate contains the Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
 */
export function hasAttestationExtension(cert: PeculiarX509Certificate): boolean {
  return cert.extensions.some((ext) => ext.type === ANDROID_KEY_ATTESTATION_OID);
}

/**
 * Determines whether a certificate contains the Provisioning Info extension (OID 1.3.6.1.4.1.11129.2.1.30).
 */
export function hasProvisioningInfoExtension(cert: PeculiarX509Certificate): boolean {
  return cert.extensions.some((ext) => ext.type === ANDROID_PROVISIONING_INFO_OID);
}

/**
 * Parses the Android Provisioning Info extension (OID 1.3.6.1.4.1.11129.2.1.30).
 * Implements bounds clamping according to official Google AOSP KeyAttestation (commit 0e3ac2f):
 * - While RFC 8949 specifies unsigned integers up to 2^64-1, return value is bounded to 0..2^31 - 1.
 * - If certificates_issued is negative, clamp/limit to 0.
 * - If certificates_issued exceeds Int.MAX_VALUE (2^31 - 1), clamp/limit to 2147483647.
 */
export function parseProvisioningInfo(cert: PeculiarX509Certificate): ProvisioningInfo | null {
  const ext = cert.extensions.find((e) => e.type === ANDROID_PROVISIONING_INFO_OID);
  if (!ext || !ext.value) return null;

  try {
    const rawBytes = Buffer.from(ext.value);
    const decoded = decode(rawBytes);
    if (!decoded || typeof decoded !== 'object') return null;

    // In CBOR map, tag 1 is certificatesIssued (key can be string '1' or number 1)
    const map = decoded as Record<string | number, unknown>;
    const rawIssued = map['1'] ?? map[1];
    if (rawIssued === undefined || rawIssued === null) return null;

    let value: number;
    if (typeof rawIssued === 'bigint') {
      if (rawIssued < 0n) {
        value = 0;
      } else if (rawIssued > BigInt(MAX_CERTIFICATES_ISSUED)) {
        value = MAX_CERTIFICATES_ISSUED;
      } else {
        value = Number(rawIssued);
      }
    } else if (typeof rawIssued === 'number') {
      if (rawIssued < 0) {
        value = 0;
      } else if (rawIssued > MAX_CERTIFICATES_ISSUED) {
        value = MAX_CERTIFICATES_ISSUED;
      } else {
        value = Math.trunc(rawIssued);
      }
    } else {
      return null;
    }

    return { certificatesIssued: value };
  } catch {
    return null;
  }
}

/**
 * Detects the provisioning method based on certificate chain characteristics.
 */
export function detectProvisioningMethod(
  peculiarCerts: PeculiarX509Certificate[],
): ProvisioningMethod {
  if (peculiarCerts.length >= 2 && hasProvisioningInfoExtension(peculiarCerts[1])) {
    return 'REMOTELY_PROVISIONED';
  }

  // Classify signed intermediates, never the client-supplied root's label.
  for (let i = 1; i < peculiarCerts.length - 1; i++) {
    const cert = peculiarCerts[i];
    const subject = cert.subject;

    // RKP intermediate typically has CN=Droid CA2 / Droid CA3 and O=Google LLC
    if (/CN=Droid CA[23](?:,|$)/.test(subject) && subject.includes('O=Google LLC')) {
      return 'REMOTELY_PROVISIONED';
    }

    // Factory provisioned intermediate has serialNumber in subject DN (OID 2.5.4.5)
    if (i === peculiarCerts.length - 2 && peculiarCerts.length === 4 &&
        (subject.includes('2.5.4.5=') || subject.includes('serialNumber='))) {
      return 'FACTORY_PROVISIONED';
    }
  }

  // A four-certificate topology alone is not evidence for an expiry exception.
  return 'UNKNOWN';
}

/**
 * Shared X.509 Chain Validator.
 * Validates cryptographic signatures, subject-to-issuer name chaining, CA constraints,
 * key usage, validity periods, critical extensions, and revocation status.
 */
export function validateCertificateChain(
  chainInputs: string[],
  options: ChainValidationOptions,
): ChainValidationResult {
  const {
    trustAnchors,
    revokedSerials = new Set<string>(),
    now = Date.now(),
    profile = 'strict',
  } = options;
  if (!Number.isFinite(now)) throw new SecurityError('INVALID_VALIDATION_TIME', 500);

  if (!trustAnchors || trustAnchors.length === 0) {
    throw new SecurityError('NO_TRUST_ANCHORS_CONFIGURED', 500);
  }

  // Parse trust anchors into SPKI strings and Node certificates
  const anchorSpkis = new Set<string>();
  const parsedAnchors: NodeX509Certificate[] = [];
  for (const anchorPem of trustAnchors) {
    try {
      const anchorCert = new NodeX509Certificate(anchorPem);
      parsedAnchors.push(anchorCert);
      anchorSpkis.add(exportSpkiPem(anchorCert.publicKey));
    } catch {
      // If anchor is a raw SPKI PEM rather than certificate
      try {
        const pubKey = createPublicKey(anchorPem);
        anchorSpkis.add(exportSpkiPem(pubKey));
      } catch {
        throw new SecurityError('INVALID_TRUST_ANCHOR', 500);
      }
    }
  }

  const { nodeCerts, peculiarCerts } = parseCertificateChain(chainInputs);

  if (nodeCerts.length < 2) {
    throw new SecurityError('CERTIFICATE_CHAIN_TOO_SHORT', 400);
  }

  const leafCert = nodeCerts[0];
  const leafPeculiarCert = peculiarCerts[0];
  const rootCert = nodeCerts[nodeCerts.length - 1];

  // 1. Root Anchor Trust Verification:
  // Root cert must be self-signed and its SPKI must match one of the configured trust anchors
  const rootSpki = exportSpkiPem(rootCert.publicKey);
  if (!anchorSpkis.has(rootSpki)) {
    throw new SecurityError('UNTRUSTED_ROOT_CA', 403);
  }
  if (rootCert.subject !== rootCert.issuer) throw new SecurityError('INVALID_ROOT_SELF_SIGNATURE', 403);

  try {
    if (!rootCert.verify(rootCert.publicKey)) {
      throw new SecurityError('INVALID_ROOT_SELF_SIGNATURE', 403);
    }
  } catch (err) {
    if (err instanceof SecurityError) throw err;
    throw new SecurityError('INVALID_ROOT_SELF_SIGNATURE', 403);
  }

  const provisioningMethod = detectProvisioningMethod(peculiarCerts);

  // 2. Anti-extension Attack & Chain Topology Verification:
  // In Android Key Attestation, the attestation extension MUST be on the target certificate (leaf, index 0).
  // If an attacker appends a descendant certificate or an intermediate has an attestation extension, reject!
  if (profile === 'android') {
    const provisioningIndexes = peculiarCerts.flatMap((cert, i) => hasProvisioningInfoExtension(cert) ? [i] : []);
    if (provisioningIndexes.length > 1 || (provisioningIndexes.length === 1 && provisioningIndexes[0] !== 1)) {
      throw new SecurityError('INVALID_PROVISIONING_INFO_POSITION', 403);
    }
    let nearestRootAttestationIdx = -1;
    for (let i = peculiarCerts.length - 1; i >= 0; i--) {
      if (hasAttestationExtension(peculiarCerts[i])) {
        nearestRootAttestationIdx = i;
        break;
      }
    }

    if (nearestRootAttestationIdx === -1) {
      throw new SecurityError('TARGET_MISSING_ATTESTATION_EXTENSION', 403);
    }

    if (nearestRootAttestationIdx !== 0) {
      // Attestation extension found on non-leaf certificate (attacker extended chain)
      throw new SecurityError('CHAIN_EXTENDED_WITH_FAKE_ATTESTATION_EXTENSION', 403);
    }

    // Verify leaf has it, and no other cert has it
    for (let i = 1; i < peculiarCerts.length; i++) {
      if (hasAttestationExtension(peculiarCerts[i])) {
        throw new SecurityError('CHAIN_EXTENDED_WITH_FAKE_ATTESTATION_EXTENSION', 403);
      }
    }
  }

  // 3. Chain Link Verification (from Leaf towards Root):
  // Signatures, Name Chaining, CA constraints, Validity, Critical Extensions, Revocation
  const validationDate = new Date(now);

  for (let i = 0; i < nodeCerts.length; i++) {
    const current = nodeCerts[i];
    const peculiar = peculiarCerts[i];
    const isLeaf = i === 0;
    const isRoot = i === nodeCerts.length - 1;
    const parent = isRoot ? null : nodeCerts[i + 1];

    // A. Revocation check on all chain serials
    const certSerial = normalizeCertSerialNumber(peculiar.serialNumber);
    if (revokedSerials.has(certSerial)) {
      throw new SecurityError('CERTIFICATE_REVOKED', 403);
    }

    // B. Signature & Issuer chaining verification
    if (parent) {
      // Issuer name chaining
      if (current.issuer !== parent.subject) {
        throw new SecurityError('NAME_CHAINING_FAILED', 403);
      }

      // Cryptographic signature check
      try {
        if (!current.verify(parent.publicKey)) {
          throw new SecurityError('INVALID_CERTIFICATE_SIGNATURE', 403);
        }
      } catch (err) {
        if (err instanceof SecurityError) throw err;
        throw new SecurityError('INVALID_CERTIFICATE_SIGNATURE', 403);
      }
    }

    // C. Basic Constraints & Key Usage
    let basicConstraints: BasicConstraintsExtension | undefined;
    let keyUsage: KeyUsagesExtension | undefined;

    for (const ext of peculiar.extensions) {
      if (ext instanceof BasicConstraintsExtension) {
        basicConstraints = ext;
      } else if (ext instanceof KeyUsagesExtension) {
        keyUsage = ext;
      }

      // D. Unknown Critical Extension Check
      if (ext.critical && !RECOGNIZED_EXTENSION_OIDS.has(ext.type) && !options.understoodCriticalExtensions?.has(ext.type)) {
        throw new SecurityError('UNRECOGNIZED_CRITICAL_EXTENSION', 403);
      }
    }
    if (new Set(peculiar.extensions.map(ext => ext.type)).size !== peculiar.extensions.length) {
      throw new SecurityError('DUPLICATE_CERTIFICATE_EXTENSION', 403);
    }
    if (!['ECDSA', 'RSASSA-PKCS1-v1_5', 'RSA-PSS'].includes(peculiar.signatureAlgorithm.name) ||
        !['SHA-256', 'SHA-384', 'SHA-512'].includes(peculiar.signatureAlgorithm.hash.name)) {
      throw new SecurityError('UNSUPPORTED_CERTIFICATE_SIGNATURE_ALGORITHM', 403);
    }

    if (isLeaf) {
      if (keyUsage && (keyUsage.usages & 1) === 0) throw new SecurityError('LEAF_DIGITAL_SIGNATURE_REQUIRED', 403);
      // Leaf certificate must not be a CA certificate
      if (basicConstraints && basicConstraints.ca) {
        throw new SecurityError('LEAF_CERTIFICATE_MUST_NOT_BE_CA', 403);
      }
    } else {
      // Intermediate / Root certificate must have CA flag true
      if (!basicConstraints || !basicConstraints.ca) {
        throw new SecurityError('INTERMEDIATE_NOT_CA', 403);
      }

      // Check keyUsage: keyCertSign (bit 5 / value 32)
      if (keyUsage && (keyUsage.usages & 32) === 0) {
        throw new SecurityError('INTERMEDIATE_MISSING_KEY_CERT_SIGN', 403);
      }

      // Check path length constraint: number of CA certificates between current and leaf cannot exceed pathLength
      if (basicConstraints.pathLength !== undefined) {
        const numIntermediateCAsBelow = i - 1;
        if (numIntermediateCAsBelow > basicConstraints.pathLength) {
          throw new SecurityError('PATH_LENGTH_CONSTRAINT_EXCEEDED', 403);
        }
      }
    }

    // E. Validity Period Check
    if (profile === 'android') {
      if (!isLeaf && !isRoot) {
        const notBefore = peculiar.notBefore;
        const notAfter = peculiar.notAfter;

        if (validationDate < notBefore) {
          throw new SecurityError('CERTIFICATE_NOT_YET_VALID', 403);
        }

        if (validationDate > notAfter) {
          // If factory provisioned intermediate, allow expired as documented
          if (provisioningMethod !== 'FACTORY_PROVISIONED') {
            throw new SecurityError('CERTIFICATE_EXPIRED', 403);
          }
        }
      }
    } else {
      // Strict PKIX profile
      const notBefore = peculiar.notBefore;
      const notAfter = peculiar.notAfter;
      if (validationDate < notBefore) {
        throw new SecurityError('CERTIFICATE_NOT_YET_VALID', 403);
      }
      if (validationDate > notAfter) {
        throw new SecurityError('CERTIFICATE_EXPIRED', 403);
      }
    }
  }

  const leafPublicKeyPem = exportSpkiPem(leafCert.publicKey);

  const provisioningInfo = (provisioningMethod === 'REMOTELY_PROVISIONED' && peculiarCerts.length >= 2)
    ? parseProvisioningInfo(peculiarCerts[1]) ?? undefined
    : undefined;

  return {
    leafCert,
    leafPeculiarCert,
    leafPublicKeyPem,
    chain: nodeCerts,
    provisioningMethod,
    ...(provisioningInfo ? { provisioningInfo } : {}),
    trustAnchor: rootCert,
  };
}
