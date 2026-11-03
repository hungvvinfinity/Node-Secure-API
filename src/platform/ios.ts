/**
 * iOS Security Provider for Node Secure API.
 *
 * Implements Apple App Attest verification following official Apple specifications:
 * - https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
 * - https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity
 *
 * Core security guarantees:
 * - Strict bounded CBOR decoding and duplicate key rejection (preserves numeric COSE keys, strictly rejects tags)
 * - Pinned Apple App Attestation Root CA certificate chain validation under strict PKIX profile
 * - Dynamic cryptographic trust anchor selection across pinned roots when root CA is omitted by device
 * - Leaf attestation extension (OID 1.2.840.113635.100.8.2) validation:
 *   exact SEQUENCE { [1] EXPLICIT primitive OCTET STRING (32 bytes) } matching SHA256(authData || SHA256(challengeUTF8))
 * - Attested leaf public key verified as EC P-256 (prime256v1), uncompressed point (0x04 || X || Y) matching COSE key
 * - Credential ID & deterministic keyId = SHA256(leafPoint).base64 (canonical, exact 32 bytes)
 * - Authenticator Data checks: rpIdHash == SHA256(appId), signCount == 0 on registration,
 *   AAGUID matches server-selected environment ("appattest\0\0\0\0\0\0\0" vs "appattestdevelop"),
 *   AT flag set, no UP flag required, reserved flags strictly rejected
 * - Exact authData CBOR structure: 1 item if ED=0, 2 items if ED=1 (no 3rd items, extensions must be Map)
 * - 2026 Apple Extensions: apple_validation_category_01 (valid 1..6 uint32; 0 and >= 7 rejected)
 *   and apple_bundle_version_01 (dotted numeric versioning compared with BigInt precision)
 * - Both registration and request assertion parse and enforce extension rules identically when ED is set
 * - Mandatory Apple App Attest fraud receipt verification via AppleReceiptVerifier
 * - Request assertion verification: strictly monotonic counter advancement against validated stored signCount,
 *   single SHA-256 composite hash crypto.verify('sha256', concat(authData, SHA256(canonical)), key, signature) with zero double-hashing
 */

import 'reflect-metadata';
import crypto, { X509Certificate } from 'node:crypto';
import * as asn1js from 'asn1js';
import {
  DeviceRecord,
  DeviceSecurityProvider,
  Platform,
  RegistrationInput,
  RequestProof,
  SecurityError,
  VerifiedRegistration,
} from '../contracts.js';
import {
  decodeMultipleBounded,
  validateAndDecodeCBOR,
} from './cbor.js';
import { APPLE_APP_ATTESTATION_ROOTS } from './ios-roots.js';
import { AppleReceiptVerifier, ReceiptVerifier } from './ios-receipt.js';
import { getP256Key } from './key-cache.js';
import { exportSpkiPem, validateCertificateChain } from './x509.js';

export const APPLE_APP_ATTEST_NONCE_OID = '1.2.840.113635.100.8.2';

const BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const DOTTED_VERSION_REGEX = /^\d+(?:\.\d+)*$/;

export interface IOSSecurityProviderOptions {
  trustAnchors?: string[];
  appId: string;
  environment?: 'production' | 'development';
  receiptVerifier?: ReceiptVerifier;
  now?: () => number;
  minimumBundleVersion?: string;
  allowedValidationCategories?: number[];
  requireAppProperties?: boolean;
}

export interface AppProperties {
  validationCategory?: number;
  bundleVersion?: string;
}

/**
 * Compares two dotted numeric version strings (e.g. "1.0.216" vs "1.0").
 * Rejects malformed parts instead of coercing to 0.
 * Uses exact BigInt comparisons for all components without rounding.
 * Returns 1 if v1 > v2, -1 if v1 < v2, and 0 if equal.
 */
export function compareDottedVersions(v1: string, v2: string): number {
  if (typeof v1 !== 'string' || !DOTTED_VERSION_REGEX.test(v1.trim())) {
    throw new SecurityError('INVALID_VERSION_FORMAT', 400);
  }
  if (typeof v2 !== 'string' || !DOTTED_VERSION_REGEX.test(v2.trim())) {
    throw new SecurityError('INVALID_VERSION_FORMAT', 400);
  }

  const parts1 = v1.trim().split('.').map((p) => BigInt(p));
  const parts2 = v2.trim().split('.').map((p) => BigInt(p));
  const maxLen = Math.max(parts1.length, parts2.length);

  for (let i = 0; i < maxLen; i++) {
    const p1 = parts1[i] ?? 0n;
    const p2 = parts2[i] ?? 0n;
    if (p1 > p2) return 1;
    if (p1 < p2) return -1;
  }
  return 0;
}

/**
 * Extracts the 32-byte attestation nonce from Apple's custom X.509 extension:
 * SEQUENCE { [1] EXPLICIT OCTET STRING (32 bytes) }
 * Strictly enforces that the inner OCTET STRING is primitive (not constructed).
 */
export function extractAttestationNonce(extValue: Uint8Array): Buffer {
  try {
    const parsed = asn1js.fromBER(extValue, { maxDepth: 8, maxNodes: 32, maxContentLength: 1024 });
    if (parsed.offset !== extValue.byteLength || !(parsed.result instanceof asn1js.Sequence)) {
      throw new SecurityError('MALFORMED_ATTESTATION_NONCE_EXTENSION', 403);
    }
    const seqValues = parsed.result.valueBlock?.value;
    if (!Array.isArray(seqValues) || seqValues.length !== 1) {
      throw new SecurityError('MALFORMED_ATTESTATION_NONCE_EXTENSION', 403);
    }
    const explicitWrapper = seqValues[0];
    if (
      explicitWrapper.idBlock.tagClass !== 3 ||
      explicitWrapper.idBlock.tagNumber !== 1
    ) {
      throw new SecurityError('MALFORMED_ATTESTATION_NONCE_EXTENSION', 403);
    }
    const innerValues = (explicitWrapper as unknown as { valueBlock?: { value?: asn1js.AsnType[] } }).valueBlock?.value;
    if (!Array.isArray(innerValues) || innerValues.length !== 1) {
      throw new SecurityError('MALFORMED_ATTESTATION_NONCE_EXTENSION', 403);
    }
    const octetString = innerValues[0];
    if (!(octetString instanceof asn1js.OctetString)) {
      throw new SecurityError('MALFORMED_ATTESTATION_NONCE_EXTENSION', 403);
    }
    // Strict primitive OCTET STRING check
    if (octetString.idBlock.isConstructed) {
      throw new SecurityError('MALFORMED_ATTESTATION_NONCE_EXTENSION', 403);
    }
    const nonce = Buffer.from(octetString.valueBlock.valueHexView);
    if (nonce.length !== 32) {
      throw new SecurityError('MALFORMED_ATTESTATION_NONCE_EXTENSION', 403);
    }
    return nonce;
  } catch (err) {
    if (err instanceof SecurityError) throw err;
    throw new SecurityError('MALFORMED_ATTESTATION_NONCE_EXTENSION', 403);
  }
}

/**
 * Validates 2026 Apple Extensions according to provider configuration:
 * - apple_validation_category_01: bounded known uint32 (1..6). 0 and >= 7 rejected.
 * - apple_bundle_version_01: dotted numeric string.
 * - requireAppProperties: enforces presence of both extensions.
 * - allowedValidationCategories: enforces presence and allowlist membership.
 * - minimumBundleVersion: enforces presence and version >= minimum.
 */
export function parseAndValidateAppProperties(
  extMap: Map<unknown, unknown> | undefined,
  options: {
    requireAppProperties: boolean;
    allowedValidationCategories?: Set<number>;
    minimumBundleVersion?: string;
  }
): AppProperties {
  let validationCategory: number | undefined;
  let bundleVersion: string | undefined;

  if (extMap instanceof Map) {
    const rawCat = extMap.get('apple_validation_category_01');
    if (rawCat !== undefined) {
      if (Buffer.isBuffer(rawCat) && rawCat.length === 4) {
        validationCategory = rawCat.readUInt32LE(0);
      } else if (typeof rawCat === 'number' && Number.isInteger(rawCat) && rawCat >= 0 && rawCat <= 0xffffffff) {
        validationCategory = rawCat;
      } else {
        throw new SecurityError('INVALID_VALIDATION_CATEGORY_EXTENSION', 400);
      }
      // Rejection of invalid 0 and reserved categories >= 7 even without configured allowlist
      if (validationCategory === 0 || validationCategory >= 7) {
        throw new SecurityError('INVALID_VALIDATION_CATEGORY', 400);
      }
    }

    const rawVer = extMap.get('apple_bundle_version_01');
    if (rawVer !== undefined) {
      if (typeof rawVer === 'string' && DOTTED_VERSION_REGEX.test(rawVer.trim())) {
        bundleVersion = rawVer.trim();
      } else {
        throw new SecurityError('INVALID_BUNDLE_VERSION_EXTENSION', 400);
      }
    }
  }

  // 1. requireAppProperties enforcement
  if (options.requireAppProperties) {
    if (validationCategory === undefined || bundleVersion === undefined) {
      throw new SecurityError('MISSING_APP_PROPERTIES', 403);
    }
  }

  // 2. allowedValidationCategories enforcement
  if (options.allowedValidationCategories !== undefined) {
    if (validationCategory === undefined) {
      throw new SecurityError('MISSING_VALIDATION_CATEGORY', 403);
    }
    if (!options.allowedValidationCategories.has(validationCategory)) {
      throw new SecurityError('VALIDATION_CATEGORY_NOT_ALLOWED', 403);
    }
  }

  // 3. minimumBundleVersion enforcement
  if (options.minimumBundleVersion !== undefined) {
    if (bundleVersion === undefined) {
      throw new SecurityError('MISSING_BUNDLE_VERSION', 403);
    }
    if (compareDottedVersions(bundleVersion, options.minimumBundleVersion) < 0) {
      throw new SecurityError('BUNDLE_VERSION_TOO_LOW', 403);
    }
  }

  return { validationCategory, bundleVersion };
}

export class IOSSecurityProvider implements DeviceSecurityProvider {
  public readonly platform: Platform = 'ios';

  private readonly trustAnchors: string[];
  private readonly appId: string;
  private readonly rpIdHash: Buffer;
  private readonly environment: 'production' | 'development';
  private readonly receiptVerifier: ReceiptVerifier;
  private readonly now: () => number;
  private readonly minimumBundleVersion?: string;
  private readonly allowedValidationCategories?: Set<number>;
  private readonly requireAppProperties: boolean;

  constructor(options: IOSSecurityProviderOptions) {
    if (!options || typeof options !== 'object') {
      throw new SecurityError('INVALID_PROVIDER_OPTIONS', 500);
    }

    if (!options.appId || typeof options.appId !== 'string' || options.appId.trim().length === 0) {
      throw new SecurityError('INVALID_APP_ID', 500);
    }
    this.appId = options.appId.trim();
    this.rpIdHash = crypto.createHash('sha256').update(this.appId, 'utf8').digest();

    if (options.trustAnchors !== undefined) {
      if (!Array.isArray(options.trustAnchors) || options.trustAnchors.length === 0) {
        throw new SecurityError('EMPTY_TRUST_ANCHORS', 500);
      }
      for (const anchor of options.trustAnchors) {
        if (typeof anchor !== 'string' || anchor.trim().length === 0) {
          throw new SecurityError('INVALID_TRUST_ANCHOR', 500);
        }
      }
      this.trustAnchors = [...options.trustAnchors];
    } else {
      this.trustAnchors = [...APPLE_APP_ATTESTATION_ROOTS];
    }

    if (options.environment !== undefined) {
      if (options.environment !== 'production' && options.environment !== 'development') {
        throw new SecurityError('INVALID_ENVIRONMENT', 500);
      }
      this.environment = options.environment;
    } else {
      this.environment = 'production';
    }

    this.now = options.now ?? Date.now;
    if (typeof this.now !== 'function') {
      throw new SecurityError('INVALID_NOW_FUNCTION', 500);
    }

    this.receiptVerifier =
      options.receiptVerifier ??
      new AppleReceiptVerifier({ trustAnchors: undefined, now: this.now });
    if (!this.receiptVerifier || typeof this.receiptVerifier.verify !== 'function') {
      throw new SecurityError('INVALID_RECEIPT_VERIFIER', 500);
    }

    if (options.minimumBundleVersion !== undefined) {
      if (
        typeof options.minimumBundleVersion !== 'string' ||
        !DOTTED_VERSION_REGEX.test(options.minimumBundleVersion.trim())
      ) {
        throw new SecurityError('INVALID_MINIMUM_BUNDLE_VERSION', 500);
      }
      this.minimumBundleVersion = options.minimumBundleVersion.trim();
    }

    if (options.allowedValidationCategories !== undefined) {
      if (!Array.isArray(options.allowedValidationCategories)) {
        throw new SecurityError('INVALID_ALLOWED_VALIDATION_CATEGORIES', 500);
      }
      const catSet = new Set<number>();
      for (const cat of options.allowedValidationCategories) {
        if (!Number.isInteger(cat) || cat <= 0 || cat >= 7) {
          throw new SecurityError('INVALID_ALLOWED_VALIDATION_CATEGORIES', 500);
        }
        catSet.add(cat);
      }
      this.allowedValidationCategories = catSet;
    }

    this.requireAppProperties = options.requireAppProperties ?? false;
  }

  public async verifyRegistration(
    input: RegistrationInput,
    context: { challenge: Buffer }
  ): Promise<VerifiedRegistration> {
    if (!input || typeof input !== 'object') {
      throw new SecurityError('INVALID_REGISTRATION_INPUT', 400);
    }

    if (typeof input.attestationObject !== 'string' || input.attestationObject.length === 0) {
      throw new SecurityError('MISSING_ATTESTATION_OBJECT', 400);
    }
    if (input.attestationObject.length > Math.ceil(256 * 1024 / 3) * 4) {
      throw new SecurityError('ATTESTATION_OBJECT_TOO_LARGE', 400);
    }

    if (!BASE64_REGEX.test(input.attestationObject)) {
      throw new SecurityError('INVALID_BASE64_ATTESTATION_OBJECT', 400);
    }

    const attestationBuffer = Buffer.from(input.attestationObject, 'base64');
    if (attestationBuffer.toString('base64') !== input.attestationObject) {
      throw new SecurityError('NON_CANONICAL_BASE64_ATTESTATION_OBJECT', 400);
    }

    if (attestationBuffer.length > 256 * 1024) {
      throw new SecurityError('ATTESTATION_OBJECT_TOO_LARGE', 400);
    }

    // keyId MUST be supplied as canonical base64 exact 32 bytes
    if (typeof input.keyId !== 'string' || input.keyId.length === 0) {
      throw new SecurityError('MISSING_KEY_ID', 400);
    }
    if (!BASE64_REGEX.test(input.keyId)) {
      throw new SecurityError('INVALID_BASE64_KEY_ID', 400);
    }
    const inputKeyIdBytes = Buffer.from(input.keyId, 'base64');
    if (inputKeyIdBytes.toString('base64') !== input.keyId || inputKeyIdBytes.length !== 32) {
      throw new SecurityError('INVALID_KEY_ID_FORMAT', 400);
    }

    if (!context || !Buffer.isBuffer(context.challenge) || context.challenge.length === 0) {
      throw new SecurityError('MISSING_CHALLENGE', 400);
    }

    // 1. Decode CBOR attestation object
    const attObj = validateAndDecodeCBOR<Map<string, unknown>>(attestationBuffer, {
      maxBytes: 256 * 1024,
    });
    if (!(attObj instanceof Map)) {
      throw new SecurityError('INVALID_ATTESTATION_FORMAT', 400);
    }

    const fmt = attObj.get('fmt');
    if (fmt !== 'apple-appattest') {
      throw new SecurityError('INVALID_ATTESTATION_FORMAT', 400);
    }

    const attStmt = attObj.get('attStmt');
    if (!(attStmt instanceof Map)) {
      throw new SecurityError('MISSING_ATTESTATION_STATEMENT', 400);
    }

    const authData = attObj.get('authData');
    if (!Buffer.isBuffer(authData) || authData.length < 55) {
      throw new SecurityError('INVALID_AUTHENTICATOR_DATA', 400);
    }

    // 2. Validate attStmt certificates and receipt
    const x5c = attStmt.get('x5c');
    if (!Array.isArray(x5c) || x5c.length === 0) {
      throw new SecurityError('MISSING_CERTIFICATE_CHAIN', 400);
    }
    if (x5c.length > 10) {
      throw new SecurityError('CERTIFICATE_CHAIN_TOO_LARGE', 400);
    }

    const chainInputs: string[] = [];
    for (const certItem of x5c) {
      if (!Buffer.isBuffer(certItem)) {
        throw new SecurityError('INVALID_CERTIFICATE_IN_CHAIN', 400);
      }
      chainInputs.push(certItem.toString('base64'));
    }

    // Apple App Attest x5c usually includes leaf + intermediate CA, omitting the Root CA.
    // If the last cert in x5c is not self-signed, choose matching root from trustAnchors by verifying signature.
    const lastCertDer = x5c[x5c.length - 1] as Buffer;
    let lastCertNode: X509Certificate;
    try {
      lastCertNode = new X509Certificate(lastCertDer);
    } catch {
      throw new SecurityError('INVALID_CERTIFICATE', 400);
    }

    if (lastCertNode.subject !== lastCertNode.issuer) {
      let matchedAnchor: string | undefined;
      for (const anchorPem of this.trustAnchors) {
        try {
          const anchorCert = new X509Certificate(anchorPem);
          if (anchorCert.subject === lastCertNode.issuer && lastCertNode.verify(anchorCert.publicKey)) {
            matchedAnchor = anchorPem;
            break;
          }
        } catch {
          // Continue to next anchor
        }
      }
      // If no matching anchor was found cryptographically, append first anchor so validation fails closed
      chainInputs.push(matchedAnchor ?? this.trustAnchors[0]);
    }

    const receipt = attStmt.get('receipt');
    if (!Buffer.isBuffer(receipt) || receipt.length === 0 || receipt.length > 128 * 1024) {
      throw new SecurityError('MISSING_APP_ATTEST_RECEIPT', 400);
    }

    // 3. Strict X.509 chain verification
    const chainResult = validateCertificateChain(chainInputs, {
      trustAnchors: this.trustAnchors,
      profile: 'strict',
      understoodCriticalExtensions: new Set([APPLE_APP_ATTEST_NONCE_OID]),
      now: this.now(),
    });

    const leafCert = chainResult.leafCert;
    const leafPeculiarCert = chainResult.leafPeculiarCert;

    // 4. Extract and verify Apple App Attest Nonce extension
    const nonceExt = leafPeculiarCert.extensions.find(
      (e) => e.type === APPLE_APP_ATTEST_NONCE_OID
    );
    if (!nonceExt) {
      throw new SecurityError('MISSING_ATTESTATION_NONCE_EXTENSION', 403);
    }

    const nonceExtBytes = Buffer.from(nonceExt.value);
    const extractedNonce = extractAttestationNonce(nonceExtBytes);

    // Normative Apple App Attest nonce algorithm:
    // SHA256(authData || SHA256(challengeUTF8))
    const challengeHash = crypto.createHash('sha256').update(context.challenge).digest();
    const expectedNonce = crypto
      .createHash('sha256')
      .update(Buffer.concat([authData, challengeHash]))
      .digest();

    if (!crypto.timingSafeEqual(extractedNonce, expectedNonce)) {
      throw new SecurityError('ATTESTATION_CHALLENGE_MISMATCH', 403);
    }

    // 5. Attested leaf public key (EC P-256) and keyId derivation
    const leafKey = leafCert.publicKey;
    if (leafKey.asymmetricKeyType !== 'ec') {
      throw new SecurityError('ATTESTED_KEY_NOT_EC', 403);
    }
    const curve = leafKey.asymmetricKeyDetails?.namedCurve;
    if (curve !== 'prime256v1' && curve !== 'secp256r1' && curve !== 'p256') {
      throw new SecurityError('ATTESTED_KEY_NOT_P256', 403);
    }

    const leafSpkiDer = leafKey.export({ format: 'der', type: 'spki' });
    if (leafSpkiDer.length !== 91 || leafSpkiDer[26] !== 0x04) {
      throw new SecurityError('INVALID_PUBLIC_KEY_FORMAT', 400);
    }

    const leafPoint = leafSpkiDer.subarray(26); // 65 bytes uncompressed: 0x04 || X || Y
    const calculatedKeyIdBuf = crypto.createHash('sha256').update(leafPoint).digest();
    const calculatedKeyId = calculatedKeyIdBuf.toString('base64');

    if (!inputKeyIdBytes.equals(calculatedKeyIdBuf)) {
      throw new SecurityError('KEY_ID_MISMATCH', 400);
    }

    // 6. Authenticator Data checks
    // A. rpIdHash: SHA256(appId)
    const expectedRpIdHash = this.rpIdHash;
    if (!crypto.timingSafeEqual(authData.subarray(0, 32), expectedRpIdHash)) {
      throw new SecurityError('RP_ID_MISMATCH', 401);
    }

    // B. flags: AT flag (0x40) MUST be set in registration. No UP requirement.
    const flags = authData[32];
    if ((flags & 0x40) === 0) {
      throw new SecurityError('ATTESTED_CREDENTIAL_DATA_FLAG_MISSING', 400);
    }
    // Reject unsupported reserved flags: RFU bits 1, 3, 4, 5 (0x3A)
    if ((flags & 0x3a) !== 0) {
      throw new SecurityError('UNSUPPORTED_AUTHENTICATOR_FLAGS', 400);
    }

    const hasExtensionData = (flags & 0x80) !== 0;

    // C. signCount: 4 bytes uint32 BE must be 0 for registration
    const signCount = authData.readUInt32BE(33);
    if (signCount !== 0) {
      throw new SecurityError('INVALID_SIGN_COUNT', 400);
    }

    // D. aaguid: 16 bytes at 37..52
    const aaguid = authData.subarray(37, 53);
    const expectedAaguid =
      this.environment === 'development'
        ? Buffer.from('appattestdevelop', 'ascii')
        : Buffer.from('61707061747465737400000000000000', 'hex');

    if (!aaguid.equals(expectedAaguid)) {
      throw new SecurityError('AAGUID_MISMATCH', 403);
    }

    // E. credId: uint16 length at 53..54 must be 32, value must equal calculatedKeyIdBuf
    const credIdLen = authData.readUInt16BE(53);
    if (credIdLen !== 32) {
      throw new SecurityError('INVALID_CREDENTIAL_ID_LENGTH', 400);
    }
    const credId = authData.subarray(55, 87);
    if (!credId.equals(calculatedKeyIdBuf)) {
      throw new SecurityError('CREDENTIAL_ID_MISMATCH', 400);
    }

    // F. Remainder contains COSE Key followed by Extensions:
    // Registration items count: 1 if ED=0, 2 if ED=1; no third CBOR items, extensions must be Map
    const restAuthData = authData.subarray(87);
    if (restAuthData.length === 0) {
      throw new SecurityError('MISSING_COSE_KEY', 400);
    }

    const items = decodeMultipleBounded(restAuthData);
    const expectedItemCount = hasExtensionData ? 2 : 1;
    if (items.length !== expectedItemCount) {
      throw new SecurityError('UNEXPECTED_CBOR_ITEMS_IN_AUTHDATA', 400);
    }

    const coseKey = items[0];
    if (!(coseKey instanceof Map)) {
      throw new SecurityError('INVALID_COSE_KEY', 400);
    }

    const kty = coseKey.get(1);
    const alg = coseKey.get(3);
    const crv = coseKey.get(-1);
    const coseX = coseKey.get(-2);
    const coseY = coseKey.get(-3);

    if (kty !== 2) throw new SecurityError('INVALID_COSE_KTY', 400);
    if (alg !== -7) throw new SecurityError('INVALID_COSE_ALG', 400);
    if (crv !== 1) throw new SecurityError('INVALID_COSE_CRV', 400);
    if (!Buffer.isBuffer(coseX) || coseX.length !== 32) throw new SecurityError('INVALID_COSE_COORDINATES', 400);
    if (!Buffer.isBuffer(coseY) || coseY.length !== 32) throw new SecurityError('INVALID_COSE_COORDINATES', 400);

    const cosePoint = Buffer.concat([Buffer.from([0x04]), coseX, coseY]);
    if (!cosePoint.equals(leafPoint)) {
      throw new SecurityError('COSE_KEY_MISMATCH', 400);
    }

    // 7. Process 2026 Apple Extensions
    let extMap: Map<unknown, unknown> | undefined;
    if (hasExtensionData) {
      if (!(items[1] instanceof Map)) {
        throw new SecurityError('INVALID_EXTENSION_DATA', 400);
      }
      extMap = items[1] as Map<unknown, unknown>;
    }

    const { validationCategory, bundleVersion } = parseAndValidateAppProperties(extMap, {
      requireAppProperties: this.requireAppProperties,
      allowedValidationCategories: this.allowedValidationCategories,
      minimumBundleVersion: this.minimumBundleVersion,
    });

    // 8. Mandatory Receipt Verification
    const leafPublicKeyPem = exportSpkiPem(leafKey);
    const receiptResult = await this.receiptVerifier.verify(receipt, {
      appId: this.appId,
      publicKeyPem: leafPublicKeyPem,
    });

    return {
      publicKeyPem: leafPublicKeyPem,
      keyId: calculatedKeyId,
      signCount: 0,
      tier: 'hardware',
      metadata: {
        platform: 'ios',
        environment: this.environment,
        appId: this.appId,
        keyId: calculatedKeyId,
        receipt: receiptResult.receipt,
        receiptCreatedAt: receiptResult.receiptCreatedAt,
        ...(validationCategory !== undefined ? { validationCategory } : {}),
        ...(bundleVersion !== undefined ? { bundleVersion } : {}),
      },
    };
  }

  public async verifyRequest(
    device: DeviceRecord,
    proof: RequestProof
  ): Promise<{ signCount?: number }> {
    // 1. Device record and stored metadata validation
    if (!device || typeof device !== 'object') {
      throw new SecurityError('INVALID_DEVICE_RECORD', 401);
    }
    if (device.platform !== 'ios') {
      throw new SecurityError('DEVICE_PLATFORM_MISMATCH', 400);
    }
    if (device.metadata?.appId !== this.appId) {
      throw new SecurityError('APP_ID_MISMATCH', 403);
    }
    if (device.metadata?.environment !== this.environment) {
      throw new SecurityError('ENVIRONMENT_MISMATCH', 403);
    }
    if (
      typeof device.signCount !== 'number' ||
      !Number.isInteger(device.signCount) ||
      device.signCount < 0 ||
      device.signCount > 0xffffffff
    ) {
      throw new SecurityError('INVALID_STORED_SIGN_COUNT', 500);
    }

    // 2. Request proof validation
    if (!proof || typeof proof !== 'object') {
      throw new SecurityError('INVALID_REQUEST_PROOF', 401);
    }
    if (!proof.canonical || !Buffer.isBuffer(proof.canonical)) {
      throw new SecurityError('INVALID_CANONICAL_DATA', 401);
    }
    if (typeof proof.assertion !== 'string' || proof.assertion.length === 0) {
      throw new SecurityError('MISSING_ASSERTION', 401);
    }
    if (proof.assertion.length > Math.ceil(8192 / 3) * 4) throw new SecurityError('ASSERTION_TOO_LARGE', 401);
    if (!BASE64_REGEX.test(proof.assertion)) {
      throw new SecurityError('INVALID_BASE64_ASSERTION', 401);
    }

    const assertionBuf = Buffer.from(proof.assertion, 'base64');
    if (assertionBuf.toString('base64') !== proof.assertion) {
      throw new SecurityError('NON_CANONICAL_BASE64_ASSERTION', 401);
    }
    if (assertionBuf.length > 8192) {
      throw new SecurityError('ASSERTION_TOO_LARGE', 401);
    }

    // 3. Decode assertion CBOR
    const decodedAssertion = validateAndDecodeCBOR<Map<string, unknown>>(assertionBuf, {
      maxBytes: 8192,
    });
    if (!(decodedAssertion instanceof Map)) {
      throw new SecurityError('INVALID_ASSERTION_FORMAT', 401);
    }

    const signature = decodedAssertion.get('signature');
    const authenticatorData = decodedAssertion.get('authenticatorData');

    if (!Buffer.isBuffer(signature) || signature.length < 8 || signature.length > 72) {
      throw new SecurityError('INVALID_SIGNATURE_LENGTH', 401);
    }

    // Strict DER ECDSA sequence check: SEQUENCE { r INTEGER, s INTEGER }
    const parsedAsn = asn1js.fromBER(signature, {
      maxDepth: 4,
      maxNodes: 8,
      maxContentLength: 128,
    });
    if (parsedAsn.offset !== signature.byteLength || !(parsedAsn.result instanceof asn1js.Sequence)) {
      throw new SecurityError('MALFORMED_DER_SIGNATURE', 401);
    }
    const sigSeq = parsedAsn.result.valueBlock?.value;
    if (
      !Array.isArray(sigSeq) ||
      sigSeq.length !== 2 ||
      !(sigSeq[0] instanceof asn1js.Integer) ||
      !(sigSeq[1] instanceof asn1js.Integer)
    ) {
      throw new SecurityError('MALFORMED_DER_SIGNATURE', 401);
    }

    if (!Buffer.isBuffer(authenticatorData) || authenticatorData.length < 37) {
      throw new SecurityError('INVALID_AUTHENTICATOR_DATA', 401);
    }

    // Check rpIdHash: SHA256(appId)
    const expectedRpIdHash = this.rpIdHash;
    if (!crypto.timingSafeEqual(authenticatorData.subarray(0, 32), expectedRpIdHash)) {
      throw new SecurityError('RP_ID_MISMATCH', 401);
    }

    // Check flags: AT flag (0x40) must NOT be set in assertions.
    // Reserved flags (0x02, 0x08, 0x10, 0x20) must NOT be set.
    // Allowed: UP (0x01), UV (0x04), ED (0x80)
    const flags = authenticatorData[32];
    if ((flags & 0x7a) !== 0) {
      if ((flags & 0x40) !== 0) {
        throw new SecurityError('UNEXPECTED_ATTESTED_CREDENTIAL_DATA', 401);
      }
      throw new SecurityError('UNSUPPORTED_AUTHENTICATOR_FLAGS', 401);
    }

    const hasExtensionData = (flags & 0x80) !== 0;

    // assertion authData length must be 37 if ED is 0
    if (!hasExtensionData && authenticatorData.length !== 37) {
      throw new SecurityError('INVALID_AUTHENTICATOR_DATA_LENGTH', 401);
    }

    // If ED is set, parse exactly one bounded CBOR extension Map after 37
    let assertExtMap: Map<unknown, unknown> | undefined;
    if (hasExtensionData) {
      if (authenticatorData.length <= 37) {
        throw new SecurityError('MISSING_EXTENSION_DATA', 401);
      }
      const assertExts = decodeMultipleBounded(authenticatorData.subarray(37));
      if (assertExts.length !== 1 || !(assertExts[0] instanceof Map)) {
        throw new SecurityError('INVALID_EXTENSION_DATA', 401);
      }
      assertExtMap = assertExts[0] as Map<unknown, unknown>;
    }

    // Apply same category/version/requireAppProperties rules as registration
    parseAndValidateAppProperties(assertExtMap, {
      requireAppProperties: this.requireAppProperties,
      allowedValidationCategories: this.allowedValidationCategories,
      minimumBundleVersion: this.minimumBundleVersion,
    });

    // Strictly monotonic signCount verification against validated stored signCount
    const counter = authenticatorData.readUInt32BE(33);
    if (counter <= device.signCount) {
      throw new SecurityError('SIGN_COUNT_NOT_INCREASED', 401);
    }

    // Signature verification over single composite hash:
    // crypto.verify('sha256', concat(authenticatorData, SHA256(canonical)), key, signature)
    const keyObject = getP256Key(device.publicKeyPem);
    const clientDataHash = crypto.createHash('sha256').update(proof.canonical).digest();
    const composite = Buffer.concat([authenticatorData, clientDataHash]);

    let valid = false;
    try {
      valid = crypto.verify('sha256', composite, keyObject, signature);
    } catch {
      throw new SecurityError('INVALID_SIGNATURE', 401);
    }

    if (!valid) {
      throw new SecurityError('INVALID_SIGNATURE', 401);
    }

    return { signCount: counter };
  }
}
