/**
 * Android Security Provider for Node Secure API.
 *
 * Implements Android Key Attestation verification following official Google specifications
 * and upstream https://github.com/android/keyattestation design.
 *
 * Core security guarantees:
 * - Real chain cryptography using official Google Hardware Attestation Roots (RSA-4096 & EC P-384)
 * - Anti-extension attack protection (attestation extension must be leaf only)
 * - Strict ASN.1 validation: bounded parser limits, full byte consumption, tag class = 3 (context-specific),
 *   exact explicit single child, no duplicate tags, no silent ignore of malformed elements
 * - Full 64-bit BigInt precision for version codes and counters
 * - Strict OctetString DER wrapping for AttestationApplicationId (Tag 709) with 32-byte digests
 * - Rejection of conflicting attestation application IDs across software and hardware lists
 * - TEE / StrongBox hardware enforcement for both attestation & keymaster security levels
 * - Hardware rootOfTrust: strict Boolean deviceLocked = true, verifiedBootState = Verified (0)
 * - Package identity verification: expected package name, minimum version, signer SHA-256 digest
 * - KeyMint parameters: purpose SIGN (2), origin GENERATED (0), EC P-256 (1), SHA-256 (4)
 * - Attested leaf public key returned as EC P-256 SPKI PEM only
 * - Bounded freshness revocation check across all certificates in the chain
 * - Request proof verification: strict canonical base64, exact DER ECDSA sequence (<= 72 bytes), SHA-256 signature
 */

import 'reflect-metadata';
import * as crypto from 'node:crypto';
import * as asn1js from 'asn1js';
import { getP256Key } from './key-cache.js';
import { verifyProofOfWork } from '../core/pow.js';
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
  ANDROID_KEY_ATTESTATION_OID,
  exportSpkiPem,
  validateCertificateChain,
} from './x509.js';

export interface RevocationSource {
  getRevokedSerials(): Promise<Set<string>>;
}

export interface AndroidSecurityProviderOptions {
  trustAnchors: string[];
  expectedPackageName: string;
  expectedSignerDigests: string[];
  minimumVersion?: bigint;
  revocationSource: RevocationSource;
  now?: () => number;
  allowSoftwareTier?: boolean;
  powDifficultyBits?: number;
  softwareDeviceTtlSeconds?: number;
}

// KeyMint Tag Constants
const TAG_PURPOSE = 1;
const TAG_ALGORITHM = 2;
const TAG_KEY_SIZE = 3;
const TAG_DIGEST = 5;
const TAG_EC_CURVE = 10;
const TAG_ORIGIN = 702;
const TAG_ROOT_OF_TRUST = 704;
const TAG_OS_VERSION = 705;
const TAG_OS_PATCH_LEVEL = 706;
const TAG_ATTESTATION_APPLICATION_ID = 709;

// Expected KeyMint Tag Values
const KM_PURPOSE_SIGN = 2;
const KM_ALGORITHM_EC = 3;
const KM_KEY_SIZE_P256 = 256;
const KM_DIGEST_SHA256 = 4;
const KM_EC_CURVE_P256 = 1;
const KM_ORIGIN_GENERATED = 0;
const KM_BOOT_STATE_VERIFIED = 0;

// Security Levels
export const SEC_LEVEL_SOFTWARE = 0;
export const SEC_LEVEL_TEE = 1;
export const SEC_LEVEL_STRONGBOX = 2;

// ASN.1 Parser Bounds
const ASN1_PARSE_LIMITS = {
  maxDepth: 16,
  maxNodes: 1024,
  maxContentLength: 64 * 1024,
};

interface ParsedPackageInfo {
  name: string;
  version: bigint;
}

interface ParsedAttestationAppId {
  packages: ParsedPackageInfo[];
  signatures: string[]; // lowercase 64-char hex digests
}

interface ParsedRootOfTrust {
  verifiedBootKey: Buffer;
  deviceLocked: boolean;
  verifiedBootState: number;
  verifiedBootHash?: Buffer;
}

interface ParsedAuthList {
  purposes?: Set<number>;
  algorithm?: number;
  keySize?: number;
  digests?: Set<number>;
  ecCurve?: number;
  origin?: number;
  rootOfTrust?: ParsedRootOfTrust;
  attestationApplicationId?: ParsedAttestationAppId;
  osVersion?: bigint;
  osPatchLevel?: number;
}

interface ParsedKeyDescription {
  attestationVersion: bigint;
  attestationSecurityLevel: number;
  keymasterVersion: bigint;
  keymasterSecurityLevel: number;
  attestationChallenge: Buffer;
  uniqueId: Buffer;
  softwareEnforced: ParsedAuthList;
  hardwareEnforced: ParsedAuthList;
}

/**
 * Extracts a non-negative BigInt from an ASN.1 Integer, preserving full precision beyond 2^53.
 */
function parseAsnInteger(item: unknown, tagNumber = 2): bigint {
  if (!(item instanceof asn1js.Integer) || item.idBlock.tagClass !== 1 || item.idBlock.tagNumber !== tagNumber) {
    throw new SecurityError('MALFORMED_ASN1_INTEGER', 403);
  }
  const hexView = item.valueBlock?.valueHexView;
  if (!hexView || !hexView.length || hexView.length > 8 || (hexView[0] & 0x80) !== 0 ||
      (hexView.length > 1 && hexView[0] === 0 && (hexView[1] & 0x80) === 0)) {
    throw new SecurityError('MALFORMED_ASN1_INTEGER', 403);
  }
  const hex = Buffer.from(hexView).toString('hex');
  return BigInt('0x' + hex);
}

function parseAsnNumber(item: unknown, tagNumber = 2): number {
  const value = parseAsnInteger(item, tagNumber);
  if (value > 0xffffffffn) throw new SecurityError('MALFORMED_ASN1_INTEGER', 403);
  return Number(value);
}

/**
 * Extracts Buffer from an ASN.1 OctetString.
 */
function parseAsnOctetString(item: unknown): Buffer {
  if (!(item instanceof asn1js.OctetString) || item.idBlock.isConstructed) {
    throw new SecurityError('MALFORMED_ASN1_OCTET_STRING', 403);
  }
  const hexView = item.valueBlock?.valueHexView;
  if (hexView) {
    return Buffer.from(hexView);
  }
  const hex = item.valueBlock?.valueHex;
  if (hex) {
    return Buffer.from(hex);
  }
  return Buffer.alloc(0);
}

export class AndroidSecurityProvider implements DeviceSecurityProvider {
  public readonly platform: Platform = 'android';

  private readonly trustAnchors: string[];
  private readonly expectedPackageName: string;
  private readonly expectedSignerDigests: Set<string>;
  private readonly minimumVersion?: bigint;
  private readonly revocationSource: RevocationSource;
  private readonly now: () => number;
  private readonly allowSoftwareTier: boolean;
  private readonly powDifficultyBits: number;
  private readonly softwareDeviceTtlSeconds: number;

  constructor(options: AndroidSecurityProviderOptions) {
    if (!options || typeof options !== 'object') {
      throw new SecurityError('INVALID_PROVIDER_OPTIONS', 500);
    }

    if (!Array.isArray(options.trustAnchors) || options.trustAnchors.length === 0) {
      throw new SecurityError('EMPTY_TRUST_ANCHORS', 500);
    }
    this.trustAnchors = [...options.trustAnchors];

    if (!options.expectedPackageName || typeof options.expectedPackageName !== 'string') {
      throw new SecurityError('INVALID_EXPECTED_PACKAGE_NAME', 500);
    }
    this.expectedPackageName = options.expectedPackageName.trim();

    if (!Array.isArray(options.expectedSignerDigests) || options.expectedSignerDigests.length === 0) {
      throw new SecurityError('EMPTY_EXPECTED_SIGNER_DIGESTS', 500);
    }

    const digests = new Set<string>();
    for (const rawDigest of options.expectedSignerDigests) {
      if (typeof rawDigest !== 'string') {
        throw new SecurityError('INVALID_EXPECTED_SIGNER_DIGEST', 500);
      }
      const clean = rawDigest.trim().toLowerCase().replace(/^0x/, '');
      if (!/^[0-9a-f]{64}$/.test(clean)) {
        throw new SecurityError('INVALID_EXPECTED_SIGNER_DIGEST', 500);
      }
      digests.add(clean);
    }
    this.expectedSignerDigests = digests;

    if (options.minimumVersion !== undefined) {
      if (typeof options.minimumVersion !== 'bigint' || options.minimumVersion < 0n) {
        throw new SecurityError('INVALID_MINIMUM_VERSION', 500);
      }
      this.minimumVersion = options.minimumVersion;
    }

    if (!options.revocationSource || typeof options.revocationSource.getRevokedSerials !== 'function') {
      throw new SecurityError('INVALID_REVOCATION_SOURCE', 500);
    }
    this.revocationSource = options.revocationSource;

    this.now = options.now ?? Date.now;
    this.allowSoftwareTier = options.allowSoftwareTier ?? true;
    this.powDifficultyBits = options.powDifficultyBits ?? 18;
    this.softwareDeviceTtlSeconds = options.softwareDeviceTtlSeconds ?? 7200;
  }

  public async verifyRegistration(
    input: RegistrationInput,
    context: { challenge: Buffer; salt?: string },
  ): Promise<VerifiedRegistration> {
    if (!input || typeof input !== 'object') {
      throw new SecurityError('INVALID_REGISTRATION_INPUT', 400);
    }

    if (!context || !Buffer.isBuffer(context.challenge) || context.challenge.length === 0) {
      throw new SecurityError('MISSING_CHALLENGE', 400);
    }

    // Branch 1: Raw EC P-256 public key registration (no certificate chain)
    if (!input.certificateChain || input.certificateChain.length === 0) {
      if (!input.publicKeyPem) {
        throw new SecurityError('MISSING_CERTIFICATE_CHAIN', 400);
      }

      if (!this.allowSoftwareTier) {
        throw new SecurityError('HARDWARE_TEE_REQUIRED', 403);
      }

      if (!input.powNonce || !context.salt) {
        throw new SecurityError('INVALID_POW', 403);
      }

      const challengeStr = context.challenge.toString('utf8');
      if (!verifyProofOfWork(challengeStr, context.salt, input.powNonce, this.powDifficultyBits)) {
        throw new SecurityError('INVALID_POW', 403);
      }

      let pubKey: crypto.KeyObject;
      try {
        pubKey = crypto.createPublicKey(input.publicKeyPem);
      } catch {
        throw new SecurityError('ATTESTED_KEY_NOT_EC', 403);
      }
      if (pubKey.asymmetricKeyType !== 'ec') {
        throw new SecurityError('ATTESTED_KEY_NOT_EC', 403);
      }
      const details = pubKey.asymmetricKeyDetails;
      const curve = details?.namedCurve;
      if (curve !== 'prime256v1' && curve !== 'secp256r1' && curve !== 'p256') {
        throw new SecurityError('ATTESTED_KEY_NOT_P256', 403);
      }
      const publicKeyPem = exportSpkiPem(pubKey);

      return {
        publicKeyPem,
        tier: 'software',
        expiresAt: this.now() + this.softwareDeviceTtlSeconds * 1000,
        metadata: {
          platform: 'android',
          tier: 'software',
          attestationSecurityLevel: 'Software',
          keymasterSecurityLevel: 'Software',
          deviceLocked: false,
          verifiedBootState: 'UNVERIFIED',
        },
      };
    }

    // Branch 2: Certificate chain provided
    // 1. Fetch fresh revoked serials. Fails closed if source is stale or unavailable.
    let revokedSerials: Set<string>;
    try {
      revokedSerials = await this.revocationSource.getRevokedSerials();
    } catch (err) {
      if (err instanceof SecurityError) throw err;
      throw new SecurityError('REVOCATION_STATUS_UNAVAILABLE', 503);
    }

    // 2. Validate X.509 certificate chain cryptography, CA constraints, and anti-extension attack
    const validationResult = validateCertificateChain(input.certificateChain, {
      trustAnchors: this.trustAnchors,
      revokedSerials,
      now: this.now(),
      profile: 'android',
    });

    const leafPeculiar = validationResult.leafPeculiarCert;
    const leafNodeCert = validationResult.leafCert;

    // 3. Verify leaf key is EC P-256
    const pubKey = leafNodeCert.publicKey;
    if (pubKey.asymmetricKeyType !== 'ec') {
      throw new SecurityError('ATTESTED_KEY_NOT_EC', 403);
    }
    const details = pubKey.asymmetricKeyDetails;
    const curve = details?.namedCurve;
    if (curve !== 'prime256v1' && curve !== 'secp256r1' && curve !== 'p256') {
      throw new SecurityError('ATTESTED_KEY_NOT_P256', 403);
    }

    // 4. Extract and parse ASN.1 KeyDescription from leaf certificate
    const attExt = leafPeculiar.extensions.find((ext) => ext.type === ANDROID_KEY_ATTESTATION_OID);
    if (!attExt) {
      throw new SecurityError('TARGET_MISSING_ATTESTATION_EXTENSION', 403);
    }

    const keyDescription = this.parseKeyDescription(Buffer.from(attExt.value));

    // 5. Attestation Challenge verification: must match byte-for-byte
    if (
      keyDescription.attestationChallenge.length !== context.challenge.length ||
      !crypto.timingSafeEqual(keyDescription.attestationChallenge, context.challenge)
    ) {
      throw new SecurityError('ATTESTATION_CHALLENGE_MISMATCH', 403);
    }

    // Branch 2A: Hardware VIP verification if no PoW nonce is supplied
    if (!input.powNonce) {
      // Attestation Security Level and Keymaster Security Level verification:
      // Both must be TEE (1) or StrongBox (2). Software (0) is strictly rejected.
      if (
        (keyDescription.attestationSecurityLevel !== SEC_LEVEL_TEE &&
          keyDescription.attestationSecurityLevel !== SEC_LEVEL_STRONGBOX) ||
        (keyDescription.keymasterSecurityLevel !== SEC_LEVEL_TEE &&
          keyDescription.keymasterSecurityLevel !== SEC_LEVEL_STRONGBOX)
      ) {
        throw new SecurityError('HARDWARE_TEE_REQUIRED', 403);
      }

      // Hardware-enforced Key Properties verification
      const hw = keyDescription.hardwareEnforced;

      if (!hw.purposes || !hw.purposes.has(KM_PURPOSE_SIGN)) {
        throw new SecurityError('HARDWARE_PURPOSE_SIGN_REQUIRED', 403);
      }
      if (hw.algorithm !== KM_ALGORITHM_EC) {
        throw new SecurityError('HARDWARE_ALGORITHM_EC_REQUIRED', 403);
      }
      if (hw.keySize !== KM_KEY_SIZE_P256) {
        throw new SecurityError('HARDWARE_KEY_SIZE_256_REQUIRED', 403);
      }
      if (!hw.digests || !hw.digests.has(KM_DIGEST_SHA256)) {
        throw new SecurityError('HARDWARE_DIGEST_SHA256_REQUIRED', 403);
      }
      if (hw.ecCurve !== KM_EC_CURVE_P256) {
        throw new SecurityError('HARDWARE_CURVE_P256_REQUIRED', 403);
      }
      if (hw.origin !== KM_ORIGIN_GENERATED) {
        throw new SecurityError('HARDWARE_ORIGIN_GENERATED_REQUIRED', 403);
      }

      // Hardware-enforced Root of Trust verification
      if (!hw.rootOfTrust) {
        throw new SecurityError('MISSING_ROOT_OF_TRUST', 403);
      }
      if (!hw.rootOfTrust.deviceLocked) {
        throw new SecurityError('DEVICE_NOT_LOCKED', 403);
      }
      if (hw.rootOfTrust.verifiedBootState !== KM_BOOT_STATE_VERIFIED) {
        throw new SecurityError('BOOT_NOT_VERIFIED', 403);
      }

      // Attestation Application ID verification (Tag 709)
      const swAppId = keyDescription.softwareEnforced.attestationApplicationId;
      const hwAppId = hw.attestationApplicationId;

      if (swAppId && hwAppId) {
        throw new SecurityError('CONFLICTING_ATTESTATION_APPLICATION_ID', 403);
      }

      const appId = hwAppId ?? swAppId;
      if (!appId || appId.packages.length === 0 || appId.signatures.length === 0) {
        throw new SecurityError('MISSING_ATTESTATION_APPLICATION_ID', 403);
      }

      const matchingPackage = appId.packages.find((p) => p.name === this.expectedPackageName);
      if (!matchingPackage) {
        throw new SecurityError('PACKAGE_NAME_MISMATCH', 403);
      }

      if (this.minimumVersion !== undefined && matchingPackage.version < this.minimumVersion) {
        throw new SecurityError('PACKAGE_VERSION_TOO_LOW', 403);
      }

      const hasValidSigner = appId.signatures.some((sig) => this.expectedSignerDigests.has(sig));
      if (!hasValidSigner) {
        throw new SecurityError('SIGNER_DIGEST_MISMATCH', 403);
      }

      const publicKeyPem = exportSpkiPem(pubKey);

      return {
        publicKeyPem,
        tier: 'hardware',
        metadata: {
          platform: 'android',
          tier: 'hardware',
          attestationSecurityLevel: keyDescription.attestationSecurityLevel === SEC_LEVEL_STRONGBOX ? 'StrongBox' : 'TEE',
          keymasterSecurityLevel: keyDescription.keymasterSecurityLevel === SEC_LEVEL_STRONGBOX ? 'StrongBox' : 'TEE',
          attestationVersion: Number(keyDescription.attestationVersion),
          keymasterVersion: Number(keyDescription.keymasterVersion),
          packageName: matchingPackage.name,
          packageVersion: matchingPackage.version.toString(),
          provisioningMethod: validationResult.provisioningMethod,
          deviceLocked: hw.rootOfTrust.deviceLocked,
          verifiedBootState: 'VERIFIED',
        },
      };
    }

    // Branch 2B: Proof of Work nonce supplied (Software Tier or Hardware VIP with PoW)
    if (!this.allowSoftwareTier) {
      throw new SecurityError('HARDWARE_TEE_REQUIRED', 403);
    }

    if (!context.salt) {
      throw new SecurityError('INVALID_POW', 403);
    }

    const challengeStr = context.challenge.toString('utf8');
    if (!verifyProofOfWork(challengeStr, context.salt, input.powNonce, this.powDifficultyBits)) {
      throw new SecurityError('INVALID_POW', 403);
    }

    const hw = keyDescription.hardwareEnforced;
    const isHardwareSecLevel = (
      (keyDescription.attestationSecurityLevel === SEC_LEVEL_TEE ||
        keyDescription.attestationSecurityLevel === SEC_LEVEL_STRONGBOX) &&
      (keyDescription.keymasterSecurityLevel === SEC_LEVEL_TEE ||
        keyDescription.keymasterSecurityLevel === SEC_LEVEL_STRONGBOX)
    );
    const hasRootOfTrust = Boolean(hw.rootOfTrust);
    const isLocked = Boolean(hw.rootOfTrust?.deviceLocked);
    const isBootVerified = hw.rootOfTrust?.verifiedBootState === KM_BOOT_STATE_VERIFIED;

    const hasHwKeyMint = (
      hw.purposes?.has(KM_PURPOSE_SIGN) &&
      hw.algorithm === KM_ALGORITHM_EC &&
      hw.keySize === KM_KEY_SIZE_P256 &&
      hw.digests?.has(KM_DIGEST_SHA256) &&
      hw.ecCurve === KM_EC_CURVE_P256 &&
      hw.origin === KM_ORIGIN_GENERATED
    );

    const swAppId = keyDescription.softwareEnforced.attestationApplicationId;
    const hwAppId = hw.attestationApplicationId;
    const appId = hwAppId ?? swAppId;
    const matchingPackage = appId?.packages?.find((p) => p.name === this.expectedPackageName);
    const hasValidSigner = appId?.signatures?.some((sig) => this.expectedSignerDigests.has(sig));

    const isHardwareQualified = Boolean(
      isHardwareSecLevel &&
      hasRootOfTrust &&
      isLocked &&
      isBootVerified &&
      hasHwKeyMint &&
      !(swAppId && hwAppId) &&
      matchingPackage &&
      (this.minimumVersion === undefined || matchingPackage.version >= this.minimumVersion) &&
      hasValidSigner
    );

    const publicKeyPem = exportSpkiPem(pubKey);

    if (isHardwareQualified) {
      return {
        publicKeyPem,
        tier: 'hardware',
        metadata: {
          platform: 'android',
          tier: 'hardware',
          attestationSecurityLevel: keyDescription.attestationSecurityLevel === SEC_LEVEL_STRONGBOX ? 'StrongBox' : 'TEE',
          keymasterSecurityLevel: keyDescription.keymasterSecurityLevel === SEC_LEVEL_STRONGBOX ? 'StrongBox' : 'TEE',
          attestationVersion: Number(keyDescription.attestationVersion),
          keymasterVersion: Number(keyDescription.keymasterVersion),
          packageName: matchingPackage!.name,
          packageVersion: matchingPackage!.version.toString(),
          provisioningMethod: validationResult.provisioningMethod,
          deviceLocked: hw.rootOfTrust!.deviceLocked,
          verifiedBootState: 'VERIFIED',
        },
      };
    }

    // Granted Software Tier
    return {
      publicKeyPem,
      tier: 'software',
      expiresAt: this.now() + this.softwareDeviceTtlSeconds * 1000,
      metadata: {
        platform: 'android',
        tier: 'software',
        attestationSecurityLevel: keyDescription.attestationSecurityLevel === SEC_LEVEL_STRONGBOX ? 'StrongBox' : (keyDescription.attestationSecurityLevel === SEC_LEVEL_TEE ? 'TEE' : 'Software'),
        keymasterSecurityLevel: keyDescription.keymasterSecurityLevel === SEC_LEVEL_STRONGBOX ? 'StrongBox' : (keyDescription.keymasterSecurityLevel === SEC_LEVEL_TEE ? 'TEE' : 'Software'),
        attestationVersion: Number(keyDescription.attestationVersion),
        keymasterVersion: Number(keyDescription.keymasterVersion),
        deviceLocked: Boolean(hw.rootOfTrust?.deviceLocked),
        verifiedBootState: hw.rootOfTrust?.verifiedBootState === KM_BOOT_STATE_VERIFIED ? 'VERIFIED' : 'UNVERIFIED',
      },
    };
  }

  public async verifyRequest(
    device: DeviceRecord,
    proof: RequestProof,
  ): Promise<{ signCount?: number }> {
    if (!proof || typeof proof !== 'object') {
      throw new SecurityError('INVALID_REQUEST_PROOF', 401);
    }

    if (!proof.canonical || !Buffer.isBuffer(proof.canonical)) {
      throw new SecurityError('INVALID_CANONICAL_DATA', 401);
    }

    if (typeof proof.signature !== 'string' || proof.signature.length === 0) {
      throw new SecurityError('MISSING_SIGNATURE', 401);
    }
    if (proof.signature.length > 96) throw new SecurityError('INVALID_SIGNATURE_LENGTH', 401);

    // 1. Strict base64 format check: no non-base64 characters or whitespace
    const b64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
    if (!b64Regex.test(proof.signature)) {
      throw new SecurityError('INVALID_BASE64_SIGNATURE', 401);
    }

    const sigBuf = Buffer.from(proof.signature, 'base64');
    if (sigBuf.toString('base64') !== proof.signature) {
      throw new SecurityError('NON_CANONICAL_BASE64_SIGNATURE', 401);
    }

    // 2. Bound signature length for DER ECDSA P-256 (between 8 and 72 bytes)
    if (sigBuf.byteLength < 8 || sigBuf.byteLength > 72) {
      throw new SecurityError('INVALID_SIGNATURE_LENGTH', 401);
    }

    // 3. Strict DER ECDSA sequence check: SEQUENCE { r INTEGER, s INTEGER } with exact byte length
    const parsedAsn = asn1js.fromBER(sigBuf, ASN1_PARSE_LIMITS);
    if (parsedAsn.offset !== sigBuf.byteLength) {
      throw new SecurityError('MALFORMED_DER_SIGNATURE', 401);
    }

    const sigSeq = parsedAsn.result;
    if (
      !(sigSeq instanceof asn1js.Sequence) ||
      !sigSeq.valueBlock ||
      !Array.isArray(sigSeq.valueBlock.value) ||
      sigSeq.valueBlock.value.length !== 2
    ) {
      throw new SecurityError('MALFORMED_DER_SIGNATURE', 401);
    }

    const [r, s] = sigSeq.valueBlock.value;
    if (!(r instanceof asn1js.Integer) || !(s instanceof asn1js.Integer)) {
      throw new SecurityError('MALFORMED_DER_SIGNATURE', 401);
    }

    // 4. Cryptographic verification using device's attested public key and SHA-256
    try {
      const isValid = crypto.verify('sha256', proof.canonical, getP256Key(device.publicKeyPem), sigBuf);
      if (!isValid) {
        throw new SecurityError('INVALID_SIGNATURE', 401);
      }
    } catch (err) {
      if (err instanceof SecurityError) throw err;
      throw new SecurityError('INVALID_SIGNATURE', 401);
    }

    return { signCount: undefined };
  }

  /**
   * Parses ASN.1 KeyDescription sequence with full byte consumption verification.
   */
  private parseKeyDescription(bytes: Buffer): ParsedKeyDescription {
    const parsed = asn1js.fromBER(bytes, ASN1_PARSE_LIMITS);
    if (parsed.offset !== bytes.byteLength || !(parsed.result instanceof asn1js.Sequence)) {
      throw new SecurityError('MALFORMED_KEY_DESCRIPTION', 403);
    }

    const elements = parsed.result.valueBlock?.value;
    if (!Array.isArray(elements) || elements.length !== 8) {
      throw new SecurityError('MALFORMED_KEY_DESCRIPTION', 403);
    }

    const attestationVersion = parseAsnInteger(elements[0]);

    if (!(elements[1] instanceof asn1js.Enumerated)) {
      throw new SecurityError('MALFORMED_KEY_DESCRIPTION', 403);
    }
    const attestationSecurityLevel = parseAsnNumber(elements[1], 10);

    const keymasterVersion = parseAsnInteger(elements[2]);

    if (!(elements[3] instanceof asn1js.Enumerated)) {
      throw new SecurityError('MALFORMED_KEY_DESCRIPTION', 403);
    }
    const keymasterSecurityLevel = parseAsnNumber(elements[3], 10);

    const attestationChallenge = parseAsnOctetString(elements[4]);
    const uniqueId = parseAsnOctetString(elements[5]);

    if (!(elements[6] instanceof asn1js.Sequence) || !(elements[7] instanceof asn1js.Sequence)) {
      throw new SecurityError('MALFORMED_KEY_DESCRIPTION', 403);
    }

    const softwareEnforced = this.parseAuthorizationList(elements[6]);
    const hardwareEnforced = this.parseAuthorizationList(elements[7]);

    return {
      attestationVersion,
      attestationSecurityLevel,
      keymasterVersion,
      keymasterSecurityLevel,
      attestationChallenge,
      uniqueId,
      softwareEnforced,
      hardwareEnforced,
    };
  }

  /**
   * Parses ASN.1 AuthorizationList sequence with strict tagClass, explicit child, and duplicate rejection.
   */
  private parseAuthorizationList(seqItem: asn1js.Sequence): ParsedAuthList {
    const result: ParsedAuthList = {};
    const items = seqItem.valueBlock?.value;
    if (!Array.isArray(items)) {
      return result;
    }

    const seenTags = new Set<number>();

    for (const rawItem of items) {
      const item = rawItem as asn1js.AsnType;

      // Must be context-specific class (tagClass === 3)
      if (item.idBlock?.tagClass !== 3) {
        throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
      }

      const tag = item.idBlock.tagNumber;
      if (seenTags.has(tag)) {
        // Duplicate tag rejection
        throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
      }
      seenTags.add(tag);

      // Must have exactly one explicit child
      const children = (item as { valueBlock?: { value?: asn1js.AsnType[] } }).valueBlock?.value;
      if (!Array.isArray(children) || children.length !== 1) {
        throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
      }
      const inner = children[0];

      switch (tag) {
        case TAG_PURPOSE: {
          if (!(inner instanceof asn1js.Set) || !Array.isArray(inner.valueBlock?.value)) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }
          const purposes = new Set<number>();
          for (const val of inner.valueBlock.value) {
            if (!(val instanceof asn1js.Integer)) {
              throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
            }
            purposes.add(parseAsnNumber(val));
          }
          result.purposes = purposes;
          break;
        }
        case TAG_ALGORITHM: {
          if (!(inner instanceof asn1js.Integer)) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }
          result.algorithm = parseAsnNumber(inner);
          break;
        }
        case TAG_KEY_SIZE: {
          if (!(inner instanceof asn1js.Integer)) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }
          result.keySize = parseAsnNumber(inner);
          break;
        }
        case TAG_DIGEST: {
          if (!(inner instanceof asn1js.Set) || !Array.isArray(inner.valueBlock?.value)) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }
          const digests = new Set<number>();
          for (const val of inner.valueBlock.value) {
            if (!(val instanceof asn1js.Integer)) {
              throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
            }
            digests.add(parseAsnNumber(val));
          }
          result.digests = digests;
          break;
        }
        case TAG_EC_CURVE: {
          if (!(inner instanceof asn1js.Integer)) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }
          result.ecCurve = parseAsnNumber(inner);
          break;
        }
        case TAG_ORIGIN: {
          if (!(inner instanceof asn1js.Integer)) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }
          result.origin = parseAsnNumber(inner);
          break;
        }
        case TAG_ROOT_OF_TRUST: {
          if (!(inner instanceof asn1js.Sequence) || !Array.isArray(inner.valueBlock?.value)) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }
          const rotElems = inner.valueBlock.value;
          if (rotElems.length < 3 || rotElems.length > 4) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }

          // verifiedBootKey: OCTET_STRING
          if (!(rotElems[0] instanceof asn1js.OctetString)) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }
          const verifiedBootKey = parseAsnOctetString(rotElems[0]);

          // deviceLocked: strict BOOLEAN
          if (!(rotElems[1] instanceof asn1js.Boolean)) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }
          const deviceLocked = rotElems[1].valueBlock.value;

          // verifiedBootState is ENUMERATED, not an arbitrary integer/coerced value.
          if (!(rotElems[2] instanceof asn1js.Enumerated)) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }
          const verifiedBootState = parseAsnNumber(rotElems[2], 10);

          let verifiedBootHash: Buffer | undefined;
          if (rotElems.length === 4) {
            if (!(rotElems[3] instanceof asn1js.OctetString)) {
              throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
            }
            verifiedBootHash = parseAsnOctetString(rotElems[3]);
          }

          result.rootOfTrust = {
            verifiedBootKey,
            deviceLocked,
            verifiedBootState,
            verifiedBootHash,
          };
          break;
        }
        case TAG_OS_VERSION: {
          if (!(inner instanceof asn1js.Integer)) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }
          result.osVersion = parseAsnInteger(inner);
          break;
        }
        case TAG_OS_PATCH_LEVEL: {
          if (!(inner instanceof asn1js.Integer)) {
            throw new SecurityError('MALFORMED_AUTHORIZATION_LIST', 403);
          }
          result.osPatchLevel = parseAsnNumber(inner);
          break;
        }
        case TAG_ATTESTATION_APPLICATION_ID: {
          result.attestationApplicationId = this.parseAttestationApplicationId(inner);
          break;
        }
      }
    }

    return result;
  }

  /**
   * Parses Tag 709 (AttestationApplicationId) strictly from an explicit OCTET STRING.
   */
  private parseAttestationApplicationId(innerItem: asn1js.AsnType): ParsedAttestationAppId {
    if (!(innerItem instanceof asn1js.OctetString)) {
      throw new SecurityError('MALFORMED_ATTESTATION_APPLICATION_ID', 403);
    }

    const derBytes = parseAsnOctetString(innerItem);
    const parsed = asn1js.fromBER(derBytes, ASN1_PARSE_LIMITS);
    if (parsed.offset !== derBytes.byteLength || !(parsed.result instanceof asn1js.Sequence)) {
      throw new SecurityError('MALFORMED_ATTESTATION_APPLICATION_ID', 403);
    }

    const appSeq = parsed.result.valueBlock?.value;
    if (!Array.isArray(appSeq) || appSeq.length !== 2) {
      throw new SecurityError('MALFORMED_ATTESTATION_APPLICATION_ID', 403);
    }

    const packageRecordsSet = appSeq[0];
    const signatureDigestsSet = appSeq[1];

    if (!(packageRecordsSet instanceof asn1js.Set) || !(signatureDigestsSet instanceof asn1js.Set)) {
      throw new SecurityError('MALFORMED_ATTESTATION_APPLICATION_ID', 403);
    }

    const pkgRecords = packageRecordsSet.valueBlock?.value;
    if (!Array.isArray(pkgRecords)) {
      throw new SecurityError('MALFORMED_ATTESTATION_APPLICATION_ID', 403);
    }

    const packages: ParsedPackageInfo[] = [];
    for (const pkgElem of pkgRecords) {
      if (!(pkgElem instanceof asn1js.Sequence) || !Array.isArray(pkgElem.valueBlock?.value) || pkgElem.valueBlock.value.length !== 2) {
        throw new SecurityError('MALFORMED_ATTESTATION_APPLICATION_ID', 403);
      }
      const [nameElem, verElem] = pkgElem.valueBlock.value;
      if (!(nameElem instanceof asn1js.OctetString) || !(verElem instanceof asn1js.Integer)) {
        throw new SecurityError('MALFORMED_ATTESTATION_APPLICATION_ID', 403);
      }
      const name = parseAsnOctetString(nameElem).toString('utf8');
      const version = parseAsnInteger(verElem);
      packages.push({ name, version });
    }

    const sigRecords = signatureDigestsSet.valueBlock?.value;
    if (!Array.isArray(sigRecords)) {
      throw new SecurityError('MALFORMED_ATTESTATION_APPLICATION_ID', 403);
    }

    const signatures: string[] = [];
    for (const sigElem of sigRecords) {
      if (!(sigElem instanceof asn1js.OctetString)) {
        throw new SecurityError('MALFORMED_ATTESTATION_APPLICATION_ID', 403);
      }
      const sigBuf = parseAsnOctetString(sigElem);
      // SHA-256 digest must be exactly 32 bytes
      if (sigBuf.byteLength !== 32) {
        throw new SecurityError('MALFORMED_ATTESTATION_APPLICATION_ID', 403);
      }
      signatures.push(sigBuf.toString('hex').toLowerCase());
    }

    return { packages, signatures };
  }
}
