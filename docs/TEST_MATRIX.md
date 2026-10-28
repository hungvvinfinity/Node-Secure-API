# Security Test Matrix & Verification Report

**Project**: Node-Secure-API (Attestation-Backed Mutual Authentication Gateway)  
**Verification Date**: 2026-10-29  
**Execution Environment**: Host Node.js v24.21.0, Redis Container `node-secure-api-continuation-20261029` (Redis server v8.10.3, Port 32773 / 32768); Docker Compose acceptance verified on Node.js v24.22.1 (`node:24-alpine`) and Redis 8-alpine  
**Test Runner**: Node.js Native Test Runner (`tsx --test test/*.test.ts`)  
**Suite Status**: **212 / 212 PASSED (100%)** — 45 Suites, 16 Test Files, 0 Failed, 0 Skipped (Docker Compose acceptance & container restart verification PASSED)  
**Loaded `src/` Code Coverage**: 90.20% Lines, 75.93% Branches, 93.33% Functions (Runtime and server composition verified in separate Docker integration smoke)

---

## 1. Executive Summary & Verification Metrics

| Category | Count | Status | Notes |
| :--- | :--- | :--- | :--- |
| **Total Test Files** | 16 | PASSED | Android KeyStore, Apple App Attest, Redis, HTTP, Canonical, CBOR, Trust Cache, Redis Probe |
| **Total Test Cases** | 212 | PASSED | 100% executed with zero skips when `REDIS_TEST_URL` is supplied |
| **Total Test Suites** | 45 | PASSED | Full domain coverage across platform attestation, durable storage, and probe gating |
| **Docker Compose CI** | 212/212 | PASSED | `npm run test:docker` passed in containerized Redis with service restart verification |
| **TypeScript Typecheck** | Clean | PASSED | `tsc --noEmit` exited with code 0 |
| **Redis Isolation** | Zero FLUSHDB | VERIFIED | Isolated UUID prefixes (`test:sec:<uuid>:`) with targeted key deletion |
| **Identity Invariants** | Enforced | VERIFIED | Missing `metadata.appId` / `metadata.environment` strictly fails 403 |

---

## 2. Comprehensive Test Matrix by Domain

### Domain 1: Canonical Request Wire Integrity & Replay Defense
**File**: `test/canonical-request.test.ts` (10 tests)  
**Components**: `src/core/canonical.ts` (`buildCanonicalString`, `buildCanonicalBuffer`), `src/core/security-service.ts` (`SecurityService`)

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `builds exact canonical string without trailing newline or padding` | `buildCanonicalString` | Wire format exactness: `timestamp:sequence:METHOD:requestTarget:bodySha256` | **PASS** |
| 2 | `normalizes method to uppercase in production canonical pipeline` | `buildCanonicalString` | Method normalization: lowercase `post` maps to canonical `POST` | **PASS** |
| 3 | `preserves empty body SHA-256 hash in canonical string` | `buildCanonicalString` | Known empty hash `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | **PASS** |
| 4 | `preserves exact wire request-target without decoding or reordering query parameters` | `buildCanonicalString` | Query and path tampering prevention: rejects parameter reordering | **PASS** |
| 5 | `detects 1-bit whitespace mutation CR(0x0d) -> TAB(0x09) via SecurityService.authenticateRequest` | `SecurityService` | Avalanche effect: whitespace alterations produce disjoint SHA-256 digests | **PASS** |
| 6 | `rejects query parameter reordering or mutation through SecurityService.authenticateRequest` | `SecurityService` | URL query injection detection | **PASS** |
| 7 | `rejects HTTP method alteration through SecurityService.authenticateRequest` | `SecurityService` | Method alteration detection | **PASS** |
| 8 | `authenticates sequence > 2^53 successfully via SecurityService` | `SecurityService` | 64-bit BigInt sequence parsing (`9007199254740993n` string equality) | **PASS** |
| 9 | `rejects malformed sequence formats in SecurityService.authenticateRequest with INVALID_SEQUENCE (400)` | `SecurityService` | Sequence validation: rejects negative, float, non-numeric, and leading zero inputs | **PASS** |
| 10 | `validates 15s timestamp freshness window via SecurityService.authenticateRequest` | `SecurityService` | Clock skew enforcement: enforces ±15s freshness window (`TIMESTAMP_TOLERANCE_MS = 15_000`) | **PASS** |

---

### Domain 2: Security Stores & Concurrency Invariants
**File**: `test/security-store.test.ts` (15 tests)  
**Components**: `src/store/memory.ts` (`MemorySecurityStore`), `src/store/redis.ts` (`RedisSecurityStore`)

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 11 | `saves and consumes challenge exactly once` | `MemorySecurityStore` | Challenge replay prevention: single-use atomic consumption | **PASS** |
| 12 | `rejects invalid or negative TTL with INVALID_CHALLENGE (400)` | `MemorySecurityStore` | Boundary validation: negative or zero TTL rejected | **PASS** |
| 13 | `rejects expired challenge via injected clock at boundary` | `MemorySecurityStore` | TTL expiration: challenge unusable at TTL + 1ms | **PASS** |
| 14 | `guarantees exactly 1 winner in 20 concurrent challenge consume attempts` | `MemorySecurityStore` | Atomic race condition: 20 simultaneous threads consume same challenge | **PASS** |
| 15 | `creates device NX without overwrite or sequence reset` | `MemorySecurityStore` | Anti-overwrite invariant: existing device registration cannot be reset | **PASS** |
| 16 | `enforces atomic CAS sequence with >2^53 BigInt support` | `MemorySecurityStore` | Atomic compare-and-swap with `BigInt(sequence)` > 2^53 | **PASS** |
| 17 | `connects to real Redis test instance without FLUSHDB` | `RedisSecurityStore` | Isolation: connects cleanly without wiping global database | **PASS** |
| 18 | `cold-start concurrency regression: 20 simultaneous pings on newly initialized store all succeed` | `RedisSecurityStore` | Concurrency regression: cold client pool handles burst load | **PASS** |
| 19 | `atomically saves and single-use consumes challenge in Redis` | `RedisSecurityStore` | Redis atomic GETDEL script for challenge consumption | **PASS** |
| 20 | `guarantees exactly 1 winner in 20 concurrent challenge consume attempts in Redis` | `RedisSecurityStore` | Redis atomic race: exactly 1 winner among 20 parallel consumers | **PASS** |
| 21 | `creates device with NX and prevents overwrite/reset in Redis` | `RedisSecurityStore` | Redis HSETNX atomicity: prevents overwriting registered public key | **PASS** |
| 22 | `guarantees exactly 1 winner in 20 concurrent requests with the SAME sequence in Redis Lua` | `RedisSecurityStore` | Lua CAS atomicity: 20 concurrent same-sequence requests yield 1 winner | **PASS** |
| 23 | `correctly handles sequence comparison > 2^53 in Redis Lua without precision loss` | `RedisSecurityStore` | Lua 64-bit integer string comparison: preserves BigInt precision | **PASS** |
| 24 | `fails closed and prevents mutation on corrupted Redis state` | `RedisSecurityStore` | Fail-closed integrity: malformed Redis hash rejected without state change | **PASS** |
| 25 | `handles blackhole TCP server gracefully with bounded timeout without hanging` | `RedisSecurityStore` | Reliability: bounded connection timeout prevents event-loop hang | **PASS** |

---

### Domain 3: Performance Caching & Key Management
**Files**: `test/cached-store.test.ts` (8 tests), `test/key-cache.test.ts` (7 tests)  
**Components**: `src/store/cached.ts` (`CachingSecurityStore`), `src/platform/key-cache.ts` (`PublicKeyCache`)

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 26 | `proves cold-cache miss and warm-cache hit behavior with statistics tracking` | `CachingSecurityStore` | Read-through caching: cold miss fetches inner, warm hit avoids I/O | **PASS** |
| 27 | `guarantees defensive structured cloning: mutating returned record does not mutate internal cache` | `CachingSecurityStore` | Memory safety: mutations to returned objects do not poison cache | **PASS** |
| 28 | `enforces TTL expiration and LRU capacity bounds` | `CachingSecurityStore` | Bounded resource usage: expired entries evicted, LRU capacity enforced | **PASS** |
| 29 | `guarantees challenges strictly bypass cache and remain durable and single-use` | `CachingSecurityStore` | Challenge bypass: challenges never cached in RAM, always durable | **PASS** |
| 30 | `guarantees commitSequence always delegates to inner store: multi-gateway race rejects stale sequence` | `CachingSecurityStore` | State synchronization: sequence commits bypass cache to authoritative store | **PASS** |
| 31 | `guarantees deleted/revoked record in inner store invalidates cache and prevents business execution` | `CachingSecurityStore` | Revocation propagation: deleted record in inner store invalidates cache | **PASS** |
| 32 | `clears volatile cache on close()` | `CachingSecurityStore` | Clean teardown: cache flushed when store is closed | **PASS** |
| 33 | `proves durable receipt persists in Redis HSET while getDevice and RAM cache return request-slim metadata` | `CachingSecurityStore` | Hot-path memory optimization: raw CMS receipt stored in Redis, excluded from RAM | **PASS** |
| 34 | `parses valid EC P-256 SPKI PEM and caches KeyObject across repeated calls` | `PublicKeyCache` | Crypto optimization: SPKI PEM parsed to `KeyObject` once and cached | **PASS** |
| 35 | `rejects RSA public key with 403 ATTESTED_KEY_NOT_EC` | `PublicKeyCache` | Key type enforcement: RSA SPKI strictly rejected | **PASS** |
| 36 | `rejects non-P256 EC keys (e.g. secp384r1 / P-384) with 403 ATTESTED_KEY_NOT_P256` | `PublicKeyCache` | Curve enforcement: P-384 curve strictly rejected | **PASS** |
| 37 | `rejects empty or whitespace PEM with 400 INVALID_PUBLIC_KEY_PEM` | `PublicKeyCache` | Input validation: empty PEM rejected | **PASS** |
| 38 | `rejects malformed PEM with 400 MALFORMED_PUBLIC_KEY` | `PublicKeyCache` | Parse safety: corrupt PEM rejected fail-closed | **PASS** |
| 39 | `enforces bounded LRU eviction when capacity is reached` | `PublicKeyCache` | Memory bound: LRU eviction prevents unbounded cache growth | **PASS** |
| 40 | `clears cache on clear()` | `PublicKeyCache` | Clean teardown: cache flushed on explicit clear | **PASS** |

---

### Domain 4: Android Hardware Attestation & Cryptographic Checks
**File**: `test/android-provider.test.ts` (31 tests)  
**Component**: `src/platform/android.ts` (`AndroidSecurityProvider`)

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 41 | `successfully verifies valid synthetic TEE attestation chain and extracts EC P-256 SPKI PEM` | `AndroidSecurityProvider` | Happy path: valid TEE attestation with Tag 704 & 709 parsed | **PASS** |
| 42 | `successfully verifies valid synthetic StrongBox hardware attestation chain` | `AndroidSecurityProvider` | Happy path: StrongBox hardware attestation verified | **PASS** |
| 43 | `successfully verifies valid request proof with ECDSA P-256 DER signature` | `AndroidSecurityProvider` | Request proof: valid ECDSA P-256 DER signature over canonical buffer | **PASS** |
| 44 | `rejects Software level in attestationSecurityLevel with 403 HARDWARE_TEE_REQUIRED` | `AndroidSecurityProvider` | Hardware enforcement: rejects software attestation security level | **PASS** |
| 45 | `rejects Software level in keymasterSecurityLevel with 403 HARDWARE_TEE_REQUIRED` | `AndroidSecurityProvider` | Hardware enforcement: rejects software keymaster security level | **PASS** |
| 46 | `rejects challenge mismatch between hardware attestation and server context` | `AndroidSecurityProvider` | Attestation challenge binding: challenge in cert must match server challenge | **PASS** |
| 47 | `rejects unlocked bootloader (deviceLocked = false) with 403 DEVICE_NOT_LOCKED` | `AndroidSecurityProvider` | Root of trust: unlocked bootloader strictly rejected | **PASS** |
| 48 | `rejects unverified boot state (SelfSigned=1, Unverified=2, Failed=3) with 403 BOOT_NOT_VERIFIED` | `AndroidSecurityProvider` | Root of trust: non-verified boot states rejected | **PASS** |
| 49 | `rejects rootOfTrust located in softwareEnforced instead of hardwareEnforced` | `AndroidSecurityProvider` | Root of trust integrity: rootOfTrust in softwareEnforced rejected | **PASS** |
| 50 | `rejects rogue package name with 403 PACKAGE_NAME_MISMATCH` | `AndroidSecurityProvider` | Application identity: package name in Tag 709 must match configured name | **PASS** |
| 51 | `rejects app version lower than minimumVersion with 403 PACKAGE_VERSION_TOO_LOW` | `AndroidSecurityProvider` | Minimum version enforcement: version code below minimum rejected | **PASS** |
| 52 | `accepts app version code exceeding 2^53 BigInt with exact string representation` | `AndroidSecurityProvider` | BigInt version support: handles version code `9007199254740993n` | **PASS** |
| 53 | `rejects signer certificate digest mismatch with 403 SIGNER_DIGEST_MISMATCH` | `AndroidSecurityProvider` | App signature integrity: APK signing certificate SHA-256 digest mismatch rejected | **PASS** |
| 54 | `rejects attestation with missing Tag 709 application ID` | `AndroidSecurityProvider` | Identity mandatory: missing Tag 709 extension rejected | **PASS** |
| 55 | `rejects leaf key that is RSA instead of EC P-256 with 403 ATTESTED_KEY_NOT_EC` | `AndroidSecurityProvider` | Key type enforcement: attested key must be EC P-256 | **PASS** |
| 56 | `rejects key without SIGN purpose with 403 HARDWARE_PURPOSE_SIGN_REQUIRED` | `AndroidSecurityProvider` | Key purpose enforcement: KeyMint Tag 1 (purpose) must contain SIGN (2) | **PASS** |
| 57 | `rejects key with origin IMPORTED with 403 HARDWARE_ORIGIN_GENERATED_REQUIRED` | `AndroidSecurityProvider` | Key origin enforcement: KeyMint Tag 702 (origin) must be GENERATED (0) | **PASS** |
| 58 | `rejects key without SHA-256 digest with 403 HARDWARE_DIGEST_SHA256_REQUIRED` | `AndroidSecurityProvider` | Key digest enforcement: KeyMint Tag 5 (digest) must contain SHA-256 (4) | **PASS** |
| 59 | `rejects chain with untrusted Root CA (not in trustAnchors)` | `AndroidSecurityProvider` | PKIX validation: untrusted root CA rejected | **PASS** |
| 60 | `rejects chain with broken signature (child not signed by parent)` | `AndroidSecurityProvider` | Cryptographic chain integrity: broken signature between certs rejected | **PASS** |
| 61 | `accepts expired leaf target certificate according to device-controlled Android attestation policy` | `AndroidSecurityProvider` | Android expiry exception: leaf cert expiry ignored per Android KeyStore spec | **PASS** |
| 62 | `rejects expired non-factory intermediate certificate with 403 CERTIFICATE_EXPIRED` | `AndroidSecurityProvider` | Intermediate expiry: expired intermediate rejected unless factory exempt | **PASS** |
| 63 | `rejects revoked certificate in chain` | `AndroidSecurityProvider` | CRL/Revocation check: serial in revocation list strictly rejected | **PASS** |
| 64 | `fails closed with 503 REVOCATION_STATUS_UNAVAILABLE if revocation source fails` | `AndroidSecurityProvider` | Fail-closed revocation: network or source failure produces 503 | **PASS** |
| 65 | `rejects intermediate certificate lacking BasicConstraints isCA=true` | `AndroidSecurityProvider` | CA constraint enforcement: intermediate without `isCA=true` rejected | **PASS** |
| 66 | `rejects leaf certificate missing attestation extension with 403 TARGET_MISSING_ATTESTATION_EXTENSION` | `AndroidSecurityProvider` | Extension presence: cert lacking OID `1.3.6.1.4.1.11129.2.1.17` rejected | **PASS** |
| 67 | `rejects non-base64 signature with 401 INVALID_BASE64_SIGNATURE` | `AndroidSecurityProvider` | Signature format: non-base64 signature header rejected | **PASS** |
| 68 | `rejects signature with invalid length (< 8 or > 72 bytes) with 401 INVALID_SIGNATURE_LENGTH` | `AndroidSecurityProvider` | Mathematical DER bounds: rejects DER length < 8 or > 72 bytes | **PASS** |
| 69 | `rejects malformed DER signature (67 bytes of invalid ASN.1) with 401 MALFORMED_DER_SIGNATURE` | `AndroidSecurityProvider` | ASN.1 parser safety: malformed DER structure rejected fail-closed | **PASS** |
| 70 | `rejects tampered canonical buffer (even 1-bit alteration)` | `AndroidSecurityProvider` | Canonical integrity: tampered payload rejected with invalid signature | **PASS** |
| 71 | `rejects signature signed by a different key with 401 INVALID_SIGNATURE` | `AndroidSecurityProvider` | Signature verification: signature from wrong private key rejected | **PASS** |

---

### Domain 5: Real Upstream Hardware & Factory Interoperability
**File**: `test/upstream-interop.test.ts` (11 tests)  
**Components**: `src/platform/chain.ts`, `src/platform/trust.ts`, `src/platform/android.ts`

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 72 | `offline interoperability smoke: verifies caiman chain with official Google RSA Root CA at historical time 2025-09-26` | `validateCertificateChain` | Real Google hardware attestation: Pixel 9 Pro SDK 36 TEE EC RKP chain | **PASS** |
| 73 | `rejects expired RKP intermediate at current time (2026-10-28) with 403 CERTIFICATE_EXPIRED` | `validateCertificateChain` | RKP expiry enforcement: expired RKP intermediate rejected at current time | **PASS** |
| 74 | `offline interoperability smoke: verifies tegu chain with new official 2026 Google EC Root CA at historical time 2026-02-25` | `validateCertificateChain` | Real 2026 Google Root: Pixel 9a SDK 36 TEE EC 2026 EC Root chain | **PASS** |
| 75 | `proves 4-certificate factory chain with expired intermediate remains VALID under Android attestation policy` | `validateCertificateChain` | Upstream factory semantics: Pixel 3 `blueline` factory chain valid under `profile: 'android'` | **PASS** |
| 76 | `proves the same expired factory intermediate is REJECTED under strict PKIX profile with 403 CERTIFICATE_EXPIRED` | `validateCertificateChain` | Strict profile separation: expired factory intermediate rejected under `profile: 'strict'` | **PASS** |
| 77 | `proves revoked factory intermediate is strictly REJECTED even with factory exemption (403 CERTIFICATE_REVOKED)` | `validateCertificateChain` | Revocation precedence: revoked serial rejects chain regardless of factory exemption | **PASS** |
| 78 | `proves full AndroidSecurityProvider enforces HARDWARE_DIGEST_SHA256_REQUIRED on blueline DIGEST_NONE key without relaxing policy` | `AndroidSecurityProvider` | Security policy integrity: refuses to relax SHA-256 requirement for factory test keys | **PASS** |
| 79 | `parses valid revocation JSON with both REVOKED and SUSPENDED entries into lowercase hex serials` | `GoogleRevocationSource` | Revocation format parsing: parses Google CRL JSON into normalized hex serials | **PASS** |
| 80 | `fails closed on malformed JSON or unknown status in revocation response` | `GoogleRevocationSource` | Revocation parser safety: malformed JSON or invalid status fails closed | **PASS** |
| 81 | `parses valid roots JSON array and rejects invalid certificate text` | `parseGoogleRootsJson` | Trust anchor loading: extracts PEM array from official JSON format | **PASS** |
| 82 | `GoogleRevocationSource caches snapshot and fails closed when empty and unreachable` | `GoogleRevocationSource` | Offline defense: uses cached revocation snapshot, fails closed if unreachable | **PASS** |

---

### Domain 6: CBOR Strict Parsing & Memory Safety
**File**: `test/cbor-security.test.ts` (18 tests)  
**Component**: `src/platform/cbor.ts` (`scanCbor`, `validateAndDecodeCBOR`, `decodeMultipleBounded`)

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 83 | `preserves numeric vs string keys distinctly in Map without coercion` | `validateAndDecodeCBOR` | Type confusion defense: integer `1` and string `"1"` remain distinct keys | **PASS** |
| 84 | `correctly decodes byte strings into raw byte buffers for cryptographic signatures` | `validateAndDecodeCBOR` | Crypto buffer fidelity: byte strings decode to raw byte arrays | **PASS** |
| 85 | `sequentially decodes multiple bounded items (e.g. COSE structure + trailing extension)` | `decodeMultipleBounded` | Multi-item parsing: sequentially decodes concatenated CBOR items | **PASS** |
| 86 | `rejects duplicate map keys with DUPLICATE_CBOR_KEY (400)` | `validateAndDecodeCBOR` | Map collision attack: duplicate literal map keys strictly rejected | **PASS** |
| 87 | `rejects semantic duplicate keys encoded via different/overlong text lengths with DUPLICATE_CBOR_KEY (400)` | `validateAndDecodeCBOR` | Semantic duplicate attack: canonical and non-canonical keys decoding to same text rejected | **PASS** |
| 88 | `rejects non-minimal integer encodings with NON_CANONICAL_CBOR_INTEGER (400)` | `validateAndDecodeCBOR` | Non-canonical encoding: non-minimal integer representations rejected | **PASS** |
| 89 | `rejects CBOR semantic tags with UNSUPPORTED_CBOR_TAG (400)` | `validateAndDecodeCBOR` | Tag injection defense: Major Type 6 semantic tags strictly rejected | **PASS** |
| 90 | `rejects indefinite-length arrays, maps, and byte strings with INDEFINITE_LENGTH_CBOR (400)` | `validateAndDecodeCBOR` | Streaming attack defense: indefinite-length items (additional info 31) rejected | **PASS** |
| 91 | `rejects reserved additional information values 28..30 with INVALID_CBOR_PAYLOAD (400)` | `validateAndDecodeCBOR` | Protocol compliance: reserved CBOR values 28..30 rejected | **PASS** |
| 92 | `rejects floating-point numbers with UNSUPPORTED_CBOR_SIMPLE_VALUE (400)` | `validateAndDecodeCBOR` | Type restriction: 32-bit and 64-bit floating point numbers rejected | **PASS** |
| 93 | `rejects non-UTF8 sequences in text strings with INVALID_CBOR_UTF8 (400)` | `validateAndDecodeCBOR` | Text sanitization: non-UTF-8 byte sequences rejected | **PASS** |
| 94 | `rejects truncated strings and incomplete buffers with TRUNCATED_CBOR_PAYLOAD (400)` | `validateAndDecodeCBOR` | Buffer overrun defense: truncated or partial CBOR payloads rejected | **PASS** |
| 95 | `rejects recursive nesting exceeding depth limit with CBOR_DEPTH_EXCEEDED (400)` | `validateAndDecodeCBOR` | Stack overflow defense: nesting depth > 16 strictly rejected | **PASS** |
| 96 | `rejects payload exceeding node count budget with CBOR_NODE_COUNT_EXCEEDED (400)` | `validateAndDecodeCBOR` | Algorithmic complexity defense: payload exceeding 4096 nodes rejected | **PASS** |
| 97 | `rejects payloads larger than maxBytes with CBOR_PAYLOAD_TOO_LARGE (400)` | `scanCbor` | Resource bounding: payloads larger than maximum byte size rejected | **PASS** |
| 98 | `rejects trailing data bytes with TRAILING_CBOR_BYTES (400)` | `validateAndDecodeCBOR` | Payload boundary enforcement: trailing unparsed garbage rejected | **PASS** |
| 99 | `rejects composite types as Map keys with UNSUPPORTED_CBOR_MAP_KEY (400)` | `validateAndDecodeCBOR` | Map integrity: arrays or maps as keys strictly rejected | **PASS** |
| 100 | `rejects empty payloads and non-buffer inputs with appropriate security codes` | `validateAndDecodeCBOR` | Input validation: empty payload (`EMPTY_CBOR_PAYLOAD`) and non-buffer (`INVALID_CBOR_PAYLOAD`) | **PASS** |

---

### Domain 7: Apple App Attest CMS Receipt Verification
**File**: `test/ios-receipt.test.ts` (11 tests)  
**Component**: `src/platform/ios-receipt.ts` (`AppleReceiptVerifier`)

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 101 | `successfully verifies valid CMS receipt signed by authorized receipt signer profile` | `AppleReceiptVerifier` | Happy path: valid CMS SignedData with Apple marker verified | **PASS** |
| 102 | `rejects arbitrary Apple-signed certificate lacking mandatory marker 1.2.840.113635.100.12.15` | `AppleReceiptVerifier` | Marker mandatory: arbitrary Apple-signed certificate lacking marker rejected | **PASS** |
| 103 | `rejects marker 1.2.840.113635.100.12.15 with non-NULL ASN.1 value` | `AppleReceiptVerifier` | Marker syntax: marker extension value must be ASN.1 NULL (`05 00`) | **PASS** |
| 104 | `rejects receipt signer certificate where CA constraint is true` | `AppleReceiptVerifier` | Signer role enforcement: receipt signing certificate must not be a CA | **PASS** |
| 105 | `rejects receipt signed by untrusted Root CA` | `AppleReceiptVerifier` | Trust anchor binding: receipt signed by untrusted root rejected | **PASS** |
| 106 | `rejects receipt with corrupted CMS cryptographic signature` | `AppleReceiptVerifier` | Cryptographic integrity: tampered CMS SignedData signature rejected | **PASS** |
| 107 | `rejects receipt with mismatched appId in attribute 2 with RECEIPT_APP_ID_MISMATCH` | `AppleReceiptVerifier` | Identity binding: receipt attribute 2 (appId) mismatch rejected | **PASS** |
| 108 | `rejects receipt with mismatched public key in attribute 3 with RECEIPT_KEY_MISMATCH` | `AppleReceiptVerifier` | Key binding: receipt attribute 3 (leaf SPKI DER) mismatch rejected | **PASS** |
| 109 | `rejects receipt where attribute 12 created timestamp is older than 5 minutes with RECEIPT_EXPIRED` | `AppleReceiptVerifier` | Freshness check: receipt created > 300s in past rejected | **PASS** |
| 110 | `rejects receipt where attribute 12 created timestamp is in the future (> 15s) with RECEIPT_EXPIRED` | `AppleReceiptVerifier` | Future timestamp defense: receipt created > 15s in future rejected | **PASS** |
| 111 | `rejects receipt with expired attribute 21 expiration timestamp with RECEIPT_EXPIRED` | `AppleReceiptVerifier` | Expiration check: receipt past its attribute 21 expiry rejected | **PASS** |

---

### Domain 8: Apple App Attest Platform Provider & Assertions
**File**: `test/ios-provider.test.ts` (35 tests)  
**Component**: `src/platform/ios.ts` (`IOSSecurityProvider`)

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 112 | `successfully verifies valid synthetic production attestation chain and extracts EC SPKI PEM` | `IOSSecurityProvider` | Happy path: production attestation + EC SPKI extraction | **PASS** |
| 113 | `successfully verifies valid development environment attestation (AAGUID appattestdevelop)` | `IOSSecurityProvider` | Environment binding: development AAGUID accepted when configured | **PASS** |
| 114 | `successfully verifies valid request assertion and advances counter (0 -> 1 -> 2)` | `IOSSecurityProvider` | Monotonic assertions: counter strictly advances 0 -> 1 -> 2 | **PASS** |
| 115 | `accepts assertion with flags=0 as legitimate without user presence requirement` | `IOSSecurityProvider` | Flag compliance: flags `0x00` (no UP) accepted for assertions | **PASS** |
| 116 | `accepts legacy iOS attestation without 2026 app properties extensions by default` | `IOSSecurityProvider` | Backwards compatibility: legacy iOS devices accepted when allowed | **PASS** |
| 117 | `parses and accepts 2026 Apple extensions (validationCategory & bundleVersion) when valid` | `IOSSecurityProvider` | Modern extensions: validates category and minimum bundle version | **PASS** |
| 118 | `rejects challenge mismatch between hardware attestation and server context (403 ATTESTATION_CHALLENGE_MISMATCH)` | `IOSSecurityProvider` | Challenge binding: `SHA256(authData \|\| SHA256(challenge))` mismatch rejected | **PASS** |
| 119 | `rejects attestation with missing Apple nonce extension 1.2.840.113635.100.8.2` | `IOSSecurityProvider` | Extension presence: leaf missing App Attest nonce extension rejected | **PASS** |
| 120 | `rejects corrupted nonce (even 1-bit alteration) with 403 ATTESTATION_CHALLENGE_MISMATCH` | `IOSSecurityProvider` | Extension syntax: non-OCTET STRING or corrupt nonce extension rejected | **PASS** |
| 121 | `rejects leaf key that is RSA instead of EC P-256 with 403 ATTESTED_KEY_NOT_EC` | `IOSSecurityProvider` | Key type enforcement: leaf RSA key strictly rejected | **PASS** |
| 122 | `rejects chain with untrusted Root CA` | `IOSSecurityProvider` | Trust anchor binding: attestation chain signed by rogue root rejected | **PASS** |
| 123 | `rejects mismatched appId in authData rpIdHash with 401 RP_ID_MISMATCH` | `IOSSecurityProvider` | App ID binding: `rpIdHash` must match `SHA256(appId)` | **PASS** |
| 124 | `rejects AAGUID environment mismatch (e.g. dev AAGUID in production provider) with 403 AAGUID_MISMATCH` | `IOSSecurityProvider` | Environment separation: dev AAGUID rejected in production | **PASS** |
| 125 | `rejects credentialId mismatch with 400 CREDENTIAL_ID_MISMATCH` | `IOSSecurityProvider` | KeyId binding: `keyId` must match `SHA256(COSE key bytes)` | **PASS** |
| 126 | `rejects COSE key mismatch with 400 COSE_KEY_MISMATCH` | `IOSSecurityProvider` | Public key binding: COSE P-256 key must match leaf certificate key | **PASS** |
| 127 | `rejects initial signCount !== 0 on registration with 400 INVALID_SIGN_COUNT` | `IOSSecurityProvider` | Initial counter: attestation signCount must be strictly 0 | **PASS** |
| 128 | `rejects registration authData with missing AT flag (0x40)` | `IOSSecurityProvider` | Authenticator flag: bit 6 (AT) must be set in attestation authData | **PASS** |
| 129 | `rejects missing receipt in attStmt with 400 MISSING_APP_ATTEST_RECEIPT` | `IOSSecurityProvider` | Receipt mandatory: attestation lacking `receipt` rejected | **PASS** |
| 130 | `rejects duplicate CBOR map keys with 400 DUPLICATE_CBOR_KEY` | `IOSSecurityProvider` | CBOR canonicalization: duplicate keys in attestation rejected | **PASS** |
| 131 | `rejects oversize attestation payload (> 256 KB) with 400 ATTESTATION_OBJECT_TOO_LARGE` | `IOSSecurityProvider` | Resource bounding: attestation payload > 256KB rejected | **PASS** |
| 132 | `rejects registration when requireAppProperties is true but extensions are missing with 403 MISSING_APP_PROPERTIES` | `IOSSecurityProvider` | Stricter policy: rejects attestation lacking extensions when required | **PASS** |
| 133 | `rejects disallowed validation category with 403 VALIDATION_CATEGORY_NOT_ALLOWED` | `IOSSecurityProvider` | App category enforcement: disallowed validation category rejected | **PASS** |
| 134 | `rejects bundle version lower than minimumBundleVersion with 403 BUNDLE_VERSION_TOO_LOW` | `IOSSecurityProvider` | Version enforcement: bundle version below minimum rejected | **PASS** |
| 135 | `rejects non-monotonic counter rollback or replay (counter <= previousCounter) with 401 SIGN_COUNT_NOT_INCREASED` | `IOSSecurityProvider` | Monotonic counter: assertion counter <= stored counter rejected | **PASS** |
| 136 | `rejects assertion signed with incorrect double-hash composite with 401 INVALID_SIGNATURE` | `IOSSecurityProvider` | Signature composite: rejects double-hashed canonical payload | **PASS** |
| 137 | `rejects assertion with AT flag set (0x40) with 401 UNEXPECTED_ATTESTED_CREDENTIAL_DATA` | `IOSSecurityProvider` | Flag restriction: bit 6 (AT) must NOT be set in assertion authData | **PASS** |
| 138 | `rejects assertion with invalid signature length (< 8 or > 72 bytes) with 401 INVALID_SIGNATURE_LENGTH` | `IOSSecurityProvider` | DER length bounds: assertion signature length < 8 or > 72 rejected | **PASS** |
| 139 | `rejects assertion with malformed DER signature (67 bytes invalid ASN.1) with 401 MALFORMED_DER_SIGNATURE` | `IOSSecurityProvider` | DER parser safety: malformed DER signature rejected fail-closed | **PASS** |
| 140 | `rejects assertion signed with a different key with 401 INVALID_SIGNATURE` | `IOSSecurityProvider` | Signature verification: assertion signed with wrong key rejected | **PASS** |
| 141 | `rejects assertion when canonical buffer is tampered (even 1-bit mutation) with 401 INVALID_SIGNATURE` | `IOSSecurityProvider` | Data integrity: tampered canonical request buffer rejected | **PASS** |
| 142 | `rejects assertion when device stored metadata is missing appId with 403 APP_ID_MISMATCH` | `IOSSecurityProvider` | **Strict Identity Regression**: missing `metadata.appId` rejected | **PASS** |
| 143 | `rejects assertion when device stored metadata is missing environment with 403 ENVIRONMENT_MISMATCH` | `IOSSecurityProvider` | **Strict Identity Regression**: missing `metadata.environment` rejected | **PASS** |
| 144 | `executes full iOS lifecycle (issue challenge -> register device -> monotonic request auth) via SecurityService` | `SecurityService` + `IOSSecurityProvider` | E2E lifecycle: register iOS device and authenticate assertion | **PASS** |
| 145 | `guarantees only 1 winner when 20 concurrent iOS requests fire with the same counter/sequence (MemoryStore)` | `SecurityService` + `IOSSecurityProvider` | Concurrency: 20 parallel requests for counter 1 yield exactly 1 winner | **PASS** |
| 146 | `guarantees only 1 winner when 20 concurrent iOS requests fire with the same counter/sequence (RedisStore)` | `SecurityService` + `IOSSecurityProvider` | Redis Lua concurrency: 20 parallel iOS assertions yield 1 winner | **PASS** |

---

### Domain 9: Multi-Platform Security Service Orchestration
**File**: `test/security-service.test.ts` (12 tests)  
**Component**: `src/core/security-service.ts` (`SecurityService`)

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 147 | `issues a cryptographically random 32-byte hex challenge with 60s TTL` | `SecurityService` | Challenge generation: 64-char hex string with 60s expiration | **PASS** |
| 148 | `rejects unsupported platform when issuing challenge` | `SecurityService` | Platform validation: unknown platform rejected with 400 | **PASS** |
| 149 | `successfully registers device by consuming challenge and persists record` | `SecurityService` | Device registration: atomic challenge consume + device persistence | **PASS** |
| 150 | `enforces single-use challenge consumption (replay registration fails)` | `SecurityService` | Replay defense: challenge unusable for second registration | **PASS** |
| 151 | `prevents re-registration from overwriting or resetting sequence (DEVICE_ALREADY_REGISTERED 409)` | `SecurityService` | Anti-overwrite: re-registering existing device yields 409 | **PASS** |
| 152 | `authenticates valid signed request and advances sequence` | `SecurityService` | Request authentication: valid signature commits sequence N | **PASS** |
| 153 | `CRITICAL INVARIANT: invalid signature MUST NOT advance sequence or burn counter` | `SecurityService` | State protection: signature failure leaves sequence / counter unmutated | **PASS** |
| 154 | `rejects replay of previously committed sequence (REPLAY_DETECTED 401)` | `SecurityService` | Replay protection: replaying sequence N rejected | **PASS** |
| 155 | `rejects request from unregistered device with DEVICE_NOT_REGISTERED (401)` | `SecurityService` | Access control: unknown device ID rejected with 401 | **PASS** |
| 156 | `rejects request with missing signature header for Android device with MISSING_SIGNATURE (401)` | `SecurityService` | Header validation: Android request without signature rejected | **PASS** |
| 157 | `guarantees only 1 winner when 20 concurrent requests fire with the same sequence` | `SecurityService` | CAS atomicity: 20 simultaneous same-sequence requests yield 1 winner | **PASS** |
| 158 | `executes complete registration and request authentication through real Android provider` | `SecurityService` | E2E integration: Android hardware attestation + signed request flow | **PASS** |

---

### Domain 10: HTTP Server Enforcement & Wire Protocol
**File**: `test/http-server.test.ts` (15 tests)  
**Component**: `src/http/server.ts` (`createServer`)

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 159 | `returns 200 UP on GET /health` | `createServer` | Liveness probe: returns status `pass` | **PASS** |
| 160 | `returns 200 READY on GET /ready when store is healthy` | `createServer` | Readiness probe: returns status `ready` | **PASS** |
| 161 | `rejects duplicate security headers with 400 DUPLICATE_HEADER` | `createServer` | HTTP smuggling / ambiguous header defense: duplicate headers rejected | **PASS** |
| 162 | `rejects compressed or unsupported content encodings with 415 UNSUPPORTED_ENCODING` | `createServer` | Zip bomb / compression attack defense: `gzip`/`deflate` rejected | **PASS** |
| 163 | `issues challenge via POST /api/auth/challenge` | `createServer` | Challenge endpoint: issues challenge with proper headers | **PASS** |
| 164 | `rejects GET /api/auth/challenge with 405 METHOD_NOT_ALLOWED` | `createServer` | HTTP method restrictions: non-POST on challenge rejected | **PASS** |
| 165 | `rejects malformed JSON payload on /api/auth/challenge with 400 INVALID_JSON` | `createServer` | Input parser safety: malformed JSON body rejected | **PASS** |
| 166 | `successfully registers device via POST /api/auth/register-device` | `createServer` | Registration endpoint: processes attestation and registers device | **PASS** |
| 167 | `rejects replay registration with same challenge with 401 INVALID_CHALLENGE` | `createServer` | HTTP replay defense: reused challenge rejected | **PASS** |
| 168 | `successfully processes valid signed request and executes businessHandler` | `createServer` | Protected route: valid mutual authentication invokes business handler | **PASS** |
| 169 | `rejects request with missing security headers with 401 MISSING_SECURITY_HEADERS` | `createServer` | Header presence enforcement: missing headers rejected | **PASS** |
| 170 | `rejects request with 1-bit whitespace tampered body with 401 INVALID_SIGNATURE` | `createServer` | Body integrity: single-byte body tamper rejected with 401 | **PASS** |
| 171 | `rejects replay attack with 401 REPLAY_DETECTED` | `createServer` | Sequence replay: replayed sequence rejected by HTTP layer | **PASS** |
| 172 | `rejects expired timestamp with 401 EXPIRED_TIMESTAMP` | `createServer` | Timestamp enforcement: stale timestamp rejected by HTTP layer | **PASS** |
| 173 | `supports sequence > 2^53 successfully over HTTP` | `createServer` | BigInt header support: parses `x-sequence: 9007199254740993` | **PASS** |

---

### Domain 11: Configuration & Fail-Closed Bounds
**File**: `test/config.test.ts` (9 tests)  
**Component**: `src/config.ts` (`loadConfig`)

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 174 | `loads valid configuration successfully` | `loadConfig` | Happy path: valid defaults for port, host, TTL, tolerances | **PASS** |
| 175 | `fails closed when REDIS_URL is missing or uses unsupported protocol` | `loadConfig` | Fail-closed initialization: missing or bad Redis protocol throws | **PASS** |
| 176 | `fails closed if USE_MEMORY_STORE is set outside test constructor injection` | `loadConfig` | In-memory guard: prevents accidental memory store use in production | **PASS** |
| 177 | `fails closed if EXPECTED_PACKAGE_NAME is missing or invalid format` | `loadConfig` | Package name format validation: malformed package format rejected | **PASS** |
| 178 | `fails closed if EXPECTED_SIGNER_DIGESTS is missing, empty, or not 64-char lowercase hex SHA-256` | `loadConfig` | Digest format enforcement: rejects non-64 hex char digests | **PASS** |
| 179 | `fails closed if MINIMUM_ANDROID_VERSION is negative, non-canonical, or out of int64 range` | `loadConfig` | Version range enforcement: negative or out-of-range version throws | **PASS** |
| 180 | `fails closed if PORT is out of 1..65535 range` | `loadConfig` | Port validation: non-numeric or out-of-range port rejected | **PASS** |
| 181 | `fails closed if both Android and iOS are disabled` | `loadConfig` | Platform configuration: at least one platform must be enabled | **PASS** |
| 182 | `fails closed if development App Attest is configured in production environment` | `loadConfig` | Environment isolation: dev App Attest forbidden in production | **PASS** |

---

### Domain 12: Redis Persistence Across Restarts & Lifecycle
**File**: `test/persistence-restart.test.ts` (3 tests)  
**Components**: `src/store/redis.ts`, `src/http/server.ts`, `src/core/security-service.ts`

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 183 | `proves Redis store preserves sequence, signCount and keys across store close and reopen without mutation` | `RedisSecurityStore` | Store restart persistence: sequence N survives close/reopen, replay N rejected, N+1 succeeds, failed commit does not mutate state, `createDeviceNX` cannot reset state | **PASS** |
| 184 | `proves full HTTP server restart with Redis persistence enforces iOS signCount and sequence continuity` | `createServer` + `IOSSecurityProvider` | Full HTTP server reboot: Server 1 registers iOS device & executes seq=1, counter=1. Server 1 shuts down. Server 2 boots with same prefix: replay rejected, stale counter rejected, seq=2, counter=2 accepted | **PASS** |
| 185 | `proves full HTTP server restart with Redis persistence enforces sequence continuity and replay protection` | `createServer` + `AndroidSecurityProvider` | Full HTTP server reboot: Server 1 registers Android device & executes seq=1. Server 1 shuts down. Server 2 boots with same prefix: replay seq=1 rejected (401), invalid signature rejected (401) without mutating sequence, seq=2 succeeds, seq=3 succeeds | **PASS** |

---

### Domain 13: Android Adversarial & Cryptographic Regression Tests
**File**: `test/android-adversarial.test.ts` (12 tests)  
**Components**: `src/platform/android.ts`, `src/platform/x509.ts`

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 186 | `1. rejects duplicate Tag 709 within AuthorizationList with 403 MALFORMED_AUTHORIZATION_LIST` | `AndroidSecurityProvider` | ASN.1 parser security: duplicate Tag 709 in AuthorizationList rejected | **PASS** |
| 187 | `2. rejects trailing unconsumed garbage bytes in KeyDescription DER with 403 MALFORMED_KEY_DESCRIPTION` | `AndroidSecurityProvider` | Strict ASN.1 framing: trailing unparsed bytes in KeyDescription extension rejected | **PASS** |
| 188 | `3. rejects negative attestationVersion in KeyDescription with 403 MALFORMED_ASN1_INTEGER` | `AndroidSecurityProvider` | Integer sign validation: negative ASN.1 INTEGER (high bit set without leading 0x00) rejected | **PASS** |
| 189 | `4. rejects masquerading universal tags inside AuthorizationList with 403 MALFORMED_AUTHORIZATION_LIST` | `AndroidSecurityProvider` | Tag class validation: universal tags masquerading as context-specific [Tag] rejected | **PASS** |
| 190 | `5. anti-extension attack: rejects chain where attested leaf key signs descendant certificate with 403 CHAIN_EXTENDED_WITH_FAKE_ATTESTATION_EXTENSION` | `AndroidSecurityProvider` | Chain extension attack: attested leaf key acting as CA to sign descendant cert rejected | **PASS** |
| 191 | `6. rejects certificate containing duplicate extension OIDs with 403 DUPLICATE_CERTIFICATE_EXTENSION` | `validateCertificateChain` | X.509 RFC 5280 compliance: duplicate extension OIDs in single certificate rejected | **PASS** |
| 192 | `7. rejects certificate with unrecognized critical extension with 403 UNRECOGNIZED_CRITICAL_EXTENSION` | `validateCertificateChain` | RFC 5280 Section 4.2: unknown critical extension strictly rejected | **PASS** |
| 193 | `8. enforces CA pathLength constraint when violated by intermediate CA with 403 PATH_LENGTH_CONSTRAINT_EXCEEDED` | `validateCertificateChain` | BasicConstraints pathLen: pathLength constraint violation strictly rejected | **PASS** |
| 194 | `9. rejects cryptographically valid signature with mismatched issuer DN with 403 NAME_CHAINING_FAILED` | `validateCertificateChain` | X.509 Name Chaining: valid cryptographic signature with mismatched Issuer/Subject DN rejected | **PASS** |
| 195 | `10a. rejects attestation missing rootOfTrust in hardwareEnforced with 403 MISSING_ROOT_OF_TRUST` | `AndroidSecurityProvider` | KeyMint rootOfTrust: missing Tag 704 in hardwareEnforced rejected | **PASS** |
| 196 | `10b. rejects rootOfTrust when deviceLocked is encoded as ASN.1 INTEGER instead of strict BOOLEAN` | `AndroidSecurityProvider` | ASN.1 type confusion: deviceLocked encoded as INTEGER instead of BOOLEAN rejected | **PASS** |
| 197 | `11. client X-Test-Mode header or mock CA cannot relax root trust on official pinned provider (403 UNTRUSTED_ROOT_CA)` | `createServer` + `AndroidSecurityProvider` | Root trust immunity: client headers cannot bypass or relax official Google root pins | **PASS** |

---

### Domain 14: Trust & Revocation Cache Management
**File**: `test/trust-cache.test.ts` (8 tests)  
**Component**: `src/platform/trust.ts` (`GoogleRevocationSource`)

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 198 | `serves cached serials within TTL without invoking fetch` | `GoogleRevocationSource` | In-memory cache hit: prevents redundant HTTP fetch | **PASS** |
| 199 | `disables cache reuse when Cache-Control is max-age=0, no-cache, or no-store` | `GoogleRevocationSource` | Cache-Control directives: bypasses cache when headers require | **PASS** |
| 200 | `subtracts upstream Age header from max-age to compute remaining TTL` | `GoogleRevocationSource` | RFC 9111 Section 5.1: remaining TTL calculation | **PASS** |
| 201 | `treats response as immediately stale if Age >= max-age or Age is malformed` | `GoogleRevocationSource` | RFC 9111 freshness: stale response triggers refresh | **PASS** |
| 202 | `strictly expires at exact TTL boundary (age >= effectiveTtlMs)` | `GoogleRevocationSource` | Exact boundary expiry: entry invalid at TTL limit | **PASS** |
| 203 | `fails closed and refreshes if system clock rolls back` | `GoogleRevocationSource` | Clock rollback detection: forces refresh on backward step | **PASS** |
| 204 | `coalesces multiple concurrent refresh requests into a single in-flight fetch` | `GoogleRevocationSource` | Thundering herd protection: deduplicates in-flight requests | **PASS** |
| 205 | `fails closed with REVOCATION_STATUS_UNAVAILABLE (503) when stale and refresh fails` | `GoogleRevocationSource` | Fail-closed defense: stale cache with failed fetch returns 503 | **PASS** |

---

### Domain 15: Redis Availability Probe & Environment Gate
**File**: `test/redis-probe.test.ts` (7 tests)  
**Component**: `test/helpers/redis-probe.ts` (`checkRedisAvailable`)

| # | Exact Test Case Name | Target Component | Threat / Security Invariant | Result |
| :--- | :--- | :--- | :--- | :--- |
| 206 | `returns false when URL is undefined (allows unit-only test skips)` | `checkRedisAvailable` | Unit environment tolerance: `undefined` returns `false` without throwing | **PASS** |
| 207 | `throws sanitized REDIS_TEST_UNAVAILABLE when URL is empty or whitespace` | `checkRedisAvailable` | Input sanitization: blank or whitespace-only URL throws `REDIS_TEST_UNAVAILABLE` | **PASS** |
| 208 | `throws sanitized REDIS_TEST_UNAVAILABLE when URL is malformed or invalid protocol` | `checkRedisAvailable` | Protocol gating: non-redis protocols (`http`, `https`, `ws`, `tcp`) throw `REDIS_TEST_UNAVAILABLE` | **PASS** |
| 209 | `throws sanitized REDIS_TEST_UNAVAILABLE for unreachable host/port and does NOT leak password credentials` | `checkRedisAvailable` | Credential leakage defense: unreachable URL with password throws sanitized error without exposing credentials in message or stack | **PASS** |
| 210 | `handles blackhole TCP server (connection/HELLO hangs) with bounded timeout and cleans up socket` | `checkRedisAvailable` | Bounded connection timeout: hanging TCP server aborts within `timeoutMs` and proves client socket closes on disposal | **PASS** |
| 211 | `successfully verifies reachability for real Redis instance` | `checkRedisAvailable` | Real Redis integration: probes live Redis instance and returns `true` | **PASS** |
| 212 | `throws sanitized REDIS_TEST_UNAVAILABLE when explicit URL points to non-existent Redis server` | `checkRedisAvailable` | Explicit unavailable URL fails closed with `REDIS_TEST_UNAVAILABLE` | **PASS** |

---

## 3. Cryptographic Invariants & Upstream Provenance Verification

### 3.1 Android KeyStore Attestation
- **Upstream Pinned Roots**: Verified with official Google RSA Root (`2019/2022 SPKI`) and the new 2026 Google EC Root (`TEGU_EC_2026_ROOT`).
- **Intermediate Expiry Exception**: Verified using real Pixel 3 `blueline` 4-cert chain (`blueline/sdk28/TEE_EC_NONE.pem`). Under `profile: 'android'`, expired intermediate is accepted per Android KeyStore factory provisioning semantics; under `profile: 'strict'`, it is strictly rejected with `403 CERTIFICATE_EXPIRED`. Revoked intermediate serial is strictly rejected (`403 CERTIFICATE_REVOKED`).
- **RKP Expiry Enforcement**: Verified using Pixel 9 Pro `caiman` RKP chain (`caiman/sdk36/TEE_EC_RKP.pem`). Accepted at historical injected time `2025-09-26`; rejected at current injected time `2026-10-28` with `403 CERTIFICATE_EXPIRED`.
- **KeyMint Enforcement**: Enforces `HARDWARE_TEE_REQUIRED`, `HARDWARE_PURPOSE_SIGN_REQUIRED`, `HARDWARE_ORIGIN_GENERATED_REQUIRED`, and `HARDWARE_DIGEST_SHA256_REQUIRED`.
- **DER Signature Bounds**: Mathematically correct length bounds `8..72` bytes accepted; lengths `<8` or `>72` rejected with `401 INVALID_SIGNATURE_LENGTH`; 67-byte malformed DER rejected with `401 MALFORMED_DER_SIGNATURE`.

### 3.2 Apple App Attest
- **Leaf Nonce Extension**: Tested against literal OID `1.2.840.113635.100.8.2` requiring composite DER `SEQUENCE { [1] EXPLICIT OCTET STRING (32 bytes) }` matching `SHA256(authData || SHA256(challengeUTF8))`.
- **CMS Fraud Receipt Verification**: Verified by real `AppleReceiptVerifier` against independent Receipt CA. Mandates signer profile marker OID `1.2.840.113635.100.12.15` (ASN.1 NULL `05 00`). Rejects non-NULL marker, `isCA=true` signers, untrusted roots, attribute 2/3 mismatches, stale timestamps (>5 min), and future timestamps (>15s).
- **Assertion Signing Composite**: `crypto.sign('sha256', concat(authData, SHA256(canonicalRequest)), privateKey)`. Negative double-hash strictly rejected.
- **Flags**: Registration flags enforce AT (`0x40`) and ED (`0x80` if extensions present). Assertion flags `0x00` accepted (no UP requirement).
- **Monotonic signCount**: Tested strictly 0 -> 1 -> 2. Counter rollback and counter replay strictly rejected under both in-memory and Redis Lua storage.
- **Strict Identity Enforcement**: In [src/platform/ios.ts](../src/platform/ios.ts), `verifyRequest` requires strict equality of stored `metadata.appId` and `metadata.environment`. Omitting either identity field fails closed with 403 `APP_ID_MISMATCH` or 403 `ENVIRONMENT_MISMATCH`.

### 3.3 Storage & Persistence Integrity
- **Durable Raw Receipt Storage**: Raw CMS fraud receipt is durably persisted in the top-level hash field `'receipt'` in Redis HSET, while hot-path `getDevice` and memory caches intentionally omit `'receipt'` from HMGET fields to optimize RAM and latency.
- **BigInt CAS Sequence**: Supports sequence values exceeding 2^53 (`9007199254740993n`) in canonical buffer, HTTP headers, memory store, and Redis Lua without precision loss.
- **Fail-Closed State**: Failed signatures or invalid assertions never increment sequences or burn counters.
