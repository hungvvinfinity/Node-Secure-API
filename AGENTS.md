# AI Coding Agent Guidelines for Node-Secure-API

> **Important:** This file is the single source of truth for AI coding agents (Antigravity, Cursor, Claude Code, Copilot) working in this repository. Read and strictly adhere to all invariants, standards, and workflows described herein.

---

## 1. Project Overview & Architecture
`Node-Secure-API` is a high-assurance, defense-in-depth API gateway written in TypeScript for Node.js 24 (ESM). It provides cryptographic hardware and software attestation, anti-replay sequence tracking, and payload verification for mobile platforms (Android KeyMint/TEE and iOS Secure Enclave / App Attest).

### Directory Topology
```
src/
├── core/               # Core business logic: canonical hashing, device ID, sequence, errors, rate limiting
│   ├── canonical.ts    # Canonical request buffer construction
│   ├── device-id.ts    # SHA-256 device identifier calculation
│   ├── errors.ts       # Centralized SecurityError and SecurityErrorCode definitions
│   ├── pow.ts          # Proof-of-Work challenge generator & verifier
│   ├── rate-limiter.ts # In-flight concurrency lock & token-bucket rate limiter
│   └── security-service.ts # Main gateway security coordinator
├── platform/           # Attestation verification per platform
│   ├── android.ts      # Android KeyMint / SafetyNet / Software-tier attestation
│   ├── ios.ts          # Apple App Attest, COSE key, CBOR unpacking, receipt verification
│   ├── trust.ts        # Google CRL & Apple App Attest root CA trust manager
│   ├── x509.ts         # Pure Node.js ASN.1 & X.509 certificate chain validator
│   └── cbor.ts         # Strict CBOR decoder for authenticatorData
├── http/               # HTTP server, routing, tarpit delay & body validation
│   ├── server.ts       # Native HTTP request handler
│   └── schemas.ts      # Zod validation schemas for API boundaries
└── store/              # State persistence (Redis & in-memory)
    ├── redis.ts        # Atomic CAS sequence advance via Redis Lua scripts
    ├── memory.ts       # In-memory store for unit tests
    └── types.ts        # SecurityStore interface contracts
```

---

## 2. Inviolable Security Invariants (DO NOT VIOLATE)

1. **BigInt Sequence Integrity:**
   * Sequence counters (`sequence`, `signCount`) must strictly be treated as `bigint` or validated string representations.
   * **NEVER** convert sequence numbers to JavaScript IEEE 754 floating-point `Number` (`parseFloat`, `Number()`). Doing so causes truncation/overflow at $2^{53} - 1$ and breaks replay protection.

2. **Raw Canonical Hashing:**
   * The canonical signing payload is computed over `SHA-256(rawBodyBytes)`.
   * **NEVER** re-serialize, re-format, or parse-and-stringify the request body before hashing.
   * **NEVER** decode, normalize, or alter query parameters in the request target.

3. **No Mock Bypasses in Production:**
   * Never introduce bypass headers, relaxed validation flags, or fake root CAs outside of `test/` directory.
   * Production code must always fail-closed.

4. **Atomic Sequence Advance:**
   * All updates to device sequence numbers and sign counts must be atomic CAS operations (handled by Redis Lua scripts in `src/store/redis.ts`).

5. **ESM Module Resolution:**
   * The project runs on Node.js 24 with native ESM (`"module": "NodeNext"`).
   * **ALL relative imports MUST include the explicit `.js` extension** (e.g. `import { ... } from './canonical.js';`).

---

## 3. Coding Standards & Guardrails

* **Language:** TypeScript 5.x, target `ES2023`.
* **Type Safety:** Strict mode with `noImplicitReturns`, `noFallthroughCasesInSwitch`, `noImplicitOverride`.
  * Avoid `any`. Use `unknown` with type guards.
  * Avoid blind type assertions (`as unknown as T`).
* **Error Handling:**
  * Throw only `SecurityError` from `src/core/errors.ts` using predefined `SecurityErrorCode`.
  * Do not invent ad-hoc error string constants without declaring them in `SECURITY_ERROR_CODES`.
* **Testing:**
  * Uses Node.js native test runner (`node:test`, `node:assert/strict`, `tsx --test`).
  * **DO NOT** install or use Jest, Mocha, or Chai.
  * Regression tests must be deterministic. Do not add sub-millisecond micro-benchmarks as hard assertions in unit tests.

---

## 4. Verification Workflow (Agent Pre-Completion Checklist)

Before concluding any implementation task or claiming completion, Coding Agents **MUST** execute the following commands in sequence and ensure all pass:

```bash
# 1. Type check
npm run typecheck

# 2. Linter / Formatter check
npm run lint

# 3. Unit & Integration test suite
npm test
```
If any command fails, inspect the error output, diagnose the root cause, and correct it before ending your turn.
