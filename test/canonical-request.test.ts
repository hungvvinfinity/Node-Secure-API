import test, { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildCanonicalString, buildCanonicalBuffer } from '../src/core/canonical.js';
import { SecurityService } from '../src/core/security-service.js';
import { MemorySecurityStore } from '../src/store/memory.js';
import { SecurityError, type DeviceRecord, type DeviceSecurityProvider, type RequestProof } from '../src/contracts.js';
import { signCanonical, createAttestationChain } from './helpers/crypto-fixtures.js';

/**
 * Standard ECDSA P-256 request verifier matching production Android provider verification.
 */
class AndroidRequestVerifier implements DeviceSecurityProvider {
  readonly platform = 'android' as const;

  async verifyRegistration(): Promise<any> {
    throw new Error('Not implemented for canonical suite');
  }

  async verifyRequest(device: DeviceRecord, proof: RequestProof): Promise<{ signCount?: number }> {
    const isMatch = crypto.verify(
      'sha256',
      proof.canonical,
      device.publicKeyPem,
      Buffer.from(proof.signature || '', 'base64')
    );
    if (!isMatch) {
      throw new SecurityError('INVALID_SIGNATURE', 401);
    }
    return {};
  }
}

describe('Canonical Request & Wire Integrity Tests', () => {
  const EMPTY_BODY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  let store: MemorySecurityStore;
  let service: SecurityService;
  let fixedNow: number;
  let fixture: Awaited<ReturnType<typeof createAttestationChain>>;
  let registeredDevice: DeviceRecord;

  beforeEach(async () => {
    fixedNow = 1729800000000;
    store = new MemorySecurityStore();
    service = new SecurityService({
      store,
      providers: [new AndroidRequestVerifier()],
      now: () => fixedNow
    });

    fixture = await createAttestationChain();
    registeredDevice = {
      deviceId: fixture.deviceId,
      platform: 'android',
      publicKeyPem: fixture.leafPublicKeyPem,
      lastSequence: '0',
      registeredAt: fixedNow,
      metadata: {}
    };
    await store.createDeviceNX(registeredDevice);
  });

  it('builds exact canonical string without trailing newline or padding', () => {
    const timestamp = '1729800000000';
    const sequence = '1';
    const method = 'POST';
    const target = '/api/tarot/read';
    const rawBody = Buffer.from('{"question":"future"}', 'utf8');
    const expectedBodySha = crypto.createHash('sha256').update(rawBody).digest('hex');

    const canonical = buildCanonicalString(timestamp, sequence, method, target, rawBody);
    const expected = `${timestamp}:${sequence}:${method}:${target}:${expectedBodySha}`;

    assert.equal(canonical, expected);
    assert.ok(!canonical.endsWith('\n'), 'Must not have trailing newline');
    assert.ok(!canonical.endsWith('\r'), 'Must not have carriage return');
  });

  it('normalizes method to uppercase in production canonical pipeline', () => {
    const rawBody = Buffer.alloc(0);
    const canonicalLower = buildCanonicalString('1000', '1', 'post', '/api/tarot/read', rawBody);
    const canonicalUpper = buildCanonicalString('1000', '1', 'POST', '/api/tarot/read', rawBody);

    assert.equal(canonicalLower, canonicalUpper);
    assert.ok(canonicalLower.includes(':POST:'));
  });

  it('preserves empty body SHA-256 hash in canonical string', () => {
    const canonical = buildCanonicalString('1000', '1', 'POST', '/api/tarot/read', Buffer.alloc(0));
    assert.ok(canonical.endsWith(`:${EMPTY_BODY_SHA256}`));
  });

  it('preserves exact wire request-target without decoding or reordering query parameters', () => {
    const targetWithEncoded = '/api/tarot/read?z=99&a=%2Fsecret&b=1%202';
    const canonical = buildCanonicalString('1000', '1', 'POST', targetWithEncoded, Buffer.alloc(0));

    assert.ok(canonical.includes(`:${targetWithEncoded}:`), 'Target must remain exact byte-for-byte');
    assert.ok(!canonical.includes('/secret'), 'Must not URL-decode parameters');
  });

  it('detects 1-bit whitespace mutation CR(0x0d) -> TAB(0x09) via SecurityService.authenticateRequest', async () => {
    // Design regression: changing \r (0x0d = 00001101) to \t (0x09 = 00001001) is exactly 1 bit.
    // JSON parsers strip or normalize this, but rawBody SHA-256 must catch it!
    const originalBody = Buffer.from('{"tarot":\r"the-sun"}', 'utf8');
    const mutatedBody = Buffer.from('{"tarot":\t"the-sun"}', 'utf8');

    // Confirm the exact 1-bit difference
    assert.equal(originalBody[9] ^ mutatedBody[9], 0b00000100, 'Must be exact 1-bit difference');

    const timestamp = String(fixedNow);
    const sequence = '1';
    const method = 'POST';
    const target = '/api/tarot/read';

    // Sign the original body bytes
    const originalCanonical = buildCanonicalBuffer(timestamp, sequence, method, target, originalBody);
    const signature = signCanonical(fixture.leafPrivateKeyPem, originalCanonical);

    // 1. Authenticating with original body succeeds through production SecurityService
    const authOk = await service.authenticateRequest({
      deviceId: registeredDevice.deviceId,
      timestamp,
      sequence,
      signature,
      method,
      requestTarget: target,
      rawBody: originalBody
    });
    assert.equal(authOk.device.deviceId, registeredDevice.deviceId);

    // 2. Tampered body with 1-bit whitespace mutation fails in production SecurityService
    const nextSeq = '2';
    const canonicalForNext = buildCanonicalBuffer(timestamp, nextSeq, method, target, originalBody);
    const sigForNext = signCanonical(fixture.leafPrivateKeyPem, canonicalForNext);

    await assert.rejects(
      async () => {
        await service.authenticateRequest({
          deviceId: registeredDevice.deviceId,
          timestamp,
          sequence: nextSeq,
          signature: sigForNext,
          method,
          requestTarget: target,
          rawBody: mutatedBody // 1-bit whitespace tampered!
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof SecurityError, 'Expected SecurityError');
        assert.equal(err.code, 'INVALID_SIGNATURE');
        assert.equal(err.status, 401);
        return true;
      }
    );
  });

  it('rejects query parameter reordering or mutation through SecurityService.authenticateRequest', async () => {
    const rawBody = Buffer.from('{"query":true}', 'utf8');
    const originalTarget = '/api/tarot/read?page=1&size=20';
    const reorderedTarget = '/api/tarot/read?size=20&page=1';

    const timestamp = String(fixedNow);
    const sequence = '10';

    const canonicalOriginal = buildCanonicalBuffer(timestamp, sequence, 'GET', originalTarget, rawBody);
    const signature = signCanonical(fixture.leafPrivateKeyPem, canonicalOriginal);

    // Verifying with reordered target must throw INVALID_SIGNATURE
    await assert.rejects(
      async () => {
        await service.authenticateRequest({
          deviceId: registeredDevice.deviceId,
          timestamp,
          sequence,
          signature,
          method: 'GET',
          requestTarget: reorderedTarget, // Tampered query target!
          rawBody
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INVALID_SIGNATURE');
        assert.equal(err.status, 401);
        return true;
      }
    );
  });

  it('rejects HTTP method alteration through SecurityService.authenticateRequest', async () => {
    const rawBody = Buffer.from('{}', 'utf8');
    const target = '/api/tarot/read';
    const timestamp = String(fixedNow);
    const sequence = '15';

    // Sign for POST
    const canonical = buildCanonicalBuffer(timestamp, sequence, 'POST', target, rawBody);
    const signature = signCanonical(fixture.leafPrivateKeyPem, canonical);

    // Request comes as PUT
    await assert.rejects(
      async () => {
        await service.authenticateRequest({
          deviceId: registeredDevice.deviceId,
          timestamp,
          sequence,
          signature,
          method: 'PUT',
          requestTarget: target,
          rawBody
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INVALID_SIGNATURE');
        assert.equal(err.status, 401);
        return true;
      }
    );
  });

  it('authenticates sequence > 2^53 successfully via SecurityService', async () => {
    // 2^53 + 1 is 9007199254740993n.
    const hugeSeq = '9007199254740993';
    const rawBody = Buffer.from('{"level":"high"}', 'utf8');
    const target = '/api/tarot/read';
    const timestamp = String(fixedNow);

    const canonical = buildCanonicalBuffer(timestamp, hugeSeq, 'POST', target, rawBody);
    const signature = signCanonical(fixture.leafPrivateKeyPem, canonical);

    const authContext = await service.authenticateRequest({
      deviceId: registeredDevice.deviceId,
      timestamp,
      sequence: hugeSeq,
      signature,
      method: 'POST',
      requestTarget: target,
      rawBody
    });

    assert.equal(authContext.sequence, hugeSeq);
    assert.equal(authContext.device.lastSequence, hugeSeq);
  });

  it('rejects malformed sequence formats in SecurityService.authenticateRequest with INVALID_SEQUENCE (400)', async () => {
    const invalidSequences = [
      '0', // Must be positive (> 0)
      '01', // Leading zero prohibited
      '007', // Leading zero prohibited
      '-1', // Negative prohibited
      '+5', // Explicit plus sign prohibited
      '1.0', // Float prohibited
      '1e5', // Scientific notation prohibited
      'abc', // Non-digit prohibited
      '123a', // Alphanumeric prohibited
      ' 123', // Leading whitespace prohibited
      '123 ', // Trailing whitespace prohibited
      '9223372036854775808' // Exceeds signed int64 max
    ];

    const rawBody = Buffer.alloc(0);
    const target = '/api/tarot/read';
    const timestamp = String(fixedNow);

    for (const badSeq of invalidSequences) {
      await assert.rejects(
        async () => {
          await service.authenticateRequest({
            deviceId: registeredDevice.deviceId,
            timestamp,
            sequence: badSeq,
            signature: 'dummy-sig',
            method: 'POST',
            requestTarget: target,
            rawBody
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError, `Expected SecurityError for sequence '${badSeq}'`);
          assert.equal(err.code, 'INVALID_SEQUENCE');
          assert.equal(err.status, 400);
          return true;
        }
      );
    }
  });

  it('validates 15s timestamp freshness window via SecurityService.authenticateRequest', async () => {
    const rawBody = Buffer.alloc(0);
    const target = '/api/tarot/read';

    // 1. Boundary: exactly 15000 ms in the past -> Accepted
    const validPastTs = String(fixedNow - 15000);
    const canonicalPast = buildCanonicalBuffer(validPastTs, '1', 'POST', target, rawBody);
    const sigPast = signCanonical(fixture.leafPrivateKeyPem, canonicalPast);

    const pastResult = await service.authenticateRequest({
      deviceId: registeredDevice.deviceId,
      timestamp: validPastTs,
      sequence: '1',
      signature: sigPast,
      method: 'POST',
      requestTarget: target,
      rawBody
    });
    assert.equal(pastResult.sequence, '1');

    // 2. Boundary: exactly 15000 ms in the future -> Accepted
    const validFutureTs = String(fixedNow + 15000);
    const canonicalFuture = buildCanonicalBuffer(validFutureTs, '2', 'POST', target, rawBody);
    const sigFuture = signCanonical(fixture.leafPrivateKeyPem, canonicalFuture);

    const futureResult = await service.authenticateRequest({
      deviceId: registeredDevice.deviceId,
      timestamp: validFutureTs,
      sequence: '2',
      signature: sigFuture,
      method: 'POST',
      requestTarget: target,
      rawBody
    });
    assert.equal(futureResult.sequence, '2');

    // 3. Expired: 15001 ms in the past -> Rejected with EXPIRED_TIMESTAMP (401)
    const expiredPastTs = String(fixedNow - 15001);
    await assert.rejects(
      async () => {
        await service.authenticateRequest({
          deviceId: registeredDevice.deviceId,
          timestamp: expiredPastTs,
          sequence: '3',
          signature: 'dummy-sig',
          method: 'POST',
          requestTarget: target,
          rawBody
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'EXPIRED_TIMESTAMP');
        assert.equal(err.status, 401);
        return true;
      }
    );

    // 4. Expired: 15001 ms in the future -> Rejected with EXPIRED_TIMESTAMP (401)
    const expiredFutureTs = String(fixedNow + 15001);
    await assert.rejects(
      async () => {
        await service.authenticateRequest({
          deviceId: registeredDevice.deviceId,
          timestamp: expiredFutureTs,
          sequence: '4',
          signature: 'dummy-sig',
          method: 'POST',
          requestTarget: target,
          rawBody
        });
      },
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'EXPIRED_TIMESTAMP');
        assert.equal(err.status, 401);
        return true;
      }
    );

    // 5. Malformed timestamp string -> Rejected with INVALID_TIMESTAMP (400)
    for (const badTs of ['abc', '-100', '0', '1.5', '17298 000']) {
      await assert.rejects(
        async () => {
          await service.authenticateRequest({
            deviceId: registeredDevice.deviceId,
            timestamp: badTs,
            sequence: '5',
            signature: 'dummy-sig',
            method: 'POST',
            requestTarget: target,
            rawBody
          });
        },
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_TIMESTAMP');
          assert.equal(err.status, 400);
          return true;
        }
      );
    }
  });
});
