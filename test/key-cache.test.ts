import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { PublicKeyCache } from '../src/platform/key-cache.js';
import { SecurityError } from '../src/contracts.js';

describe('PublicKeyCache (Bounded LRU Cryptographic Key Parsing Cache)', () => {
  it('parses valid EC P-256 SPKI PEM and caches KeyObject across repeated calls', () => {
    const cache = new PublicKeyCache({ maxEntries: 10 });
    const ecKey = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pem = ecKey.publicKey.export({ type: 'spki', format: 'pem' }) as string;

    assert.equal(cache.stats.hits, 0);
    assert.equal(cache.stats.misses, 0);

    // 1. Initial call: cache miss, parses PEM
    const key1 = cache.getP256Key(pem);
    assert.ok(key1);
    assert.equal(key1.asymmetricKeyType, 'ec');
    assert.equal(cache.stats.misses, 1);
    assert.equal(cache.stats.hits, 0);
    assert.equal(cache.size, 1);

    // 2. Second call: cache hit, returns cached KeyObject
    const key2 = cache.getP256Key(pem);
    assert.strictEqual(key1, key2);
    assert.equal(cache.stats.hits, 1);
    assert.equal(cache.stats.misses, 1);
  });

  it('rejects RSA public key with 403 ATTESTED_KEY_NOT_EC', () => {
    const cache = new PublicKeyCache();
    const rsaKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rsaPem = rsaKey.publicKey.export({ type: 'spki', format: 'pem' }) as string;

    assert.throws(
      () => cache.getP256Key(rsaPem),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'ATTESTED_KEY_NOT_EC');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  it('rejects non-P256 EC keys (e.g. secp384r1 / P-384) with 403 ATTESTED_KEY_NOT_P256', () => {
    const cache = new PublicKeyCache();
    const p384Key = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    const p384Pem = p384Key.publicKey.export({ type: 'spki', format: 'pem' }) as string;

    assert.throws(
      () => cache.getP256Key(p384Pem),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'ATTESTED_KEY_NOT_P256');
        assert.equal(err.status, 403);
        return true;
      }
    );
  });

  it('rejects empty or whitespace PEM with 400 INVALID_PUBLIC_KEY_PEM', () => {
    const cache = new PublicKeyCache();
    assert.throws(
      () => cache.getP256Key('   '),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INVALID_PUBLIC_KEY_PEM');
        assert.equal(err.status, 400);
        return true;
      }
    );
  });

  it('rejects malformed PEM with 400 MALFORMED_PUBLIC_KEY', () => {
    const cache = new PublicKeyCache();
    assert.throws(
      () => cache.getP256Key('-----BEGIN PUBLIC KEY-----\nNOT_BASE64!\n-----END PUBLIC KEY-----'),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'MALFORMED_PUBLIC_KEY');
        assert.equal(err.status, 400);
        return true;
      }
    );
  });

  it('enforces bounded LRU eviction when capacity is reached', () => {
    const cache = new PublicKeyCache({ maxEntries: 2 });
    const key1 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pem1 = key1.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const key2 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pem2 = key2.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const key3 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pem3 = key3.publicKey.export({ type: 'spki', format: 'pem' }) as string;

    cache.getP256Key(pem1);
    cache.getP256Key(pem2);
    assert.equal(cache.size, 2);

    // Adding pem3 must evict pem1 (oldest)
    cache.getP256Key(pem3);
    assert.equal(cache.size, 2);

    // pem1 should now be a miss again
    const missesBefore = cache.stats.misses;
    cache.getP256Key(pem1);
    assert.equal(cache.stats.misses, missesBefore + 1);
  });

  it('clears cache on clear()', () => {
    const cache = new PublicKeyCache({ maxEntries: 5 });
    const key = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pem = key.publicKey.export({ type: 'spki', format: 'pem' }) as string;

    cache.getP256Key(pem);
    assert.equal(cache.size, 1);

    cache.clear();
    assert.equal(cache.size, 0);
  });
});
