/**
 * Bounded LRU Public Key Cache for P-256 EC Keys.
 *
 * Avoids expensive repeated PEM parsing on the request verification hot path.
 * Enforces EC prime256v1 / secp256r1 curves.
 * Bounded capacity prevents unbounded memory growth from arbitrary inputs.
 */

import crypto, { type KeyObject } from 'node:crypto';
import { SecurityError } from '../contracts.js';

export const DEFAULT_KEY_CACHE_MAX_ENTRIES = 4096;

export interface PublicKeyCacheOptions {
  maxEntries?: number;
}

export interface PublicKeyCacheStats {
  hits: number;
  misses: number;
  size: number;
}

export class PublicKeyCache {
  private readonly maxEntries: number;
  private readonly cache = new Map<string, KeyObject>();
  private hitCount = 0;
  private missCount = 0;

  constructor(options: PublicKeyCacheOptions = {}) {
    const max = options.maxEntries ?? DEFAULT_KEY_CACHE_MAX_ENTRIES;
    if (!Number.isInteger(max) || max <= 0) {
      throw new Error('maxEntries must be a positive integer');
    }
    this.maxEntries = max;
  }

  /**
   * Retrieves or parses an EC P-256 KeyObject from SPKI PEM string.
   * Throws SecurityError if the key is not an EC key on curve prime256v1 / secp256r1.
   */
  public getP256Key(pem: string): KeyObject {
    if (typeof pem !== 'string' || pem.trim().length === 0) {
      throw new SecurityError('INVALID_PUBLIC_KEY_PEM', 400);
    }

    const cached = this.cache.get(pem);
    if (cached) {
      this.hitCount++;
      // Promote to most recently used
      this.cache.delete(pem);
      this.cache.set(pem, cached);
      return cached;
    }

    this.missCount++;

    let keyObject: KeyObject;
    try {
      keyObject = crypto.createPublicKey(pem);
    } catch {
      throw new SecurityError('MALFORMED_PUBLIC_KEY', 400);
    }

    // Verify key type and curve
    if (keyObject.asymmetricKeyType !== 'ec') {
      throw new SecurityError('ATTESTED_KEY_NOT_EC', 403);
    }

    const curve = keyObject.asymmetricKeyDetails?.namedCurve;
    if (curve !== 'prime256v1' && curve !== 'secp256r1' && curve !== 'p256') {
      throw new SecurityError('ATTESTED_KEY_NOT_P256', 403);
    }

    // Enforce bounded LRU capacity
    if (this.cache.size >= this.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(pem, keyObject);
    return keyObject;
  }

  public get size(): number {
    return this.cache.size;
  }

  public get stats(): PublicKeyCacheStats {
    return {
      hits: this.hitCount,
      misses: this.missCount,
      size: this.cache.size,
    };
  }

  public clear(): void {
    this.cache.clear();
    this.hitCount = 0;
    this.missCount = 0;
  }
}

export const defaultPublicKeyCache = new PublicKeyCache();

export function getP256Key(pem: string): KeyObject {
  return defaultPublicKeyCache.getP256Key(pem);
}
