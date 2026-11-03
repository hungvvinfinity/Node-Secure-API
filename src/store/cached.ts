/**
 * Caching Security Store Decorator.
 *
 * Implements a bounded LRU cache for DeviceRecord identity, public keys, and metadata.
 *
 * Core architectural invariants:
 * - NEVER trusts cached sequence/counter for final acceptance: commitSequence ALWAYS delegates to durable inner store
 * - getDevice cache hit returns structuredClone (defensive copying against mutation)
 * - commitSequence success updates cached sequence and signCount for liveness
 * - commitSequence NOT_FOUND or KEY_MISMATCH invalidates cached record
 * - createDeviceNX only caches on success (created === true)
 * - saveChallenge and consumeChallenge always bypass cache and use durable inner store
 * - Strips large receipt bytes from cached metadata while preserving durable receipt
 * - ping and close delegate to durable inner store; close clears volatile cache
 */

import type { DeviceRecord, Platform } from '../contracts.js';
import type { CommitResult, SecurityStore } from './types.js';

export const DEFAULT_CACHE_MAX_ENTRIES = 4096;
export const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

export interface CachingSecurityStoreOptions {
  maxEntries?: number;
  ttlMs?: number;
  now?: () => number;
}

interface CacheEntry {
  record: DeviceRecord;
  cachedAt: number;
}

export interface CacheStats {
  hits: number;
  misses: number;
  size: number;
}

/**
 * Strips binary/large receipt fields from device metadata before caching in RAM.
 */
function sanitizeMetadataForCache(metadata: Record<string, unknown>): Record<string, unknown> {
  const {
    receipt,
    ...cleanMetadata
  } = metadata;
  return cleanMetadata;
}

export class CachingSecurityStore implements SecurityStore {
  private readonly inner: SecurityStore;
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly now: () => number;
  private readonly cache = new Map<string, CacheEntry>();

  private hitCount = 0;
  private missCount = 0;

  constructor(inner: SecurityStore, options: CachingSecurityStoreOptions = {}) {
    if (!inner || typeof inner !== 'object') {
      throw new Error('inner SecurityStore is required');
    }
    this.inner = inner;

    const max = options.maxEntries ?? DEFAULT_CACHE_MAX_ENTRIES;
    if (!Number.isInteger(max) || max <= 0) {
      throw new Error('maxEntries must be a positive integer');
    }
    this.maxEntries = max;

    const ttl = options.ttlMs ?? DEFAULT_CACHE_TTL_MS;
    if (!Number.isInteger(ttl) || ttl <= 0) {
      throw new Error('ttlMs must be a positive integer');
    }
    this.ttlMs = ttl;

    this.now = options.now ?? (() => Date.now());
  }

  public async saveChallenge(challenge: string, platform: Platform, ttlSeconds: number, salt?: string): Promise<void> {
    // Challenge operations are strictly durable and never cached
    return this.inner.saveChallenge(challenge, platform, ttlSeconds, salt);
  }

  public async consumeChallenge(challenge: string): Promise<{ platform: Platform; salt?: string } | null> {
    // Challenge consumption must be atomic and durable
    return this.inner.consumeChallenge(challenge);
  }

  public async createDeviceNX(device: DeviceRecord): Promise<boolean> {
    // Always attempt durable creation first
    const created = await this.inner.createDeviceNX(device);
    if (created) {
      // Cache stripped record on successful durable insertion
      const cachedRecord = structuredClone(device);
      if (cachedRecord.metadata && typeof cachedRecord.metadata === 'object') {
        cachedRecord.metadata = sanitizeMetadataForCache(cachedRecord.metadata);
      }

      this.putInLru(device.deviceId, cachedRecord);
    }
    return created;
  }

  public async getDevice(deviceId: string): Promise<DeviceRecord | null> {
    const currentTime = this.now();
    const entry = this.cache.get(deviceId);

    if (entry) {
      const age = currentTime - entry.cachedAt;
      const leaseExpired = entry.record.expiresAt !== undefined && currentTime >= entry.record.expiresAt;
      if (!leaseExpired && age >= 0 && age < this.ttlMs) {
        this.hitCount++;
        // Promote to most recently used
        this.cache.delete(deviceId);
        this.cache.set(deviceId, entry);
        // Return defensive copy
        return structuredClone(entry.record);
      }
      // Expired entry
      this.cache.delete(deviceId);
    }

    this.missCount++;
    const device = await this.inner.getDevice(deviceId);
    if (!device) {
      return null;
    }

    // Cache sanitized defensive copy
    const cachedRecord = structuredClone(device);
    if (cachedRecord.metadata && typeof cachedRecord.metadata === 'object') {
      cachedRecord.metadata = sanitizeMetadataForCache(cachedRecord.metadata);
    }

    this.putInLru(deviceId, cachedRecord);
    return structuredClone(cachedRecord);
  }

  public async commitSequence(
    deviceId: string,
    expectedPublicKeyPem: string,
    newSequence: string,
    newSignCount?: number,
  ): Promise<CommitResult> {
    // NEVER trust cached sequence/counter for final acceptance:
    // ALWAYS delegate to durable inner store
    const result = await this.inner.commitSequence(deviceId, expectedPublicKeyPem, newSequence, newSignCount);

    if (result.ok) {
      // On success, update cached sequence and signCount for liveness
      const entry = this.cache.get(deviceId);
      if (entry) {
        entry.record.lastSequence = newSequence;
        if (newSignCount !== undefined) {
          entry.record.signCount = newSignCount;
        }
        // Promote in LRU
        this.cache.delete(deviceId);
        this.cache.set(deviceId, entry);
      }
    } else if (result.reason === 'NOT_FOUND' || result.reason === 'KEY_MISMATCH') {
      // Invalidate cached record on structural mismatch or deletion
      this.cache.delete(deviceId);
    }

    return result;
  }

  public async ping(): Promise<boolean> {
    return this.inner.ping();
  }

  public async close(): Promise<void> {
    // Clear volatile cache
    this.cache.clear();
    this.hitCount = 0;
    this.missCount = 0;
    return this.inner.close();
  }

  public get size(): number {
    return this.cache.size;
  }

  public get stats(): CacheStats {
    return {
      hits: this.hitCount,
      misses: this.missCount,
      size: this.cache.size,
    };
  }

  public invalidate(deviceId: string): void {
    this.cache.delete(deviceId);
  }

  public clear(): void {
    this.cache.clear();
    this.hitCount = 0;
    this.missCount = 0;
  }

  private putInLru(deviceId: string, record: DeviceRecord): void {
    if (this.cache.has(deviceId)) {
      this.cache.delete(deviceId);
    } else if (this.cache.size >= this.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }
    this.cache.set(deviceId, {
      record,
      cachedAt: this.now(),
    });
  }
}
