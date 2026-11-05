/**
 * Trust & Revocation helper for Android Key Attestation.
 *
 * Implements:
 * - Bounded timeouts covering both connection and body read
 * - Bounded response body size (2MB status, 64KB roots)
 * - Strict redirect rejection ('error')
 * - Fail-closed validation on malformed entries or unknown statuses (no skipping)
 * - Both REVOKED and SUSPENDED status revocation
 * - Upstream Cache-Control max-age bound consideration
 * - Zero request-controlled trust bypass
 * - Sanitized stable error codes
 */

import { X509Certificate as NodeX509Certificate } from 'node:crypto';
import { SecurityError } from '../contracts.js';
import { createClient, type RedisClientType } from 'redis';
import crypto from 'node:crypto';

export const GOOGLE_ATTESTATION_ROOTS_URL = 'https://android.googleapis.com/attestation/root';
export const GOOGLE_ATTESTATION_STATUS_URL = 'https://android.googleapis.com/attestation/status';

export const DEFAULT_HTTP_TIMEOUT_MS = 5000;
export const DEFAULT_REVOCATION_MAX_AGE_MS = 3600 * 1000; // 1 hour

export const MAX_STATUS_BYTES = 2 * 1024 * 1024; // 2 MB
export const MAX_ROOTS_BYTES = 64 * 1024; // 64 KB

const VALID_STATUSES = new Set(['REVOKED', 'SUSPENDED']);

/**
 * Normalizes an X.509 or CRL serial number string to canonical unpadded lowercase hex.
 * According to official Android documentation, CRL dictionary keys are lowercase hex strings.
 */
export function normalizeSerialNumber(serial: string): string {
  if (typeof serial !== 'string' || serial.trim().length === 0) {
    throw new SecurityError('MALFORMED_REVOCATION_STATUS', 502);
  }
  const clean = serial.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]+$/.test(clean)) {
    throw new SecurityError('MALFORMED_REVOCATION_STATUS', 502);
  }
  return BigInt('0x' + clean).toString(16);
}

export interface RevocationStatusEntry {
  status: string;
  reason?: string;
  comment?: string;
  expires?: string;
}

export interface RevocationStatusFile {
  entries: Record<string, RevocationStatusEntry>;
}

/**
 * Strictly parses and validates the revocation status JSON.
 * Throws MALFORMED_REVOCATION_STATUS on ANY malformed entry, unknown status,
 * or unparseable serial. Collects serials for both REVOKED and SUSPENDED.
 */
export function parseRevocationStatusJson(rawText: string): Set<string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    throw new SecurityError('MALFORMED_REVOCATION_STATUS', 502);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new SecurityError('MALFORMED_REVOCATION_STATUS', 502);
  }

  const entries = (parsed as Record<string, unknown>).entries;
  if (!entries || typeof entries !== 'object' || Array.isArray(entries)) {
    throw new SecurityError('MALFORMED_REVOCATION_STATUS', 502);
  }

  const revokedSerials = new Set<string>();

  for (const [key, value] of Object.entries(entries)) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new SecurityError('MALFORMED_REVOCATION_STATUS', 502);
    }

    // Key must be a valid hex serial
    const normalizedSerial = normalizeSerialNumber(key);

    const statusVal = (value as Record<string, unknown>).status;
    if (typeof statusVal !== 'string') {
      throw new SecurityError('MALFORMED_REVOCATION_STATUS', 502);
    }

    const upperStatus = statusVal.toUpperCase();
    if (!VALID_STATUSES.has(upperStatus)) {
      // Unknown status in entry: fail-closed, do not silently skip
      throw new SecurityError('MALFORMED_REVOCATION_STATUS', 502);
    }

    // Both REVOKED and SUSPENDED certificates must be treated as revoked
    revokedSerials.add(normalizedSerial);
  }

  return revokedSerials;
}

/**
 * Validates and parses the raw roots JSON into an array of validated certificate PEM strings.
 * Ensures every item in the JSON is a valid X.509 certificate.
 */
export function parseRootsJson(rawText: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    throw new SecurityError('MALFORMED_ROOTS_RESPONSE', 502);
  }

  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new SecurityError('MALFORMED_ROOTS_RESPONSE', 502);
  }

  const roots: string[] = [];
  for (const item of parsed) {
    if (typeof item !== 'string' || !item.includes('-----BEGIN CERTIFICATE-----')) {
      throw new SecurityError('MALFORMED_ROOTS_RESPONSE', 502);
    }
    const pem = item.trim();
    try {
      // Validate that it actually parses as an X.509 certificate
      new NodeX509Certificate(pem);
    } catch {
      throw new SecurityError('MALFORMED_ROOTS_RESPONSE', 502);
    }
    roots.push(pem);
  }
  return roots;
}

/**
 * Reads response body with strict byte limit and applies timeout.
 */
async function readBoundedText(res: Response, maxBytes: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) {
    return res.text();
  }

  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        try {
          await reader.cancel();
        } catch {
          // ignore
        }
        throw new SecurityError('RESPONSE_BODY_TOO_LARGE', 502);
      }
      chunks.push(value);
    }
  }

  const merged = Buffer.concat(chunks);
  return merged.toString('utf8');
}

/**
 * Parses Cache-Control max-age header if present.
 */
export function parseCacheControlMaxAge(headerValue: string | null): number | null {
  if (!headerValue) return null;
  const directives = headerValue.split(',').map(value => value.trim().toLowerCase());
  if (directives.some(value => /^(no-cache|no-store)(?:\s*=|$)/.test(value))) return 0;
  const ages: number[] = [];
  for (const directive of directives) {
    if (!/^max-age\b/.test(directive)) continue;
    const match = directive.match(/^max-age\s*=\s*"?(\d+)"?$/);
    if (!match) return 0;
    const milliseconds = Number(match[1]) * 1000;
    if (!Number.isSafeInteger(milliseconds)) return 0;
    ages.push(milliseconds);
  }
  return ages.length ? Math.min(...ages) : null;
}

export interface TrustFetchOptions {
  url?: string;
  timeoutMs?: number;
  fetchFn?: typeof fetch;
}

/**
 * Fetches Google Attestation Trust Anchors from official Google endpoint.
 */
export async function fetchGoogleTrustAnchors(options: TrustFetchOptions = {}): Promise<string[]> {
  const url = options.url ?? GOOGLE_ATTESTATION_ROOTS_URL;
  const timeoutMs = options.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
  const fetchFn = options.fetchFn ?? fetch;

  const res = await fetchFn(url, {
    method: 'GET',
    redirect: 'error',
    signal: AbortSignal.timeout(timeoutMs),
  }).catch(() => {
    throw new SecurityError('FAILED_TO_FETCH_ROOTS', 502);
  });

  if (!res.ok) {
    throw new SecurityError('FAILED_TO_FETCH_ROOTS', 502);
  }

  const bodyText = await readBoundedText(res, MAX_ROOTS_BYTES);
  return parseRootsJson(bodyText);
}

export interface RevocationFetchResult {
  serials: Set<string>;
  cacheMaxAgeMs: number | null;
}

/**
 * Fetches Google Attestation Revocation Status from official Google endpoint.
 */
export async function fetchGoogleRevocationStatus(
  options: TrustFetchOptions = {},
): Promise<RevocationFetchResult> {
  const url = options.url ?? GOOGLE_ATTESTATION_STATUS_URL;
  const timeoutMs = options.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
  const fetchFn = options.fetchFn ?? fetch;

  const res = await fetchFn(url, {
    method: 'GET',
    redirect: 'error',
    signal: AbortSignal.timeout(timeoutMs),
  }).catch(() => {
    throw new SecurityError('FAILED_TO_FETCH_REVOCATION_STATUS', 502);
  });

  if (!res.ok) {
    throw new SecurityError('FAILED_TO_FETCH_REVOCATION_STATUS', 502);
  }

  const cacheControl = res.headers.get('cache-control');
  let cacheMaxAgeMs = parseCacheControlMaxAge(cacheControl);
  const ageHeader = res.headers.get('age');
  if (cacheMaxAgeMs !== null && ageHeader !== null) {
    const ageMs = /^\d+$/.test(ageHeader) ? Number(ageHeader) * 1000 : NaN;
    cacheMaxAgeMs = Number.isSafeInteger(ageMs) ? Math.max(0, cacheMaxAgeMs - ageMs) : 0;
  }

  const bodyText = await readBoundedText(res, MAX_STATUS_BYTES);
  const serials = parseRevocationStatusJson(bodyText);

  return { serials, cacheMaxAgeMs };
}

export interface RevocationSource {
  getRevokedSerials(): Promise<Set<string>>;
}

export interface GoogleRevocationSourceOptions {
  url?: string;
  timeoutMs?: number;
  maxAgeMs?: number;
  fetchFn?: typeof fetch;
  now?: () => number;
  redisUrl?: string;
  redisKeyPrefix?: string;
  redisClient?: RedisClientType;
}

interface RevocationSnapshot {
  readonly serials: Set<string>;
  readonly fetchedAt: number;
  readonly effectiveTtlMs: number;
}

/**
 * Production revocation source for Android Key Attestation.
 * Caches status with bounded freshness, refreshes atomically, and fails closed
 * if the status cannot be refreshed and the cache is stale or empty.
 */
export class GoogleRevocationSource implements RevocationSource {
  private readonly url: string;
  private readonly timeoutMs: number;
  private readonly configuredMaxAgeMs: number;
  private readonly fetchFn: typeof fetch;
  private readonly now: () => number;
  private readonly redisClient?: RedisClientType;
  private readonly ownsRedis: boolean;
  private readonly redisPrefix: string;

  private snapshot: RevocationSnapshot | null = null;
  private inFlightRefresh: Promise<Set<string>> | null = null;

  constructor(options: GoogleRevocationSourceOptions = {}) {
    this.url = options.url ?? GOOGLE_ATTESTATION_STATUS_URL;

    const timeout = options.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
    if (!Number.isFinite(timeout) || timeout <= 0) {
      throw new SecurityError('INVALID_TIMEOUT_MS', 500);
    }
    this.timeoutMs = timeout;

    const maxAge = options.maxAgeMs ?? DEFAULT_REVOCATION_MAX_AGE_MS;
    if (!Number.isFinite(maxAge) || maxAge <= 0) {
      throw new SecurityError('INVALID_MAX_AGE_MS', 500);
    }
    this.configuredMaxAgeMs = maxAge;

    this.fetchFn = options.fetchFn ?? fetch;
    this.now = options.now ?? Date.now;
    this.redisClient=options.redisClient ?? (options.redisUrl ? createClient({url:options.redisUrl,disableOfflineQueue:true}) as RedisClientType : undefined);
    this.ownsRedis=Boolean(options.redisUrl && !options.redisClient);
    this.redisPrefix=options.redisKeyPrefix ?? 'sec:';
  }

  /**
   * Returns true if the cache contains a valid, non-stale snapshot.
   */
  public isReady(): boolean {
    if (!this.snapshot) return false;
    const currentTime = this.now();
    const age = currentTime - this.snapshot.fetchedAt;
    return age >= 0 && age < this.snapshot.effectiveTtlMs;
  }

  /**
   * Explicitly triggers an atomic refresh.
   */
  public async refresh(): Promise<Set<string>> {
    if (this.inFlightRefresh) {
      return this.inFlightRefresh;
    }

    this.inFlightRefresh = this.executeRefresh().finally(() => {
      this.inFlightRefresh = null;
    });

    return this.inFlightRefresh;
  }

  public async getRevokedSerials(): Promise<Set<string>> {
    const currentTime = this.now();

    // Check existing snapshot freshness
    if (this.snapshot) {
      const age = currentTime - this.snapshot.fetchedAt;
      if (age >= 0 && age < this.snapshot.effectiveTtlMs) {
        return this.snapshot.serials;
      }
    }

    // Stale or missing snapshot: must refresh
    return this.refresh();
  }

  private async executeRefresh(): Promise<Set<string>> {
    if (this.redisClient) {
      try {
        if (!this.redisClient.isReady) await this.redisClient.connect();
        const cached=await this.redisClient.get(this.redisPrefix+'crl:snapshot');
        if(cached){ const value=JSON.parse(cached) as {serials:string[];expiresAt:number}; if(value.expiresAt>this.now()){ this.snapshot={serials:new Set(value.serials),fetchedAt:this.now(),effectiveTtlMs:value.expiresAt-this.now()}; return this.snapshot.serials; } }
        const token=crypto.randomUUID();
        const lock=await this.redisClient.set(this.redisPrefix+'lock:crl',token,{NX:true,EX:30});
        if(lock!=='OK') { await new Promise(r=>setTimeout(r,1000)); const waitValue=await this.redisClient.get(this.redisPrefix+'crl:snapshot'); if(waitValue){const v=JSON.parse(waitValue) as {serials:string[];expiresAt:number}; if(v.expiresAt>this.now()){this.snapshot={serials:new Set(v.serials),fetchedAt:this.now(),effectiveTtlMs:v.expiresAt-this.now()};return this.snapshot.serials;}} }
        else {
          try { const res=await this.fetchAndCacheRedis(); return res; }
          finally { await this.redisClient.eval("if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end",{keys:[this.redisPrefix+'lock:crl'],arguments:[token]}).catch(()=>{}); }
        }
      } catch { /* Redis failure falls back to direct upstream fetch. */ }
    }
    return this.fetchAndCacheRedis(false);
  }

  private async fetchAndCacheRedis(cacheRedis = true): Promise<Set<string>> {
    const fetchTime = this.now();
    let result: RevocationFetchResult;

    try {
      result = await fetchGoogleRevocationStatus({
        url: this.url,
        timeoutMs: this.timeoutMs,
        fetchFn: this.fetchFn,
      });
    } catch {
      // Fail closed: do not extend stale snapshot
      throw new SecurityError('REVOCATION_STATUS_UNAVAILABLE', 503);
    }

    // Determine effective TTL: respect upstream max-age if shorter than configured
    let effectiveTtl = this.configuredMaxAgeMs;
    if (result.cacheMaxAgeMs !== null && result.cacheMaxAgeMs >= 0 && result.cacheMaxAgeMs < effectiveTtl) {
      effectiveTtl = result.cacheMaxAgeMs;
    }

    // Atomic snapshot replacement
    this.snapshot = {
      serials: result.serials,
      fetchedAt: fetchTime,
      effectiveTtlMs: effectiveTtl,
    };
    if(cacheRedis && this.redisClient?.isReady) {
      const ttl=Math.max(1,Math.ceil(effectiveTtl/1000));
      await this.redisClient.set(this.redisPrefix+'crl:snapshot',JSON.stringify({serials:[...result.serials],expiresAt:fetchTime+effectiveTtl}),{EX:ttl}).catch(()=>{});
    }

    return result.serials;
  }

  public async close(): Promise<void> {
    if (this.ownsRedis && this.redisClient?.isOpen) {
      await this.redisClient.quit().catch(() => {});
    }
  }
}
