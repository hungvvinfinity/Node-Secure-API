import { Decoder } from 'cbor-x';
import { SecurityError } from '../contracts.js';

export interface CborValidationOptions {
  maxBytes?: number;
  maxDepth?: number;
  maxNodes?: number;
  allowMultiple?: boolean;
}
const decoder = new Decoder({ mapsAsObjects: false, useRecords: false });
const utf8 = new TextDecoder('utf-8', { fatal: true });
const fail = (code: string): never => { throw new SecurityError(code, 400); };

/** Preflight before library decoding: bounded trees, scalar keys, semantic duplicates, no tags/indefinites. */
export function scanCbor(buffer: Buffer, options: CborValidationOptions = {}): { itemCount: number; bytesRead: number } {
  const maxBytes = options.maxBytes ?? 256 * 1024;
  const maxDepth = options.maxDepth ?? 16;
  const maxNodes = options.maxNodes ?? 4096;
  if (![maxBytes, maxDepth, maxNodes].every(n => Number.isSafeInteger(n) && n > 0) ||
      maxBytes > 1024 * 1024 || maxDepth > 32 || maxNodes > 16384) throw new Error('Invalid CBOR limits');
  if (!Buffer.isBuffer(buffer)) return fail('INVALID_CBOR_PAYLOAD');
  if (!buffer.length) return fail('EMPTY_CBOR_PAYLOAD');
  if (buffer.length > maxBytes) return fail('CBOR_PAYLOAD_TOO_LARGE');
  let offset = 0;
  let nodes = 0;
  let itemCount = 0;
  const take = (length: number): Buffer => {
    if (length > buffer.length - offset) return fail('TRUNCATED_CBOR_PAYLOAD');
    const value = buffer.subarray(offset, offset + length);
    offset += length;
    return value;
  };
  const argument = (additional: number): bigint => {
    if (additional < 24) return BigInt(additional);
    if (additional > 27) return fail(additional === 31 ? 'INDEFINITE_LENGTH_CBOR' : 'INVALID_CBOR_PAYLOAD');
    const length = 2 ** (additional - 24);
    const bytes = take(length);
    let value = 0n;
    for (const byte of bytes) value = value * 256n + BigInt(byte);
    return value;
  };
  function item(depth: number, asKey = false): string | undefined {
    if (depth > maxDepth) return fail('CBOR_DEPTH_EXCEEDED');
    if (++nodes > maxNodes) return fail('CBOR_NODE_COUNT_EXCEEDED');
    const first = take(1)[0];
    const major = first >> 5;
    const additional = first & 31;
    if (major === 6) return fail('UNSUPPORTED_CBOR_TAG');
    const value = argument(additional);
    if (major === 0 || major === 1) {
      // Deterministic integer encodings avoid number/BigInt ambiguity in COSE maps.
      if ((additional === 24 && value < 24n) || (additional === 25 && value <= 255n) ||
          (additional === 26 && value <= 65535n) || (additional === 27 && value <= 0xffffffffn)) {
        return fail('NON_CANONICAL_CBOR_INTEGER');
      }
      return asKey ? 'n:' + (major === 0 ? value : -1n - value).toString() : undefined;
    }
    if (major === 7) {
      if (additional === 20 || additional === 21 || additional === 22) return asKey ? 'v:' + additional : undefined;
      return fail('UNSUPPORTED_CBOR_SIMPLE_VALUE');
    }
    if (value > BigInt(maxBytes)) return fail('CBOR_PAYLOAD_TOO_LARGE');
    const length = Number(value);
    if (major === 2) {
      const bytes = take(length);
      return asKey ? 'b:' + bytes.toString('hex') : undefined;
    }
    if (major === 3) {
      try { const text = utf8.decode(take(length)); return asKey ? 's:' + text : undefined; }
      catch (error) {
        if (error instanceof SecurityError) throw error;
        return fail('INVALID_CBOR_UTF8');
      }
    }
    if (major === 4) {
      if (asKey) return fail('UNSUPPORTED_CBOR_MAP_KEY');
      if (length > maxNodes - nodes) return fail('CBOR_NODE_COUNT_EXCEEDED');
      for (let i = 0; i < length; i++) item(depth + 1);
      return undefined;
    }
    if (major === 5) {
      if (asKey) return fail('UNSUPPORTED_CBOR_MAP_KEY');
      if (length * 2 > maxNodes - nodes) return fail('CBOR_NODE_COUNT_EXCEEDED');
      const keys = new Set<string>();
      for (let i = 0; i < length; i++) {
        const key = item(depth + 1, true);
        if (key === undefined) return fail('UNSUPPORTED_CBOR_MAP_KEY');
        if (keys.has(key)) return fail('DUPLICATE_CBOR_KEY');
        keys.add(key);
        item(depth + 1);
      }
      return undefined;
    }
    return fail('INVALID_CBOR_PAYLOAD');
  }
  do {
    item(0);
    itemCount++;
  } while (options.allowMultiple && offset < buffer.length);
  if (offset !== buffer.length) return fail('TRAILING_CBOR_BYTES');
  return { itemCount, bytesRead: offset };
}

export function validateAndDecodeCBOR<T = unknown>(buffer: Buffer, options: CborValidationOptions = {}): T {
  scanCbor(buffer, { ...options, allowMultiple: false });
  try { return decoder.decode(buffer) as T; }
  catch { return fail('MALFORMED_CBOR'); }
}
export function decodeMultipleBounded(buffer: Buffer, options: CborValidationOptions = {}): unknown[] {
  scanCbor(buffer, { ...options, allowMultiple: true });
  try {
    const values = decoder.decodeMultiple(buffer);
    if (!Array.isArray(values)) return fail('MALFORMED_CBOR');
    return values;
  } catch (error) {
    if (error instanceof SecurityError) throw error;
    return fail('MALFORMED_CBOR');
  }
}
