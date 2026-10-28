import crypto from 'node:crypto';

/**
 * Builds the canonical string for request signing:
 * timestamp:sequence:METHOD:request-target:SHA256(rawBody)
 *
 * - timestamp: milliseconds as received in header
 * - sequence: canonical decimal positive int64 as received in header
 * - METHOD: uppercase HTTP method
 * - request-target: raw path + query as received on the wire without decoding or reordering
 * - SHA256(rawBody): lowercase hex digest of raw body bytes
 */
export function buildCanonicalString(
  timestamp: string,
  sequence: string,
  method: string,
  requestTarget: string,
  rawBody: Buffer
): string {
  const methodUpper = method.toUpperCase();
  const bodySha256 = crypto.createHash('sha256').update(rawBody).digest('hex');
  return `${timestamp}:${sequence}:${methodUpper}:${requestTarget}:${bodySha256}`;
}

/**
 * Encodes the canonical string into a UTF-8 Buffer.
 */
export function buildCanonicalBuffer(
  timestamp: string,
  sequence: string,
  method: string,
  requestTarget: string,
  rawBody: Buffer
): Buffer {
  return Buffer.from(buildCanonicalString(timestamp, sequence, method, requestTarget, rawBody), 'utf8');
}
