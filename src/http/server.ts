import http, { type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { SecurityError, type Platform } from '../contracts.js';
import type { AuthContext, SecurityService } from '../core/security-service.js';
import type { SecurityStore } from '../store/types.js';

export interface CreateServerOptions {
  securityService: SecurityService;
  store: SecurityStore;
  maxBodySizeBytes?: number;
  controlBodyLimitBytes?: number;
  businessHandler?: (req: IncomingMessage, res: ServerResponse, context: AuthContext) => Promise<void> | void;
  readinessCheck?: () => Promise<boolean>;
}

const SECURITY_HEADER_NAMES = new Set([
  'x-device-id',
  'x-timestamp',
  'x-sequence',
  'x-signature',
  'x-assertion'
]);

function sendJson(res: ServerResponse, statusCode: number, payload: unknown): void {
  if (res.headersSent) {
    return;
  }
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function sendError(res: ServerResponse, error: unknown): void {
  if (error instanceof SecurityError) {
    sendJson(res, error.status, {
      error: error.code,
      message: error.message
    });
    return;
  }

  // Sanitized generic error response (do not leak stack traces or internal details)
  sendJson(res, 500, {
    error: 'INTERNAL_ERROR',
    message: 'Internal server error'
  });
}

function hasDuplicateSecurityHeaders(req: IncomingMessage): boolean {
  const seen = new Set<string>();
  const raw = req.rawHeaders;
  for (let i = 0; i < raw.length; i += 2) {
    const name = raw[i].toLowerCase();
    if (SECURITY_HEADER_NAMES.has(name)) {
      if (seen.has(name)) {
        return true;
      }
      seen.add(name);
    }
  }
  return false;
}

function hasUnsupportedEncoding(req: IncomingMessage): boolean {
  const contentEncoding = req.headers['content-encoding'];
  if (contentEncoding && contentEncoding.trim().toLowerCase() !== 'identity') {
    return true;
  }

  const transferEncoding = req.headers['transfer-encoding'];
  if (transferEncoding && transferEncoding.trim().toLowerCase() !== 'chunked') {
    return true;
  }

  return false;
}

function readBodyWithLimit(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    if (req.destroyed || !req.readable) {
      if (req.complete && req.readableEnded) resolve(Buffer.alloc(0));
      else reject(new SecurityError('REQUEST_ABORTED', 400));
      return;
    }

    const chunks: Buffer[] = [];
    let receivedBytes = 0;
    let completed = false;

    const cleanup = () => {
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('error', onError);
      req.off('close', onClose);
    };

    const onData = (chunk: Buffer) => {
      if (completed) return;
      receivedBytes += chunk.length;
      if (receivedBytes > maxBytes) {
        completed = true;
        cleanup();
        req.pause();
        reject(new SecurityError('PAYLOAD_TOO_LARGE', 413));
        return;
      }
      chunks.push(chunk);
    };

    const onEnd = () => {
      if (completed) return;
      completed = true;
      cleanup();
      resolve(Buffer.concat(chunks));
    };

    const onError = (err: Error) => {
      if (completed) return;
      completed = true;
      cleanup();
      reject(err);
    };

    const onClose = () => {
      if (completed) return;
      completed = true;
      cleanup();
      if (!req.complete) {
        reject(new SecurityError('REQUEST_ABORTED', 400));
      } else {
        resolve(Buffer.concat(chunks));
      }
    };

    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onError);
    req.on('close', onClose);
  });
}

export function createServer(options: CreateServerOptions): Server {
  const {
    securityService,
    store,
    maxBodySizeBytes = 1048576, // 1 MB default
    controlBodyLimitBytes = 65536, // 64 KB default
    businessHandler,
    readinessCheck
  } = options;

  const server = http.createServer(async (req, res) => {
    try {
      // 1. Check for duplicate security headers
      if (hasDuplicateSecurityHeaders(req)) {
        sendJson(res, 400, {
          error: 'DUPLICATE_HEADER',
          message: 'Duplicate security header detected'
        });
        return;
      }

      // 2. Reject unsupported / compressed content encodings to protect canonical byte fidelity
      if (hasUnsupportedEncoding(req)) {
        sendJson(res, 415, {
          error: 'UNSUPPORTED_ENCODING',
          message: 'Compressed or unsupported content encoding is rejected'
        });
        return;
      }

      const method = (req.method || 'GET').toUpperCase();
      const rawUrl = req.url || '/';
      const pathname = rawUrl.split('?')[0];

      // 3. Health & Readiness endpoints
      if (method === 'GET' && (pathname === '/health' || pathname === '/api/health')) {
        sendJson(res, 200, { status: 'UP' });
        return;
      }

      if (method === 'GET' && (pathname === '/ready' || pathname === '/api/ready')) {
        const storeHealthy = await store.ping().catch(() => false);
        let platformHealthy = true;
        if (readinessCheck) {
          platformHealthy = await readinessCheck().catch(() => false);
        }

        if (storeHealthy && platformHealthy) {
          sendJson(res, 200, { status: 'READY' });
        } else {
          sendJson(res, 503, {
            status: 'NOT_READY',
            error: !storeHealthy ? 'STORE_DOWN' : 'PLATFORM_TRUST_NOT_READY'
          });
        }
        return;
      }

      // 4. Control Endpoints (Challenge & Device Registration)
      if (pathname === '/api/auth/challenge') {
        if (method !== 'POST') {
          sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED', message: 'POST required' });
          return;
        }

        const rawBody = await readBodyWithLimit(req, controlBodyLimitBytes);
        let platform: Platform = 'android';

        if (rawBody.length > 0) {
          const contentType = req.headers['content-type'] || '';
          if (!contentType.toLowerCase().includes('application/json')) {
            sendJson(res, 415, {
              error: 'UNSUPPORTED_MEDIA_TYPE',
              message: 'Content-Type must be application/json'
            });
            return;
          }

          let parsed: Record<string, unknown>;
          try {
            parsed = JSON.parse(rawBody.toString('utf8'));
          } catch {
            sendJson(res, 400, { error: 'INVALID_JSON', message: 'Malformed JSON payload' });
            return;
          }

          if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
            sendJson(res, 400, {
              error: 'INVALID_REQUEST_BODY',
              message: 'JSON payload must be an object'
            });
            return;
          }

          if (parsed.platform !== undefined) {
            if (parsed.platform !== 'android' && parsed.platform !== 'ios') {
              sendJson(res, 400, {
                error: 'INVALID_PLATFORM',
                message: 'Platform must be android or ios'
              });
              return;
            }
            platform = parsed.platform;
          }
        }

        const challengeResult = await securityService.issueChallenge(platform);
        sendJson(res, 200, {
          status: 'SUCCESS',
          challenge: challengeResult.challenge,
          expiresAt: challengeResult.expiresAt
        });
        return;
      }

      if (pathname === '/api/auth/register-device') {
        if (method !== 'POST') {
          sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED', message: 'POST required' });
          return;
        }

        const rawBody = await readBodyWithLimit(req, controlBodyLimitBytes);
        const contentType = req.headers['content-type'] || '';
        if (!contentType.toLowerCase().includes('application/json')) {
          sendJson(res, 415, {
            error: 'UNSUPPORTED_MEDIA_TYPE',
            message: 'Content-Type must be application/json'
          });
          return;
        }

        let parsed: Record<string, unknown>;
        try {
          parsed = JSON.parse(rawBody.toString('utf8'));
        } catch {
          sendJson(res, 400, { error: 'INVALID_JSON', message: 'Malformed JSON payload' });
          return;
        }

        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          sendJson(res, 400, {
            error: 'INVALID_REQUEST_BODY',
            message: 'JSON payload must be an object'
          });
          return;
        }

        const { challenge, certificateChain, attestationObject, keyId } = parsed;

        if (!challenge || typeof challenge !== 'string' || !/^[0-9a-fA-F]{64}$/.test(challenge)) {
          sendJson(res, 400, {
            error: 'INVALID_CHALLENGE',
            message: 'Challenge must be a 64-character hex string'
          });
          return;
        }

        if (
          certificateChain !== undefined &&
          (!Array.isArray(certificateChain) ||
            certificateChain.length === 0 ||
            certificateChain.some((c) => typeof c !== 'string' || !c.trim()))
        ) {
          sendJson(res, 400, {
            error: 'INVALID_CERTIFICATE_CHAIN',
            message: 'certificateChain must be a non-empty array of base64 strings'
          });
          return;
        }

        if (
          attestationObject !== undefined &&
          (typeof attestationObject !== 'string' || !attestationObject.trim())
        ) {
          sendJson(res, 400, {
            error: 'INVALID_ATTESTATION',
            message: 'attestationObject must be a non-empty string'
          });
          return;
        }

        if (!certificateChain && !attestationObject) {
          sendJson(res, 400, {
            error: 'INVALID_ATTESTATION',
            message: 'Either certificateChain or attestationObject is required'
          });
          return;
        }

        const registerResult = await securityService.registerDevice({
          challenge,
          certificateChain: certificateChain as string[] | undefined,
          attestationObject: attestationObject as string | undefined,
          keyId: typeof keyId === 'string' ? keyId : undefined
        });

        sendJson(res, 200, {
          status: 'SUCCESS',
          deviceId: registerResult.deviceId,
          message: 'Device registered successfully'
        });
        return;
      }

      // 5. Business Endpoints (Protected by hardware attestation & replay guard)
      const isTarotEndpoint = pathname === '/api/tarot/read' || pathname.startsWith('/api/tarot/');
      if (isTarotEndpoint) {
        const rawBody = await readBodyWithLimit(req, maxBodySizeBytes);

        const deviceId = req.headers['x-device-id'];
        const timestamp = req.headers['x-timestamp'];
        const sequence = req.headers['x-sequence'];
        const signature = req.headers['x-signature'];
        const assertion = req.headers['x-assertion'];

        if (
          !deviceId ||
          !timestamp ||
          !sequence ||
          Array.isArray(deviceId) ||
          Array.isArray(timestamp) ||
          Array.isArray(sequence)
        ) {
          sendJson(res, 401, {
            error: 'MISSING_SECURITY_HEADERS',
            message: 'X-Device-Id, X-Timestamp, and X-Sequence headers are required'
          });
          return;
        }

        // Authenticate request before invoking any business logic
        const authContext = await securityService.authenticateRequest({
          deviceId,
          timestamp,
          sequence,
          signature: typeof signature === 'string' ? signature : undefined,
          assertion: typeof assertion === 'string' ? assertion : undefined,
          method,
          requestTarget: rawUrl,
          rawBody
        });

        // Business handler is ONLY invoked after successful authentication
        if (businessHandler) {
          await businessHandler(req, res, authContext);
          return;
        }

        // Default demo /api/tarot/read response
        if (pathname === '/api/tarot/read' && method === 'POST') {
          sendJson(res, 200, {
            status: 'SUCCESS',
            data: {
              card: 'The Star',
              meaning: 'Hardware security successfully protected your request!'
            }
          });
          return;
        }

        sendJson(res, 404, { error: 'NOT_FOUND', message: 'Endpoint not found' });
        return;
      }

      // 6. Any other unmatched routes
      sendJson(res, 404, { error: 'NOT_FOUND', message: 'Route not found' });
    } catch (err) {
      if (err instanceof SecurityError && err.status === 413) {
        res.setHeader('Connection', 'close');
        res.once('finish', () => req.destroy());
      }
      sendError(res, err);
    }
  });

  // Bounded timeouts to prevent connection hangs / slowloris
  server.requestTimeout = 30000; // 30 seconds
  server.headersTimeout = 31000; // 31 seconds
  server.keepAliveTimeout = 5000; // 5 seconds

  return server;
}
