import { type Server } from 'node:http';
import type { AppConfig } from './config.js';
import { type DeviceSecurityProvider } from './contracts.js';
import { SecurityService } from './core/security-service.js';
import { createServer } from './http/server.js';
import { AndroidSecurityProvider } from './platform/android.js';
import { GOOGLE_HARDWARE_ATTESTATION_ROOTS } from './platform/android-roots.js';
import { GoogleRevocationSource } from './platform/trust.js';
import { RedisSecurityStore } from './store/redis.js';
import { CachingSecurityStore } from './store/cached.js';
import { IOSSecurityProvider } from './platform/ios.js';

export interface RunningApplication { server: Server; stop(): Promise<void> }

/** Production composition: fixed trusted roots, real revocation, Redis, and shared security service. */
export async function startApplication(config: AppConfig): Promise<RunningApplication> {
  const store = new CachingSecurityStore(new RedisSecurityStore({ url: config.redisUrl, keyPrefix: config.redisKeyPrefix }));
  const revocations = config.androidEnabled ? new GoogleRevocationSource() : undefined;
  let refreshTimer: NodeJS.Timeout | undefined;
  let server: Server | undefined;
  try {
    if (!await store.ping()) throw new Error('Security store unavailable');
    const providers: DeviceSecurityProvider[] = [];
    if (revocations) {
      await revocations.refresh();
      providers.push(new AndroidSecurityProvider({
        trustAnchors: [...GOOGLE_HARDWARE_ATTESTATION_ROOTS],
        expectedPackageName: config.androidPackage,
        expectedSignerDigests: config.androidSignerDigests,
        minimumVersion: config.androidMinimumVersion,
        revocationSource: revocations,
        allowSoftwareTier: config.androidAllowSoftwareTier,
        powDifficultyBits: config.powDifficultyBits,
        softwareDeviceTtlSeconds: config.softwareDeviceTtlSeconds
      }));
      refreshTimer = setInterval(() => {
        void revocations.refresh().catch(() => console.error('REVOCATION_REFRESH_FAILED'));
      }, 5 * 60 * 1000);
      refreshTimer.unref();
    }
    if (config.iosEnabled) providers.push(new IOSSecurityProvider({
      appId: config.iosAppId, environment: config.iosEnvironment,
      minimumBundleVersion: config.iosMinimumBundleVersion,
      allowedValidationCategories: config.iosAllowedValidationCategories,
      requireAppProperties: config.iosRequireAppProperties
    }));
    const securityService = new SecurityService({
      store,
      providers,
      powDifficultyBits: config.powDifficultyBits,
      softwareRateLimitRpm: config.softwareRateLimitRpm
    });
    server = createServer({
      securityService,
      store,
      maxBodySizeBytes: config.bodyLimitBytes,
      readinessCheck: async () => !revocations || revocations.isReady(),
      softwareTarpitDelayMs: config.softwareTarpitDelayMs
    });
    const runningServer = server;
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      runningServer.once('error', onError);
      runningServer.listen(config.port, config.host, () => {
        runningServer.off('error', onError);
        resolve();
      });
    });
    let stopPromise: Promise<void> | undefined;
    return { server: runningServer, stop: () => {
      if (!stopPromise) stopPromise = (async () => {
        if (refreshTimer) clearInterval(refreshTimer);
        const forceClose = setTimeout(() => runningServer.closeAllConnections(), 10_000);
        try { await new Promise<void>((resolve) => runningServer.close(() => resolve())); }
        finally { clearTimeout(forceClose); await store.close(); }
      })();
      return stopPromise;
    } };
  } catch (error) {
    if (refreshTimer) clearInterval(refreshTimer);
    if (server?.listening) server.close();
    await store.close();
    throw error;
  }
}
