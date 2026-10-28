import { loadConfig } from './config.js';
import { SecurityError } from './contracts.js';
import { startApplication } from './runtime.js';

try {
  const app = await startApplication(loadConfig());
  console.log('Secure API listening; Redis and platform trust initialized.');
  let stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    try { await app.stop(); }
    catch { process.exitCode = 1; }
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
} catch (error) {
  // Configuration errors contain field names only. Never log Redis credentials or raw certificates.
  console.error('FATAL:', error instanceof SecurityError ? error.code :
    error instanceof Error ? error.message : 'STARTUP_FAILED');
  process.exitCode = 1;
}
