import { readFile } from 'node:fs/promises';
import { X509Certificate } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

// Read-only drift detector. Changed roots/commits require review; never auto-apply trust.
const snapshot = JSON.parse(await readFile(new URL('../docs/upstream-snapshot.json', import.meta.url), 'utf8'));
async function readJson(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(15_000), redirect: 'error',
    headers: { 'user-agent': 'node-secure-api-source-review', accept: 'application/json' } });
  if (!response.ok) throw new Error(`Upstream HTTP ${response.status}: ${url}`);
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 2 * 1024 * 1024) { await reader.cancel(); throw new Error('Upstream response too large'); }
    chunks.push(value);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

const [roots, remote] = await Promise.all([
  readJson('https://android.googleapis.com/attestation/root'),
  promisify(execFile)('git', ['ls-remote', 'https://github.com/android/keyattestation.git', 'refs/heads/main'],
    { timeout: 15_000, maxBuffer: 64 * 1024 })
]);
const commit = remote.stdout.trim().split(/\s+/)[0];
if (!Array.isArray(roots) || !roots.length || roots.length > 16 || !/^[a-f0-9]{40}$/.test(commit)) {
  throw new Error('Unexpected upstream schema');
}
const fingerprints = roots.map(pem => new X509Certificate(pem).fingerprint256.replaceAll(':', '')).sort();
const drift = commit !== snapshot.androidCommit ||
  JSON.stringify(fingerprints) !== JSON.stringify([...snapshot.androidRootFingerprints].sort());
console.log(JSON.stringify({ checkedAt: new Date().toISOString(), androidCommit: commit,
  androidRootFingerprints: fingerprints, reviewRequired: drift }, null, 2));
if (drift) {
  console.error('Upstream changed. Review official sources, update verifier/tests if needed, then update the reviewed snapshot.');
  process.exitCode = 1;
}
