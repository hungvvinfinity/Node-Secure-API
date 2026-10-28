// Read-only operational checks. This script cannot attest a hardware device.
const scope = 'preflight-only';
try {
  let base;
  try { base = new URL(process.env.CANARY_BASE_URL); }
  catch { throw new Error('CANARY_BASE_URL_REQUIRED'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname);
  if (base.username || base.password || base.search || base.hash || base.pathname !== '/' ||
      (base.protocol !== 'https:' && !(base.protocol === 'http:' && loopback))) {
    throw new Error('INVALID_CANARY_BASE_URL');
  }
  const checks = [];
  for (const [path, expected] of [['/health', 'UP'], ['/ready', 'READY']]) {
    const started = performance.now();
    const response = await fetch(new URL(path, base), { redirect: 'error', signal: AbortSignal.timeout(5000) });
    if (response.status !== 200) {
      await response.body?.cancel();
      throw new Error(`${expected}_HTTP_${response.status}`);
    }
    const reader = response.body?.getReader();
    if (!reader) throw new Error('INVALID_HEALTH_RESPONSE');
    const chunks = [];
    let bytes = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 16384) { await reader.cancel(); throw new Error('HEALTH_RESPONSE_TOO_LARGE'); }
      chunks.push(value);
    }
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
    catch { throw new Error('INVALID_HEALTH_RESPONSE'); }
    if (body?.status !== expected) throw new Error('INVALID_HEALTH_RESPONSE');
    checks.push({ path, status: response.status, elapsedMs: Math.round(performance.now() - started) });
  }
  console.log(JSON.stringify({ scope, checkedAt: new Date().toISOString(), origin: base.origin,
    result: 'PASS', checks, hardwareAttestationVerified: false }, null, 2));
} catch (error) {
  const message = error instanceof Error ? error.message : '';
  const code = /^(?:CANARY_BASE_URL_REQUIRED|INVALID_CANARY_BASE_URL|INVALID_HEALTH_RESPONSE|HEALTH_RESPONSE_TOO_LARGE|(?:UP|READY)_HTTP_\d{3})$/.test(message)
    ? message : 'PREFLIGHT_NETWORK_ERROR';
  console.error(JSON.stringify({ scope, result: 'FAIL', error: code, hardwareAttestationVerified: false }));
  process.exitCode = 1;
}
