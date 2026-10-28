// Integration acceptance must be explicit and must never use a production REDIS_URL.
try {
  const value = process.env.REDIS_TEST_URL;
  if (!value || !value.trim()) throw new Error();
  const url = new URL(value);
  if (!['redis:', 'rediss:'].includes(url.protocol) || !url.hostname) throw new Error();
} catch {
  console.error('REDIS_TEST_URL_REQUIRED: configure a dedicated Redis or run npm run test:docker');
  process.exitCode = 1;
}
