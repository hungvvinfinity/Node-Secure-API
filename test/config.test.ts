import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';

describe('AppConfig (Fail-Closed Configuration Tests)', () => {
  const validBaseEnv: NodeJS.ProcessEnv = {
    REDIS_URL: 'redis://127.0.0.1:6379',
    EXPECTED_PACKAGE_NAME: 'com.astrology.tarot',
    EXPECTED_SIGNER_DIGESTS: 'a'.repeat(64),
    MINIMUM_ANDROID_VERSION: '100'
  };

  it('loads valid configuration successfully', () => {
    const config = loadConfig(validBaseEnv);

    assert.equal(config.redisUrl, 'redis://127.0.0.1:6379');
    assert.equal(config.androidEnabled, true);
    assert.equal(config.androidPackage, 'com.astrology.tarot');
    assert.deepEqual(config.androidSignerDigests, ['a'.repeat(64)]);
    assert.equal(config.androidMinimumVersion, 100n);
    assert.equal(config.port, 3000);
    assert.equal(config.host, '0.0.0.0');
  });

  it('fails closed when REDIS_URL is missing or uses unsupported protocol', () => {
    assert.throws(
      () => loadConfig({ ...validBaseEnv, REDIS_URL: '' }),
      /REDIS_URL is required/
    );

    assert.throws(
      () => loadConfig({ ...validBaseEnv, REDIS_URL: 'http://127.0.0.1:6379' }),
      /REDIS_URL must use redis or rediss/
    );
  });

  it('fails closed if USE_MEMORY_STORE is set outside test constructor injection', () => {
    assert.throws(
      () => loadConfig({ ...validBaseEnv, USE_MEMORY_STORE: 'true' }),
      /Memory store is only available by constructor injection in isolated tests/
    );
  });

  it('fails closed if EXPECTED_PACKAGE_NAME is missing or invalid format', () => {
    assert.throws(
      () => loadConfig({ ...validBaseEnv, EXPECTED_PACKAGE_NAME: '' }),
      /EXPECTED_PACKAGE_NAME is required/
    );

    assert.throws(
      () => loadConfig({ ...validBaseEnv, EXPECTED_PACKAGE_NAME: '123-bad-package-name' }),
      /Invalid EXPECTED_PACKAGE_NAME/
    );
  });

  it('fails closed if EXPECTED_SIGNER_DIGESTS is missing, empty, or not 64-char lowercase hex SHA-256', () => {
    assert.throws(
      () => loadConfig({ ...validBaseEnv, EXPECTED_SIGNER_DIGESTS: '' }),
      /EXPECTED_SIGNER_DIGESTS is required/
    );

    assert.throws(
      () => loadConfig({ ...validBaseEnv, EXPECTED_SIGNER_DIGESTS: 'short-digest' }),
      /EXPECTED_SIGNER_DIGESTS must contain SHA256 app signing certificate digests/
    );

    assert.throws(
      () => loadConfig({ ...validBaseEnv, EXPECTED_SIGNER_DIGESTS: 'z'.repeat(64) }),
      /EXPECTED_SIGNER_DIGESTS must contain SHA256 app signing certificate digests/
    );
  });

  it('fails closed if MINIMUM_ANDROID_VERSION is negative, non-canonical, or out of int64 range', () => {
    assert.throws(
      () => loadConfig({ ...validBaseEnv, MINIMUM_ANDROID_VERSION: '-1' }),
      /Invalid MINIMUM_ANDROID_VERSION/
    );

    assert.throws(
      () => loadConfig({ ...validBaseEnv, MINIMUM_ANDROID_VERSION: '01' }),
      /Invalid MINIMUM_ANDROID_VERSION/
    );

    assert.throws(
      () => loadConfig({ ...validBaseEnv, MINIMUM_ANDROID_VERSION: '9223372036854775808' }),
      /MINIMUM_ANDROID_VERSION out of range/
    );
  });

  it('fails closed if PORT is out of 1..65535 range', () => {
    assert.throws(
      () => loadConfig({ ...validBaseEnv, PORT: '0' }),
      /PORT out of range/
    );

    assert.throws(
      () => loadConfig({ ...validBaseEnv, PORT: '70000' }),
      /PORT out of range/
    );
  });

  it('fails closed if both Android and iOS are disabled', () => {
    assert.throws(
      () => loadConfig({ ...validBaseEnv, ANDROID_ENABLED: 'false', IOS_ENABLED: 'false' }),
      /At least one security provider must be configured/
    );
  });

  it('fails closed if development App Attest is configured in production environment', () => {
    assert.throws(
      () =>
        loadConfig({
          ...validBaseEnv,
          NODE_ENV: 'production',
          IOS_ENABLED: 'true',
          IOS_APP_ID: '1234567890.com.example.app',
          IOS_APP_ATTEST_ENV: 'development'
        }),
      /Development App Attest is forbidden in production/
    );
  });
});
