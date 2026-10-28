export interface AppConfig {
  host: string;
  port: number;
  redisUrl: string;
  redisKeyPrefix: string;
  bodyLimitBytes: number;
  androidEnabled: boolean;
  androidPackage: string;
  androidSignerDigests: string[];
  androidMinimumVersion: bigint;
  iosEnabled: boolean;
  iosAppId: string;
  iosEnvironment: 'production' | 'development';
  iosMinimumBundleVersion?: string;
  iosAllowedValidationCategories?: number[];
  iosRequireAppProperties: boolean;
}

/** Parse server policy once at startup. No client input can change these values. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const required = (name: string): string => {
    const value = env[name]?.trim();
    if (!value) throw new Error(`${name} is required`);
    return value;
  };
  const flag = (name: string, fallback: boolean): boolean => {
    const value = env[name];
    if (value === undefined) return fallback;
    if (value !== 'true' && value !== 'false') throw new Error(`${name} must be true or false`);
    return value === 'true';
  };
  const integer = (name: string, fallback: number, min: number, max: number): number => {
    const text = env[name] ?? String(fallback);
    if (!/^(0|[1-9]\d*)$/.test(text)) throw new Error(`${name} must be a canonical integer`);
    const value = Number(text);
    if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`${name} out of range`);
    return value;
  };
  if (env.USE_MEMORY_STORE && env.USE_MEMORY_STORE !== 'false') {
    throw new Error('Memory store is only available by constructor injection in isolated tests');
  }
  const redisUrl = required('REDIS_URL');
  const parsedRedisUrl = new URL(redisUrl);
  if (!['redis:', 'rediss:'].includes(parsedRedisUrl.protocol)) throw new Error('REDIS_URL must use redis or rediss');
  const redisKeyPrefix = env.REDIS_KEY_PREFIX?.trim() || 'secure-api:';
  if (!/^[a-zA-Z0-9:_-]{1,64}$/.test(redisKeyPrefix)) throw new Error('Invalid REDIS_KEY_PREFIX');
  const androidEnabled = flag('ANDROID_ENABLED', true);
  const iosEnabled = flag('IOS_ENABLED', Boolean(env.IOS_APP_ID?.trim()));
  if (!androidEnabled && !iosEnabled) throw new Error('At least one security provider must be configured');

  let androidPackage = '';
  let androidSignerDigests: string[] = [];
  let androidMinimumVersion = 0n;
  if (androidEnabled) {
    androidPackage = required('EXPECTED_PACKAGE_NAME');
    if (!/^[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)+$/.test(androidPackage)) throw new Error('Invalid EXPECTED_PACKAGE_NAME');
    androidSignerDigests = required('EXPECTED_SIGNER_DIGESTS').split(',').map(x => x.trim().replaceAll(':', '').toLowerCase());
    if (!androidSignerDigests.length || androidSignerDigests.some(x => !/^[a-f0-9]{64}$/.test(x))) {
      throw new Error('EXPECTED_SIGNER_DIGESTS must contain SHA256 app signing certificate digests');
    }
    const minimum = required('MINIMUM_ANDROID_VERSION');
    if (!/^(0|[1-9]\d*)$/.test(minimum)) throw new Error('Invalid MINIMUM_ANDROID_VERSION');
    androidMinimumVersion = BigInt(minimum);
    if (androidMinimumVersion > 9223372036854775807n) throw new Error('MINIMUM_ANDROID_VERSION out of range');
  }
  let iosAppId = '';
  const iosEnvironment = env.IOS_APP_ATTEST_ENV ?? 'production';
  if (iosEnvironment !== 'production' && iosEnvironment !== 'development') throw new Error('Invalid IOS_APP_ATTEST_ENV');
  if (env.NODE_ENV === 'production' && iosEnvironment !== 'production') {
    throw new Error('Development App Attest is forbidden in production');
  }
  if (iosEnabled) {
    iosAppId = required('IOS_APP_ID');
    if (!/^[A-Z0-9]{10}\.[A-Za-z0-9][A-Za-z0-9.-]+$/.test(iosAppId)) throw new Error('Invalid IOS_APP_ID (use actual App ID prefix)');
  }
  const iosMinimumBundleVersion = env.IOS_MINIMUM_BUNDLE_VERSION?.trim() || undefined;
  if (iosMinimumBundleVersion && (!/^\d+(?:\.\d+){0,2}$/.test(iosMinimumBundleVersion) || iosMinimumBundleVersion.length > 64)) {
    throw new Error('Invalid IOS_MINIMUM_BUNDLE_VERSION (numeric dotted version required)');
  }
  const rawCategories = env.IOS_ALLOWED_VALIDATION_CATEGORIES?.trim();
  const iosAllowedValidationCategories = rawCategories ? rawCategories.split(',').map(value => {
    if (!/^[1-6]$/.test(value.trim())) throw new Error('Invalid IOS_ALLOWED_VALIDATION_CATEGORIES');
    return Number(value.trim());
  }) : undefined;
  return {
    host: env.HOST?.trim() || '0.0.0.0',
    port: integer('PORT', 3000, 1, 65535),
    redisUrl, redisKeyPrefix,
    bodyLimitBytes: integer('BODY_LIMIT_BYTES', 1_048_576, 1, 10_485_760),
    androidEnabled, androidPackage, androidSignerDigests, androidMinimumVersion,
    iosEnabled, iosAppId, iosEnvironment, iosMinimumBundleVersion, iosAllowedValidationCategories,
    iosRequireAppProperties: flag('IOS_REQUIRE_APP_PROPERTIES', false)
  };
}
