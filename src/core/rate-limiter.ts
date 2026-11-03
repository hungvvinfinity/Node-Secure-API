export interface RateLimiterOptions {
  softwareRateLimitRpm?: number;
  ipRateLimitRpm?: number;
  ipRegistrationLimitPerHour?: number;
  inFlightTimeoutMs?: number;
  now?: () => number;
}

interface InFlightEntry {
  acquiredAt: number;
}

export class RateLimiter {
  private readonly softwareRateLimitRpm: number;
  private readonly ipRateLimitRpm: number;
  private readonly ipRegistrationLimitPerHour: number;
  private readonly inFlightTimeoutMs: number;
  private readonly now: () => number;

  private readonly inFlightLocks = new Map<string, InFlightEntry>();
  private readonly deviceTimestamps = new Map<string, number[]>();
  private readonly ipRequestTimestamps = new Map<string, number[]>();
  private readonly ipRegistrationTimestamps = new Map<string, number[]>();

  constructor(options: RateLimiterOptions = {}) {
    this.softwareRateLimitRpm = options.softwareRateLimitRpm ?? 6;
    this.ipRateLimitRpm = options.ipRateLimitRpm ?? 20;
    this.ipRegistrationLimitPerHour = options.ipRegistrationLimitPerHour ?? 5;
    this.inFlightTimeoutMs = options.inFlightTimeoutMs ?? 30000;
    this.now = options.now ?? (() => Date.now());
  }

  /**
   * Attempts to acquire an atomic single in-flight lock for a software device.
   * Returns true if lock was acquired, false if another request is currently in-flight.
   */
  acquireInFlight(deviceId: string): boolean {
    const currentTime = this.now();
    const existing = this.inFlightLocks.get(deviceId);

    if (existing) {
      const elapsed = currentTime - existing.acquiredAt;
      if (elapsed >= 0 && elapsed < this.inFlightTimeoutMs) {
        return false;
      }
      // Stale in-flight lock expired or clock skew detected
      this.inFlightLocks.delete(deviceId);
    }

    this.inFlightLocks.set(deviceId, { acquiredAt: currentTime });
    return true;
  }

  /**
   * Releases the in-flight lock for a software device.
   */
  releaseInFlight(deviceId: string): void {
    this.inFlightLocks.delete(deviceId);
  }

  /**
   * Checks if a device is currently marked in-flight.
   */
  isInFlight(deviceId: string): boolean {
    const existing = this.inFlightLocks.get(deviceId);
    if (!existing) return false;
    const elapsed = this.now() - existing.acquiredAt;
    if (elapsed < 0 || elapsed >= this.inFlightTimeoutMs) {
      this.inFlightLocks.delete(deviceId);
      return false;
    }
    return true;
  }

  /**
   * Enforces sliding window RPM for software devices (default 6 req/min).
   */
  checkDeviceRateLimit(deviceId: string): boolean {
    const currentTime = this.now();
    const windowStart = currentTime - 60000;

    const timestamps = this.deviceTimestamps.get(deviceId);
    const valid = timestamps ? timestamps.filter((t) => t > windowStart) : [];

    if (valid.length >= this.softwareRateLimitRpm) {
      this.deviceTimestamps.set(deviceId, valid);
      return false;
    }

    valid.push(currentTime);
    this.deviceTimestamps.set(deviceId, valid);

    if (this.deviceTimestamps.size > 10000) {
      this.sweepMap(this.deviceTimestamps, 60000);
    }

    return true;
  }

  /**
   * Enforces sliding window RPM per IP address for software tier requests (default 20 req/min).
   */
  checkIpRateLimit(ip: string): boolean {
    const currentTime = this.now();
    const windowStart = currentTime - 60000;

    const timestamps = this.ipRequestTimestamps.get(ip);
    const valid = timestamps ? timestamps.filter((t) => t > windowStart) : [];

    if (valid.length >= this.ipRateLimitRpm) {
      this.ipRequestTimestamps.set(ip, valid);
      return false;
    }

    valid.push(currentTime);
    this.ipRequestTimestamps.set(ip, valid);

    if (this.ipRequestTimestamps.size > 10000) {
      this.sweepMap(this.ipRequestTimestamps, 60000);
    }

    return true;
  }

  /**
   * Enforces sliding window hourly registrations per IP address (default 5 reg/hour).
   */
  checkIpRegistrationLimit(ip: string): boolean {
    const currentTime = this.now();
    const windowStart = currentTime - 3600000; // 1 hour

    const timestamps = this.ipRegistrationTimestamps.get(ip);
    const valid = timestamps ? timestamps.filter((t) => t > windowStart) : [];

    if (valid.length >= this.ipRegistrationLimitPerHour) {
      this.ipRegistrationTimestamps.set(ip, valid);
      return false;
    }

    valid.push(currentTime);
    this.ipRegistrationTimestamps.set(ip, valid);

    if (this.ipRegistrationTimestamps.size > 10000) {
      this.sweepMap(this.ipRegistrationTimestamps, 3600000);
    }

    return true;
  }

  private sweepMap(map: Map<string, number[]>, windowMs: number): void {
    const cutoff = this.now() - windowMs;
    for (const [key, timestamps] of map.entries()) {
      const valid = timestamps.filter((t) => t > cutoff);
      if (valid.length === 0) {
        map.delete(key);
      } else {
        map.set(key, valid);
      }
    }
  }

  /**
   * Clears all state (used between test runs).
   */
  reset(): void {
    this.inFlightLocks.clear();
    this.deviceTimestamps.clear();
    this.ipRequestTimestamps.clear();
    this.ipRegistrationTimestamps.clear();
  }
}
