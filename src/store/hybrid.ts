import type { DeviceRecord } from '../contracts.js';
import type { CommitResult, DurableDeviceStore, SecurityStore } from './types.js';
import type { CheckpointWorker } from './checkpoint-worker.js';

/** Redis is the replay/CAS authority; PostgreSQL persists device identity and checkpoints. */
export class HybridSecurityStore implements SecurityStore {
  constructor(private readonly hot: SecurityStore, private readonly durable: DurableDeviceStore, private readonly checkpoint?: CheckpointWorker) {}
  saveChallenge(...args: Parameters<SecurityStore['saveChallenge']>): Promise<void> { return this.hot.saveChallenge(...args); }
  consumeChallenge(...args: Parameters<SecurityStore['consumeChallenge']>): ReturnType<SecurityStore['consumeChallenge']> { return this.hot.consumeChallenge(...args); }
  consumeStatelessChallenge(challenge: string, ttlSeconds: number): Promise<boolean> { return this.hot.consumeStatelessChallenge?.(challenge, ttlSeconds) ?? Promise.resolve(false); }
  async createDeviceNX(device: DeviceRecord): Promise<boolean> {
    if (!await this.durable.createDeviceNX(device)) return false;
    try { if (await this.hot.createDeviceNX(device)) return true; }
    catch { return true; }
    // A durable insert succeeded but Redis failed: remove the incomplete durable row is unsafe;
    // materialize from L3 on next lookup and report registration success.
    return true;
  }
  async getDevice(id: string): Promise<DeviceRecord | null> {
    const hot=await this.hot.getDevice(id); if(hot) return hot;
    const durable=await this.durable.getDevice(id); if(durable) await this.hot.createDeviceNX(durable); return durable;
  }
  commitSequence(...args: Parameters<SecurityStore['commitSequence']>): Promise<CommitResult> { return this.hot.commitSequence(...args); }
  isQuarantined(timestamp: number): boolean { return this.hot.isQuarantined?.(timestamp) ?? false; }
  async ping(): Promise<boolean> { return await this.hot.ping() && await this.durable.ping(); }
  async close(): Promise<void> { try { await this.checkpoint?.stop(); } finally { await Promise.allSettled([this.hot.close(), this.durable.close()]); } }
}
