import { Pool } from 'pg';
import { SecurityError, type DeviceRecord } from '../../contracts.js';
import type { DurableDeviceStore } from '../types.js';
import { validateDeviceRecord } from '../validation.js';

export class PostgresDeviceStore implements DurableDeviceStore {
  private readonly pool: Pool;
  constructor(options: { connectionString?: string; pool?: Pool } = {}) {
    this.pool = options.pool ?? new Pool({ connectionString: options.connectionString ?? process.env.DATABASE_URL });
  }
  async createDeviceNX(d: DeviceRecord): Promise<boolean> {
    validateDeviceRecord(d);
    const { receipt, ...metadata } = d.metadata;
    const result = await this.pool.query(`INSERT INTO devices
      (device_id, platform, public_key_pem, key_id, sign_count, last_sequence, registered_at, tier, expires_at, metadata, receipt)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11) ON CONFLICT (device_id) DO NOTHING`,
      [d.deviceId,d.platform,d.publicKeyPem,d.keyId ?? null,d.signCount ?? null,d.lastSequence,d.registeredAt,d.tier ?? 'hardware',d.expiresAt ?? null,JSON.stringify(metadata),typeof receipt === 'string' ? receipt : null]);
    return result.rowCount === 1;
  }
  async getDevice(id: string): Promise<DeviceRecord | null> {
    const { rows } = await this.pool.query('SELECT * FROM devices WHERE device_id=$1 AND (expires_at IS NULL OR expires_at > $2)', [id, Date.now()]);
    const r = rows[0]; if (!r) return null;
    const d: DeviceRecord = { deviceId:r.device_id, platform:r.platform, publicKeyPem:r.public_key_pem, keyId:r.key_id ?? undefined,
      signCount:r.sign_count === null ? undefined : Number(r.sign_count), lastSequence:String(r.last_sequence), registeredAt:Number(r.registered_at),
      tier:r.tier, expiresAt:r.expires_at === null ? undefined : Number(r.expires_at), metadata:{...r.metadata, ...(r.receipt ? {receipt:r.receipt} : {})} };
    validateDeviceRecord(d); return d;
  }
  async checkpointDevices(devices: Array<{deviceId:string;lastSequence:string;signCount?:number}>): Promise<void> {
    if (!devices.length) return;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      for (const d of devices) await client.query(`UPDATE devices SET last_sequence=$2, sign_count=COALESCE($3,sign_count), updated_at=NOW()
        WHERE device_id=$1 AND (length(last_sequence)<length($2) OR (length(last_sequence)=length($2) AND last_sequence <= $2))`, [d.deviceId,d.lastSequence,d.signCount ?? null]);
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  }
  async ping(): Promise<boolean> { try { await this.pool.query('SELECT 1'); return true; } catch { return false; } }
  async close(): Promise<void> { await this.pool.end(); }
  async initialize(): Promise<void> {
    try { await this.pool.query("SELECT 1 FROM devices LIMIT 0"); }
    catch { throw new SecurityError('DURABLE_STORE_UNAVAILABLE', 503); }
  }
}
