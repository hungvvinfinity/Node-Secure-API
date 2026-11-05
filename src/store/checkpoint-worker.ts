import type { RedisClientType } from 'redis';
import type { DurableDeviceStore } from './types.js';

export interface CheckpointWorkerOptions { client: RedisClientType; durable: DurableDeviceStore; keyPrefix?: string; intervalMs?: number; batchSize?: number; closeClient?: boolean; }
export class CheckpointWorker {
  private timer?: NodeJS.Timeout;
  private running?: Promise<void>;
  private stopped = false;
  private readonly prefix: string;
  private readonly interval: number;
  private readonly batchSize: number;
  constructor(private readonly options: CheckpointWorkerOptions) {
    this.prefix=options.keyPrefix ?? 'sec:'; this.interval=options.intervalMs ?? 5000; this.batchSize=options.batchSize ?? 200;
  }
  start(): void { if (this.timer) return; this.timer=setInterval(()=>{void this.flush().catch(()=>{});},this.interval); this.timer.unref(); }
  async flush(): Promise<void> {
    if (this.running) return this.running;
    this.running=this.doFlush().finally(()=>{this.running=undefined;}); return this.running;
  }
  private async doFlush(): Promise<void> {
    const key=this.prefix+'dirty_devices';
    while (!this.stopped) {
      const ids=await this.options.client.sendCommand(['SPOP',key,String(this.batchSize)]) as unknown as string[];
      if (!ids?.length) return;
      try {
        const devices=[];
        for(const id of ids){ const data=await this.options.client.hmGet(this.prefix+'device:'+id,['lastSequence','signCount']);
          if(data[0]) devices.push({deviceId:id,lastSequence:data[0],signCount:data[1] ? Number(data[1]) : undefined}); }
        await this.options.durable.checkpointDevices(devices);
      } catch(e) { if(ids.length) await this.options.client.sAdd(key,ids); throw e; }
    }
  }
  async stop(): Promise<void> { if(this.timer) clearInterval(this.timer); this.timer=undefined; await this.flush(); this.stopped=true; if(this.options.closeClient) await this.options.client.quit().catch(()=>{}); }
}
