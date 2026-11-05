import test from 'node:test';
import assert from 'node:assert/strict';
import { MemorySecurityStore } from '../src/store/memory.js';
import { HybridSecurityStore } from '../src/store/hybrid.js';
import { SecurityService } from '../src/core/security-service.js';
import type { DeviceRecord, DeviceSecurityProvider, RegistrationInput, VerifiedRegistration } from '../src/contracts.js';
import { RedisSecurityStore } from '../src/store/redis.js';
import { createAttestationChain } from './helpers/crypto-fixtures.js';

const device: DeviceRecord={deviceId:'device-1',platform:'android',publicKeyPem:'pem',metadata:{},lastSequence:'0',registeredAt:1000};

test('HybridSecurityStore persists identity to durable tier and restores Redis cache on miss',async()=>{
  const hot=new MemorySecurityStore(), base=new MemorySecurityStore();
  const durable={createDeviceNX:(d:DeviceRecord)=>base.createDeviceNX(d),getDevice:(id:string)=>base.getDevice(id),checkpointDevices:async()=>{},ping:()=>base.ping(),close:()=>base.close()};
  const hybrid=new HybridSecurityStore(hot,durable);
  assert.equal(await hybrid.createDeviceNX(device),true);
  await hot.close();
  assert.equal((await hybrid.getDevice(device.deviceId))?.publicKeyPem,'pem');
});

test('CheckpointWorker SPOP requeue semantics preserve dirty IDs if durable batch fails',async()=>{
  let pending=['device-1']; let calls=0;
  const client:any={sendCommand:async()=>{const out=pending;pending=[];return out;},hmGet:async()=>['4',null],sAdd:async(_k:string,ids:string[])=>{pending.push(...ids);}};
  const durable:any={checkpointDevices:async()=>{calls++;throw new Error('temporary');}};
  const {CheckpointWorker}=await import('../src/store/checkpoint-worker.js');
  const worker=new CheckpointWorker({client,durable});
  await assert.rejects(worker.flush()); assert.deepEqual(pending,['device-1']); assert.equal(calls,1);
});

test('Redis timestamp quarantine blocks pre-boot timestamps only during the window',()=>{
  let now=20_000; const redis=new RedisSecurityStore({now:()=>now});
  redis.setQuarantine(10_000,15_000);
  assert.equal(redis.isQuarantined(9_999),true); assert.equal(redis.isQuarantined(10_000),false);
  now=25_000; assert.equal(redis.isQuarantined(9_999),false);
});

test('StatelessChallenge derives deterministic salt and rejects replay and tampering',async()=>{
  let now=1_729_800_000_000; const store=new MemorySecurityStore({now:()=>now});
  const provider:DeviceSecurityProvider={platform:'android',verifyRegistration:async(_i:RegistrationInput,c)=>({publicKeyPem:'pem',metadata:{challenge:c.challenge.toString()}} as VerifiedRegistration),verifyRequest:async()=>({})};
  const service=new SecurityService({store,providers:[provider],now:()=>now,challengeHmacSecret:'x'.repeat(32)});
  const fixture=await createAttestationChain();
  provider.verifyRegistration=async(_i:RegistrationInput,c)=>({publicKeyPem:fixture.leafPublicKeyPem,metadata:{challenge:c.challenge.toString()}});
  const issued=await service.issueChallenge('android');
  assert.match(issued.challenge,/^[0-9a-f]{64}$/); assert.equal(issued.pow?.salt.length,32);
  const issued2=await service.issueChallenge('android');
  const nonce1=Buffer.from(issued.challenge,'hex').subarray(0,12),nonce2=Buffer.from(issued2.challenge,'hex').subarray(0,12);
  assert.notDeepEqual(nonce1,nonce2);
  const input={challenge:issued.challenge,certificateChain:fixture.chain};
  await service.registerDevice(input);
  await assert.rejects(service.registerDevice(input),{code:'INVALID_CHALLENGE'});
  const tampered=issued2.challenge.slice(0,63)+(issued2.challenge[63]==='0'?'1':'0');
  await assert.rejects(service.registerDevice({...input,challenge:tampered}),{code:'INVALID_CHALLENGE'});
  now+=61_000;
  await assert.rejects(service.registerDevice({...input,challenge:issued2.challenge}),{code:'INVALID_CHALLENGE'});
});

test('PostgresDeviceStore performs insert ON CONFLICT, getDevice and monotonic checkpointing', async () => {
  const queries: string[] = [];
  const client: any = {
    query: async (sql: string) => {
      queries.push(sql);
      return { rowCount: 1, rows: [] };
    },
    release: () => {}
  };
  const pool: any = {
    query: async (sql: string) => {
      queries.push(sql);
      if (sql.includes('SELECT * FROM devices')) {
        return {
          rows: [{
            device_id: 'dev-1',
            platform: 'android',
            public_key_pem: 'pem',
            key_id: null,
            sign_count: null,
            last_sequence: '10',
            registered_at: 1000,
            tier: 'hardware',
            expires_at: null,
            metadata: { foo: 'bar' },
            receipt: 'sample-receipt'
          }]
        };
      }
      return { rowCount: 1, rows: [] };
    },
    connect: async () => client,
    end: async () => {}
  };
  const { PostgresDeviceStore } = await import('../src/store/durable/postgres-store.js');
  const store = new PostgresDeviceStore({ pool });

  const created = await store.createDeviceNX({
    deviceId: 'dev-1',
    platform: 'android',
    publicKeyPem: 'pem',
    lastSequence: '0',
    registeredAt: 1000,
    metadata: { receipt: 'sample-receipt' }
  });
  assert.equal(created, true);
  assert.ok(queries.some(q => q.includes('ON CONFLICT (device_id) DO NOTHING')));

  const retrieved = await store.getDevice('dev-1');
  assert.equal(retrieved?.deviceId, 'dev-1');
  assert.equal(retrieved?.metadata.receipt, 'sample-receipt');

  await store.checkpointDevices([{ deviceId: 'dev-1', lastSequence: '11', signCount: 5 }]);
  assert.ok(queries.includes('BEGIN'));
  assert.ok(queries.includes('COMMIT'));
  assert.ok(queries.some(q => q.includes('length(last_sequence)<length($2)')));
});

test('GoogleRevocationSource utilizes Redis snapshot cache and distributed lock', async () => {
  const redisState = new Map<string, string>();
  const redisClient: any = {
    isReady: true,
    connect: async () => {},
    get: async (key: string) => redisState.get(key) ?? null,
    set: async (key: string, val: string) => {
      if (key.includes('lock:crl')) {
        redisState.set(key, val);
        return 'OK';
      }
      redisState.set(key, val);
      return 'OK';
    },
    eval: async () => 1
  };
  const { GoogleRevocationSource } = await import('../src/platform/trust.js');
  const fakeFetch = async () => new Response(JSON.stringify({ entries: { '01': { status: 'REVOKED' } } }), {
    status: 200,
    headers: { 'Cache-Control': 'max-age=3600' }
  });
  const source = new GoogleRevocationSource({
    redisClient,
    fetchFn: fakeFetch as any,
    now: () => 100000
  });

  const serials = await source.getRevokedSerials();
  assert.ok(serials.has('1'));
  assert.ok(redisState.has('sec:crl:snapshot'));

  let fetchCalled = false;
  const source2 = new GoogleRevocationSource({
    redisClient,
    fetchFn: (async () => { fetchCalled = true; throw new Error('should not fetch'); }) as any,
    now: () => 100000
  });
  const cachedSerials = await source2.getRevokedSerials();
  assert.equal(fetchCalled, false);
  assert.ok(cachedSerials.has('1'));
});
