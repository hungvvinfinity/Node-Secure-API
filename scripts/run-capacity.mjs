import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';

const cwd = fileURLToPath(new URL('../', import.meta.url));
const output = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-api-capacity-'));
for (const dir of ['fixtures', 'results']) fs.mkdirSync(path.join(output, dir));
const project = 'secure-capacity-' + randomUUID().slice(0, 8);
const env = { ...process.env, BENCHMARK_OUTPUT_DIR: output };
const args = ['compose', '-p', project, '-f', 'compose.benchmark.yaml'];
const duration = Number(process.env.CAPACITY_STAGE_SECONDS ?? 15);
const confirmation = Number(process.env.CAPACITY_CONFIRM_SECONDS ?? 60);
const replicas = Number(process.env.CAPACITY_API_REPLICAS ?? 1);
const reportName = process.env.CAPACITY_REPORT_FILE ?? 'capacity-results.json';
const preallocated = Number(process.env.CAPACITY_VUS ?? 512);
const rates = (process.env.CAPACITY_RATES ?? '500,1000,2000,4000,8000,12000,16000,24000,32000').split(',').map(Number);
if (![duration, confirmation].every(n => Number.isInteger(n) && n >= 3 && n <= 300)) throw new Error('Invalid capacity durations');
if (!Number.isInteger(replicas) || replicas < 1 || replicas > 8 || !/^[a-z0-9-]+\.json$/.test(reportName)) throw new Error('Invalid capacity options');
if (!Number.isInteger(preallocated) || preallocated < 1 || preallocated > 512 || !rates.length ||
    rates.some((rate, i) => !Number.isInteger(rate) || rate < 1 || rate > 100000 || (i > 0 && rate <= rates[i - 1]))) throw new Error('Invalid load options');
let child;
let interrupted = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { interrupted = true; child?.kill(signal); });
async function compose(command, logName = 'orchestration.log') {
  if (interrupted && command[0] !== 'down') throw new Error('Capacity run interrupted');
  const fd = fs.openSync(path.join(output, logName), 'a');
  try {
    return await new Promise((resolve, reject) => {
      child = spawn('docker', [...args, ...command], { cwd, env, stdio: ['ignore', fd, fd] });
      child.once('error', reject);
      child.once('exit', code => { child = undefined; resolve(code); });
    });
  } finally { fs.closeSync(fd); }
}
const exec = promisify(execFile);
let stage = 0;
const results = [];
async function measure(rate, seconds, label) {
  const index = ++stage;
  const samples = [];
  let sampling = false;
  const timer = setInterval(async () => {
    if (sampling) return;
    sampling = true;
    try {
      const { stdout } = await exec('docker', ['stats', '--no-stream', '--format', '{{json .}}'], { timeout: 5000 });
      const sampledAt = Date.now();
      for (const line of stdout.trim().split('\n')) {
        const row = JSON.parse(line);
        if (row.Name.startsWith(project + '-')) samples.push({ at: sampledAt, ...row });
      }
    } catch { /* Sampling must not change the load generator's result. */ }
    finally { sampling = false; }
  }, 2000);
  let code;
  try {
    code = await compose(['run', '--rm', '--no-deps', '-e', `RATE=${rate}`, '-e', `DURATION=${seconds}s`,
      '-e', `VUS=${preallocated}`, '-e', 'MAX_VUS=512', '-e', `SEQUENCE_BASE=${index * 1_000_000_000}`, 'k6'], `stage-${index}.log`);
  } finally { clearInterval(timer); }
  if (code !== 0 && code !== 99) throw new Error(`k6 execution error ${code}; see ${output}/stage-${index}.log`);
  const summaryFile = path.join(output, 'results', 'summary.json');
  const summary = JSON.parse(fs.readFileSync(summaryFile, 'utf8'));
  fs.copyFileSync(summaryFile, path.join(output, 'results', `stage-${index}.json`));
  const metric = (name, key, fallback = 0) => summary.metrics[name]?.values[key] ?? fallback;
  const accepted = metric('accepted', 'count');
  const rejected = metric('rejected', 'count');
  const dropped = metric('dropped_iterations', 'count');
  const p95 = metric('http_req_duration', 'p(95)', Infinity);
  const p99 = metric('http_req_duration', 'p(99)', Infinity);
  const pass = code === 0 && rejected / Math.max(1, accepted + rejected) < .01 && dropped === 0 &&
    p95 < 100 && p99 < 250 && accepted >= rate * seconds * .99;
  const peaks = {};
  const apiTotals = new Map();
  for (const row of samples) {
    const service = row.Name.includes('-api-') ? 'api' : row.Name.includes('-redis-') ? 'redis' : 'k6';
    const peak = peaks[service] ?? { cpuPercent: 0, memory: '' };
    const cpu = parseFloat(row.CPUPerc);
    if (service === 'api') apiTotals.set(row.at, (apiTotals.get(row.at) ?? 0) + cpu);
    if (cpu >= peak.cpuPercent) peaks[service] = { cpuPercent: cpu, memory: row.MemUsage };
  }
  const result = { stage: index, label, targetRps: rate, seconds, accepted, rejected, dropped,
    acceptedRps: +(accepted / seconds).toFixed(1), p95ms: +p95.toFixed(2), p99ms: +p99.toFixed(2),
    signingP95ms: metric('signing_ms', 'p(95)'), pass, resourcePeaks: peaks,
    apiTotalCpuPercentPeak: Math.max(0, ...apiTotals.values()) };
  results.push(result);
  fs.writeFileSync(path.join(output, 'results', `resources-${index}.json`), JSON.stringify(samples, null, 2));
  console.log(JSON.stringify(result));
  return result;
}
let failure;
try {
  console.log(`Capacity artifacts: ${output}`);
  if (await compose(['build', 'api', 'seed']) !== 0) throw new Error('Benchmark image build failed');
  if (await compose(['up', '-d', '--wait', '--wait-timeout', '90', '--scale', `api=${replicas}`, 'api', 'redis']) !== 0) throw new Error('Benchmark stack unavailable');
  if (await compose(['run', '--rm', '--no-deps', 'seed']) !== 0) throw new Error('Synthetic seed failed');
  const smoke = await measure(50, 3, 'smoke');
  if (!smoke.pass) throw new Error('Signed traffic smoke failed; do not interpret capacity');
  let lower = 0;
  let upper = 0;
  for (const rate of rates) {
    if ((await measure(rate, duration, 'sweep')).pass) lower = rate;
    else { upper = rate; break; }
  }
  if (upper && lower) for (let i = 0; i < 5 && upper - lower > 250; i++) {
    const rate = Math.round((lower + upper) / 500) * 250;
    if ((await measure(rate, duration, 'refine')).pass) lower = rate;
    else upper = rate;
  }
  let confirmed;
  if (lower) {
    let candidate = lower;
    for (let attempt = 0; attempt < 3; attempt++) {
      confirmed = await measure(candidate, confirmation, 'confirmation');
      if (confirmed.pass) break;
      candidate = Math.max(1, Math.floor(candidate * .8 / 250) * 250);
    }
  }
  const report = { generatedAt: new Date().toISOString(), scope: 'synthetic-seeded Android steady-state on actual runtime API',
    hardwareAttestationMeasured: false, tlsOrAiBusinessMeasured: false,
    slo: { p95Ms: 100, p99Ms: 250, errorRateBelow: .01, droppedIterations: 0 },
    host: { cpu: os.cpus()[0]?.model, logicalCpus: os.cpus().length, memoryGiB: +(os.totalmem() / 2 ** 30).toFixed(1) },
    persistence: 'Redis AOF appendfsync always', k6: '2.3.0',
    apiReplicas: replicas,
    preAllocatedVUs: preallocated, maxVUs: 512,
    highestPassingTargetRps: lower || null, shortStageFailureUpperBoundRps: upper || null,
    confirmedTargetRps: confirmed?.pass ? confirmed.targetRps : null, results };
  fs.writeFileSync(path.join(cwd, 'docs', reportName), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ report: 'docs/' + reportName, artifacts: output,
    confirmedTargetRps: report.confirmedTargetRps, highestPassingTargetRps: lower, shortStageFailureUpperBoundRps: upper }));
} catch (error) { failure = error; }
finally {
  const cleanup = await compose(['down', '--volumes']);
  fs.rmSync(path.join(output, 'fixtures'), { recursive: true, force: true });
  if (cleanup !== 0 && !failure) failure = new Error('Benchmark Compose cleanup failed');
}
if (failure) { console.error(failure instanceof Error ? failure.message : 'Capacity failed'); process.exitCode = 1; }
