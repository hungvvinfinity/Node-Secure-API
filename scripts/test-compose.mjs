import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

// No host node_modules or Redis needed; all application checks run inside the image.
const cwd = fileURLToPath(new URL('../', import.meta.url));
const project = 'secure-api-test-' + randomUUID().slice(0, 8);
const runId = randomUUID();
const composeArgs = ['compose', '-p', project, '-f', 'compose.test.yaml'];
let interrupted = false;
let activeChild;
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  interrupted = true;
  activeChild?.kill(signal);
});
async function compose(args, captureOutput = false) {
  if (interrupted && args[0] !== 'down') throw new Error('Compose verification interrupted');
  return await new Promise((resolve, reject) => {
    let output = '';
    const child = spawn('docker', [...composeArgs, ...args], { cwd,
      stdio: captureOutput ? ['ignore', 'pipe', 'inherit'] : 'inherit' });
    if (captureOutput) child.stdout.on('data', data => {
      output += data.toString('utf8');
      if (Buffer.byteLength(output) > 65536) {
        child.kill('SIGTERM');
        reject(new Error('Compose proof output exceeded limit'));
      }
    });
    activeChild = child;
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (activeChild === child) activeChild = undefined;
      if (captureOutput) process.stdout.write(output);
      code === 0 ? resolve(output) : reject(new Error(`Compose ${args[0]} failed (${signal ?? code})`));
    });
  });
}
let failed = false;
try {
  await compose(['build', 'tests']);
  await compose(['up', '-d', '--wait', '--wait-timeout', '45', 'redis']);
  await compose(['run', '--rm', '--no-deps', 'tests']);
  const run = ['run', '--rm', '--no-deps', '-e', `PERSISTENCE_TEST_ID=${runId}`];
  const proof = ['tests', 'node', '--import', 'tsx', 'scripts/compose-persistence.ts'];
  const seeded = JSON.parse((await compose([...run, ...proof, 'seed'], true)).trim());
  if (!/^[a-f0-9]{64}$/.test(seeded.publicKeySha256 ?? '')) throw new Error('Invalid seed key hash');
  await compose(['restart', 'redis']);
  await compose(['up', '-d', '--wait', '--wait-timeout', '45', 'redis']);
  await compose([...run, '-e', `PERSISTENCE_EXPECTED_KEY_SHA256=${seeded.publicKeySha256}`, ...proof, 'verify']);
  console.log(JSON.stringify({ dockerCompose: true, realRedis: true, realCryptographicFixtures: true,
    realHttpIntegration: true, redisServiceActuallyRestarted: true, result: 'PASS' }));
} catch (error) {
  failed = true;
  console.error(error instanceof Error ? error.message : 'Compose verification failed');
} finally {
  try { await compose(['down', '--volumes']); }
  catch (error) { failed = true; console.error(error instanceof Error ? error.message : 'Compose cleanup failed'); }
}
if (failed) process.exitCode = 1;
