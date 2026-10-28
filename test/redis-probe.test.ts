import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { checkRedisAvailable } from './helpers/redis-probe.js';

describe('Redis Availability Probe Helper Tests', () => {
  it('returns false when URL is undefined (allows unit-only test skips)', async () => {
    const isAvailable = await checkRedisAvailable(undefined);
    assert.equal(isAvailable, false);
  });

  it('throws sanitized REDIS_TEST_UNAVAILABLE when URL is empty or whitespace', async () => {
    for (const invalidUrl of ['', '   ', '\t\n']) {
      await assert.rejects(
        () => checkRedisAvailable(invalidUrl),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'REDIS_TEST_UNAVAILABLE');
          return true;
        }
      );
    }
  });

  it('throws sanitized REDIS_TEST_UNAVAILABLE when URL is malformed or invalid protocol', async () => {
    const invalidProtocols = [
      'not-a-valid-url',
      'http://127.0.0.1:6379',
      'https://127.0.0.1:6379',
      'ws://127.0.0.1:6379',
      'tcp://127.0.0.1:6379'
    ];

    for (const badUrl of invalidProtocols) {
      await assert.rejects(
        () => checkRedisAvailable(badUrl),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'REDIS_TEST_UNAVAILABLE');
          return true;
        }
      );
    }
  });

  it('throws sanitized REDIS_TEST_UNAVAILABLE for unreachable host/port and does NOT leak password credentials', async () => {
    // Acquire a guaranteed closed port
    const port = await new Promise<number>((resolve, reject) => {
      const s = net.createServer();
      s.listen(0, '127.0.0.1', () => {
        const addr = s.address() as net.AddressInfo;
        s.close((err) => (err ? reject(err) : resolve(addr.port)));
      });
    });

    const secretPassword = 'SUPER_SECRET_TOKEN_DO_NOT_LEAK_12345';
    const secretUrl = `redis://default:${secretPassword}@127.0.0.1:${port}`;

    await assert.rejects(
      () => checkRedisAvailable(secretUrl, 150),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'REDIS_TEST_UNAVAILABLE');
        assert.ok(!err.message.includes(secretPassword), 'Password leaked in error message');
        assert.ok(!String(err.stack).includes(secretPassword), 'Password leaked in stack trace');
        return true;
      }
    );
  });

  it('handles blackhole TCP server (connection/HELLO hangs) with bounded timeout and cleans up socket', async () => {
    let acceptedSocket: net.Socket | undefined;
    let clientClosedOnServerSide = false;
    let server: net.Server | undefined;

    try {
      server = await new Promise<net.Server>((resolve) => {
        const s = net.createServer((sock) => {
          acceptedSocket = sock;
          sock.on('error', () => { /* Safe error listener prevents unhandled ECONNRESET */ });
          sock.on('close', () => {
            clientClosedOnServerSide = true;
          });
          sock.resume(); // Drain incoming HELLO/PING data so client disconnect (FIN/RST) is processed
          // Blackhole: do not send any Redis response or close socket
        });
        s.listen(0, '127.0.0.1', () => resolve(s));
      });

      const addr = server.address() as net.AddressInfo;
      const blackholeUrl = `redis://127.0.0.1:${addr.port}`;

      const timeoutMs = 150;
      const startTime = Date.now();

      await assert.rejects(
        () => checkRedisAvailable(blackholeUrl, timeoutMs),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.equal(err.message, 'REDIS_TEST_UNAVAILABLE');
          return true;
        }
      );

      const elapsed = Date.now() - startTime;
      // Invariant: Must fail boundedly within a small margin of timeoutMs, not default 60s
      assert.ok(elapsed < 1000, `Expected bounded timeout < 1000ms, took ${elapsed}ms`);

      // Invariant: Prove client actively disposed and closed connection BEFORE forced test cleanup
      const closeDeadline = Date.now() + 500;
      while (!clientClosedOnServerSide && Date.now() < closeDeadline) {
        await new Promise((r) => setTimeout(r, 10));
      }
      assert.equal(
        clientClosedOnServerSide,
        true,
        'Accepted server socket must be closed by client disposal within bounded timeout BEFORE server cleanup'
      );
    } finally {
      if (acceptedSocket) {
        acceptedSocket.destroy();
      }
      if (server) {
        await new Promise<void>((resolve) => server!.close(() => resolve()));
      }
    }
  });

  it('successfully verifies reachability for real Redis instance', async (t) => {
    const liveUrl = process.env.REDIS_TEST_URL;
    if (liveUrl === undefined) {
      t.skip('Skipping live Redis probe: REDIS_TEST_URL not set in unit-only environment');
      return;
    }
    const isAvailable = await checkRedisAvailable(liveUrl, 1000);
    assert.equal(isAvailable, true);
  });

  it('throws sanitized REDIS_TEST_UNAVAILABLE when explicit URL points to non-existent Redis server', async () => {
    const closedPort = await new Promise<number>((resolve, reject) => {
      const s = net.createServer();
      s.listen(0, '127.0.0.1', () => {
        const addr = s.address() as net.AddressInfo;
        s.close((err) => (err ? reject(err) : resolve(addr.port)));
      });
    });

    const unavailableUrl = `redis://127.0.0.1:${closedPort}`;
    await assert.rejects(
      () => checkRedisAvailable(unavailableUrl, 150),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.equal(err.message, 'REDIS_TEST_UNAVAILABLE');
        return true;
      }
    );
  });
});
