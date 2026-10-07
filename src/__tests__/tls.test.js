import { beforeAll, afterAll, describe, expect, it } from 'vitest';
import { createServer } from 'node:tls';
import { createConnection } from 'node:net';
import { Readable, Writable } from 'node:stream';
import { once } from 'node:events';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCipheriv } from 'node:crypto';
import { TlsClient } from '../tls/client.js';
import { chacha20Poly1305Encrypt, chacha20Poly1305Decrypt } from '../tls/chacha.js';

let directory, key, cert;
beforeAll(() => {
  directory = mkdtempSync(join(tmpdir(), 'edgetunnel-tls-test-'));
  const keyPath = join(directory, 'key.pem'),
    certPath = join(directory, 'cert.pem');
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      keyPath,
      '-out',
      certPath,
      '-subj',
      '/CN=localhost',
      '-days',
      '1',
    ],
    { stdio: 'ignore' },
  );
  key = readFileSync(keyPath);
  cert = readFileSync(certPath);
});
afterAll(() => {
  if (directory) rmSync(directory, { recursive: true, force: true });
});

describe('TLS 握手与加密兼容', () => {
  it.each(['TLSv1.2', 'TLSv1.3'])('%s 上游请求客户端证书时回送空证书并完成握手', async (version) => {
    const sockets = new Set();
    const server = createServer(
      { key, cert, minVersion: version, maxVersion: version, requestCert: true, rejectUnauthorized: false },
      (connection) => {
        connection.on('data', (data) => connection.write(data));
      },
    );
    server.on('connection', (connection) => {
      sockets.add(connection);
      connection.on('close', () => sockets.delete(connection));
    });
    server.on('tlsClientError', () => {});
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const native = createConnection(server.address().port, '127.0.0.1');
    native.on('error', () => {});
    const remote = {
      readable: Readable.toWeb(native),
      writable: Writable.toWeb(native),
      close() {
        native.destroy();
      },
    };
    const client = new TlsClient(remote, {
      serverName: 'localhost',
      tls12: version === 'TLSv1.2',
      tls13: version === 'TLSv1.3',
      timeout: 1500,
    });
    try {
      await client.handshake();
      expect(client.handshakeComplete).toBe(true);
      expect(client.isTls13).toBe(version === 'TLSv1.3');
      const message = new TextEncoder().encode('test-data');
      await client.write(message);
      expect(new TextDecoder().decode(await client.read())).toBe('test-data');
    } finally {
      client.close();
      for (const connection of sockets) connection.destroy();
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('ChaCha20-Poly1305 输出与 Node 标准实现一致，拒绝篡改标签', () => {
    const key = new Uint8Array(32).fill(3),
      nonce = new Uint8Array(12).fill(4);
    const data = new TextEncoder().encode('private payload'),
      aad = new Uint8Array([1, 2, 3]);
    const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad, { plaintextLength: data.length });
    const expected = Buffer.concat([cipher.update(data), cipher.final(), cipher.getAuthTag()]);
    const actual = chacha20Poly1305Encrypt(key, nonce, data, aad);
    expect([...actual]).toEqual([...expected]);
    expect(chacha20Poly1305Decrypt(key, nonce, actual, aad)).toEqual(data);
    actual[actual.length - 1] ^= 1;
    expect(() => chacha20Poly1305Decrypt(key, nonce, actual, aad)).toThrow();
  });
});
