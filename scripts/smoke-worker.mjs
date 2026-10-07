import assert from 'node:assert/strict';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

const uuid = '12345678-1234-4123-8123-123456789abc';
const worker = new Miniflare(
  convertV4MiniflareOptions({
    modules: true,
    scriptPath: 'dist/index.js',
    compatibilityDate: '2025-11-04',
    host: '127.0.0.1',
    port: 0,
    kvNamespaces: { KV: 'smoke-test-kv' },
    bindings: { ADMIN: 'smoke-test-admin', UUID: uuid, KEY: 'smoke-test-key', URL: 'nginx' },
    outboundService: async () => {
      throw new Error('冒烟测试禁止外部网络请求');
    },
  }),
);

// 仅操作本地 workerd 和内存 KV；所有凭证均为测试常量。
async function fetch(path, options = {}) {
  return worker.dispatchFetch(`https://worker.example${path}`, {
    redirect: 'manual',
    ...options,
    headers: { 'User-Agent': 'Mozilla/5.0', ...options.headers },
  });
}

try {
  const version = await fetch(`/version?uuid=${uuid}`);
  assert.equal((await version.json()).Version, 20260922200117);
  const denied = await fetch('/admin/config.json');
  assert.equal(denied.status, 302);
  const login = await fetch('/login', { method: 'POST', body: 'password=smoke-test-admin' });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('Set-Cookie');
  assert.ok(cookie.includes('Secure; SameSite=Strict'));
  const configResponse = await fetch('/admin/config.json', { headers: { Cookie: cookie } });
  const config = await configResponse.json();
  assert.equal(config.UUID, uuid);
  config.优选订阅生成.本地IP库.随机IP = false;
  const saved = await fetch('/admin/config.json', {
    method: 'POST',
    headers: { Cookie: cookie },
    body: JSON.stringify(config),
  });
  assert.equal(saved.status, 200);
  const added = await fetch('/admin/ADD.txt', {
    method: 'POST',
    headers: { Cookie: cookie },
    body: '104.16.0.1:443#smoke',
  });
  assert.equal(added.status, 200);
  const subscription = await fetch(`/sub?token=${config.优选订阅生成.TOKEN}`);
  assert.equal(subscription.status, 200);
  assert.ok((await subscription.text()).includes(uuid));
  const xhttp = await fetch('/proxy', { method: 'POST', body: new Uint8Array([1, 2, 3]) });
  assert.equal(xhttp.status, 400);
  const grpc = await fetch('/proxy', {
    method: 'POST',
    headers: { 'Content-Type': 'application/grpc' },
    body: new Uint8Array([0, 0, 0, 0, 0]),
  });
  assert.equal(grpc.status, 200);
  assert.equal((await grpc.arrayBuffer()).byteLength, 0);
  const websocket = await fetch('/proxy', { headers: { Upgrade: 'websocket' } });
  assert.equal(websocket.status, 101);
  const socket = websocket.webSocket;
  socket.accept();
  const host = new TextEncoder().encode('cp.cloudflare.com');
  const uuidBytes = uuid
    .replaceAll('-', '')
    .match(/../g)
    .map((hex) => parseInt(hex, 16));
  const httpRequest = new TextEncoder().encode('GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\n\r\n');
  const packet = new Uint8Array(23 + host.length + httpRequest.length);
  packet.set([0, ...uuidBytes, 0, 1, 0, 80, 2, host.length]);
  packet.set(host, 23);
  packet.set(httpRequest, 23 + host.length);
  const validXhttp = await fetch('/proxy', { method: 'POST', body: packet });
  assert.equal(validXhttp.status, 200);
  assert.ok(new TextDecoder().decode(new Uint8Array(await validXhttp.arrayBuffer()).slice(2)).includes('204'));
  const protobuf = new Uint8Array(2 + packet.length);
  protobuf.set([10, packet.length]);
  protobuf.set(packet, 2);
  const frame = new Uint8Array(5 + protobuf.length);
  frame.set([0, 0, 0, 0, protobuf.length]);
  frame.set(protobuf, 5);
  const validGrpc = await fetch('/proxy', {
    method: 'POST',
    headers: { 'Content-Type': 'application/grpc' },
    body: frame,
  });
  assert.equal(validGrpc.status, 200);
  assert.ok(new TextDecoder().decode(await validGrpc.arrayBuffer()).includes('204'));
  const received = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('WS 本地测速响应超时')), 3000);
    socket.addEventListener(
      'message',
      (event) => {
        clearTimeout(timeout);
        resolve(new Uint8Array(event.data));
      },
      { once: true },
    );
    socket.addEventListener(
      'error',
      (event) => {
        clearTimeout(timeout);
        reject(event.error);
      },
      { once: true },
    );
  });
  socket.send(packet);
  const result = await received;
  assert.equal(result[0], 0);
  assert.ok(new TextDecoder().decode(result.slice(2)).includes('204'));
  socket.close();
  console.log('Workers 本地冒烟通过：版本、认证、KV 配置、订阅、无效首包、WS/XHTTP/gRPC 的 VLESS 本地响应。');
} finally {
  await worker.dispose();
}
