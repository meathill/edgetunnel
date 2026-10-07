import { vi } from 'vitest';

export const UUID = '12345678-1234-4123-8123-123456789abc';
export const HOST = 'worker.example';
export const UA = 'Mozilla/5.0';
export const ADMIN = 'test-admin';
export const KEY = 'test-key';

export function memoryKV(entries = {}) {
  const data = new Map(Object.entries(entries));
  return {
    data,
    get: vi.fn(async (key) => data.get(key) ?? null),
    put: vi.fn(async (key, value) => {
      data.set(key, value);
    }),
  };
}

export function context() {
  const tasks = [];
  return {
    tasks,
    waitUntil(task) {
      tasks.push(task.catch(() => {}));
    },
  };
}

export function request(path, options = {}, cf = {}) {
  const result = new Request(`https://${HOST}${path}`, {
    ...options,
    headers: { 'User-Agent': UA, ...options.headers },
  });
  Object.defineProperty(result, 'cf', { value: { colo: 'NRT', country: 'US', asn: 13335, ...cf } });
  return result;
}

export function bytes(text) {
  return new TextEncoder().encode(text);
}

export function vlessPacket(hostname = 'example.com', port = 443, payload = new Uint8Array(), command = 1) {
  const host = bytes(hostname);
  const packet = new Uint8Array(23 + host.length + payload.length);
  const uuidBytes = UUID.replaceAll('-', '')
    .match(/../g)
    .map((hex) => parseInt(hex, 16));
  packet.set([0, ...uuidBytes, 0, command, port >> 8, port & 255, 2, host.length]);
  packet.set(host, 23);
  packet.set(payload, 23 + host.length);
  return packet;
}

export function socket(chunks = [], write = async () => {}, { keepOpen = false } = {}) {
  let readerController;
  const readable = new ReadableStream({
    start(controller) {
      readerController = controller;
      for (const chunk of chunks) controller.enqueue(chunk);
      if (!keepOpen) controller.close();
    },
  });
  return {
    opened: Promise.resolve(),
    closed: Promise.resolve(),
    readable,
    writable: new WritableStream({ write }),
    close: vi.fn(),
    readerController,
  };
}

export function webSocket() {
  return { readyState: 1, send: vi.fn(), close: vi.fn() };
}
