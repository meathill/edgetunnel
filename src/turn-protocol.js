import { 数据转Uint8Array, 拼接字节数据, 有效数据长度 } from './utils/bytes.js';
export const CONNECT_TIMEOUT_MS = 9999;

export const TURN_STUN_MAGIC_COOKIE = new Uint8Array([0x21, 0x12, 0xa4, 0x42]);

export const TURN_STUN_TYPE = {
  ALLOCATE_REQUEST: 0x0003,
  ALLOCATE_SUCCESS: 0x0103,
  ALLOCATE_ERROR: 0x0113,
  CREATE_PERMISSION_REQUEST: 0x0008,
  CREATE_PERMISSION_SUCCESS: 0x0108,
  CONNECT_REQUEST: 0x000a,
  CONNECT_SUCCESS: 0x010a,
  CONNECTION_BIND_REQUEST: 0x000b,
  CONNECTION_BIND_SUCCESS: 0x010b,
};

export const TURN_STUN_ATTR = {
  USERNAME: 0x0006,
  MESSAGE_INTEGRITY: 0x0008,
  ERROR_CODE: 0x0009,
  XOR_PEER_ADDRESS: 0x0012,
  REALM: 0x0014,
  NONCE: 0x0015,
  REQUESTED_TRANSPORT: 0x0019,
  CONNECTION_ID: 0x002a,
};

export async function withTimeout(promise, timeoutMs, message) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(message)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export function isIPv4(value) {
  const parts = String(value || '').split('.');
  return (
    parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255)
  );
}

export function turnStunPadding(length) {
  return -length & 3;
}

export function createTurnStunAttribute(type, value) {
  const body = 数据转Uint8Array(value);
  const attribute = new Uint8Array(4 + body.byteLength + turnStunPadding(body.byteLength));
  const view = new DataView(attribute.buffer);
  view.setUint16(0, type);
  view.setUint16(2, body.byteLength);
  attribute.set(body, 4);
  return attribute;
}

export function createTurnStunMessage(type, transactionId, attributes) {
  const body = 拼接字节数据(...attributes);
  const header = new Uint8Array(20);
  const view = new DataView(header.buffer);
  view.setUint16(0, type);
  view.setUint16(2, body.byteLength);
  header.set(TURN_STUN_MAGIC_COOKIE, 4);
  header.set(transactionId, 8);
  return 拼接字节数据(header, body);
}

export function parseTurnErrorCode(data) {
  return data?.byteLength >= 4 ? (data[2] & 7) * 100 + data[3] : 0;
}

export function randomTurnTransactionId() {
  return crypto.getRandomValues(new Uint8Array(12));
}

export async function addTurnMessageIntegrity(message, key) {
  const signedMessage = new Uint8Array(message);
  const view = new DataView(signedMessage.buffer);
  view.setUint16(2, view.getUint16(2) + 24);
  const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', hmacKey, signedMessage);
  return 拼接字节数据(
    signedMessage,
    createTurnStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY, new Uint8Array(signature)),
  );
}

export async function readTurnStunMessage(reader, bufferedData = null, timeoutMessage = 'TURN response timed out') {
  let buffer = 有效数据长度(bufferedData) ? 数据转Uint8Array(bufferedData) : new Uint8Array(0);
  const pull = async () => {
    const { done, value } = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, timeoutMessage);
    if (done) throw new Error('TURN server closed connection');
    if (value?.byteLength) buffer = 拼接字节数据(buffer, value);
  };
  while (buffer.byteLength < 20) await pull();

  const messageLength = 20 + ((buffer[2] << 8) | buffer[3]);
  if (messageLength > 65555) throw new Error('TURN response is too large');
  while (buffer.byteLength < messageLength) await pull();
  const messageBuffer = buffer.subarray(0, messageLength);
  if (TURN_STUN_MAGIC_COOKIE.some((value, index) => messageBuffer[4 + index] !== value))
    throw new Error('Invalid TURN/STUN response');

  const view = new DataView(messageBuffer.buffer, messageBuffer.byteOffset, messageBuffer.byteLength);
  const attributes = {};
  for (let offset = 20; offset + 4 <= messageLength;) {
    const type = view.getUint16(offset);
    const length = view.getUint16(offset + 2);
    if (offset + 4 + length > messageBuffer.byteLength) break;
    attributes[type] = messageBuffer.slice(offset + 4, offset + 4 + length);
    offset += 4 + length + turnStunPadding(length);
  }
  return {
    message: { type: view.getUint16(0), attributes },
    extraData: buffer.byteLength > messageLength ? buffer.subarray(messageLength) : null,
  };
}

export async function writeTurnBytes(writer, bytes, timeoutMessage) {
  await withTimeout(writer.write(bytes), CONNECT_TIMEOUT_MS, timeoutMessage);
}
