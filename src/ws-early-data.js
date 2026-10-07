import { UUID字节匹配 } from './protocol.js';
import { sha224 } from './utils/crypto.js';
import { WS早期数据最大头长度, WS早期数据最大字节 } from './state.js';
export function 是有效WS早期数据(bytes, token) {
  if (!bytes?.byteLength) return false;
  if (bytes.byteLength >= 18 && UUID字节匹配(bytes, 1, token)) return true;
  if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;

  const trojanPassword = sha224(token);
  for (let i = 0; i < 56; i++) {
    if (bytes[i] !== trojanPassword.charCodeAt(i)) return false;
  }
  return true;
}

export function 解码WS早期数据(header, token) {
  if (!header) return null;
  if (header.length > WS早期数据最大头长度) throw new Error('early data is too large');

  let bytes;
  const Uint8ArrayBase64 = /** @type {any} */ (Uint8Array);
  if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
    try {
      bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' });
    } catch (_) {}
  }
  if (!bytes) {
    let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
    const padding = normalized.length % 4;
    if (padding) normalized += '='.repeat(4 - padding);
    let binaryString;
    try {
      binaryString = atob(normalized);
    } catch (_) {
      return null;
    }
    bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
  }

  if (bytes.byteLength > WS早期数据最大字节) throw new Error('early data is too large');
  return 是有效WS早期数据(bytes, token) ? bytes : null;
}
