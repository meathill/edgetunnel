import { SSTP_EMPTY_BYTES, readSstpUint16 } from './sstp-protocol.js';
import { 数据转Uint8Array, 拼接字节数据 } from './utils/bytes.js';
import { textDecoder } from './tls/constants.js';
import { CONNECT_TIMEOUT_MS, withTimeout } from './turn-protocol.js';
export function 创建SSTP读取器(获取reader) {
  let bufferedBytes = SSTP_EMPTY_BYTES;
  const readSocketChunk = async () => {
    const { value, done } = await 获取reader().read();
    if (done || !value) throw new Error('SSTP socket closed');
    return 数据转Uint8Array(value);
  };
  const readBytes = async (length) => {
    while (bufferedBytes.byteLength < length) {
      const chunk = await readSocketChunk();
      bufferedBytes = bufferedBytes.byteLength ? 拼接字节数据(bufferedBytes, chunk) : chunk;
    }
    const result = bufferedBytes.subarray(0, length);
    bufferedBytes = bufferedBytes.subarray(length);
    return result;
  };
  const readHttpLine = async () => {
    for (;;) {
      const lineEnd = bufferedBytes.indexOf(10);
      if (lineEnd >= 0) {
        const line = textDecoder.decode(bufferedBytes.subarray(0, lineEnd));
        bufferedBytes = bufferedBytes.subarray(lineEnd + 1);
        return line.replace(/\r$/, '');
      }
      const chunk = await readSocketChunk();
      bufferedBytes = bufferedBytes.byteLength ? 拼接字节数据(bufferedBytes, chunk) : chunk;
    }
  };
  const readPacket = async (timeoutMs = CONNECT_TIMEOUT_MS) => {
    const header = await withTimeout(readBytes(4), timeoutMs, 'SSTP read timeout');
    const length = readSstpUint16(header, 2) & 0x0fff;
    if (length < 4) throw new Error('Invalid SSTP packet length');
    return {
      isControl: (header[1] & 1) !== 0,
      body:
        length > 4
          ? await withTimeout(readBytes(length - 4), timeoutMs, 'SSTP packet body read timeout')
          : SSTP_EMPTY_BYTES,
    };
  };
  return {
    readHttpLine,
    readPacket,
    get 剩余字节数() {
      return bufferedBytes.byteLength;
    },
  };
}
