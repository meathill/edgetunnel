import { 有效数据长度, 数据转Uint8Array } from './utils/bytes.js';
import { log } from './utils/log.js';
export function isSpeedTestSite(hostname) {
  const speedTestDomains = ['speed.cloudflare.com', 'cp.cloudflare.com'];
  hostname = hostname.toLowerCase();
  return speedTestDomains.some((domain) => hostname === domain || hostname.endsWith('.' + domain));
}

export function 构造本地204响应(respHeader = null) {
  const 本地204响应 = new TextEncoder().encode(
    'HTTP/1.1 204 No Content\r\n' + 'Content-Length: 0\r\n' + 'Connection: close\r\n' + '\r\n',
  );
  if (有效数据长度(respHeader) === 0) return 本地204响应;
  const 协议响应头 = 数据转Uint8Array(respHeader);
  const response = new Uint8Array(协议响应头.byteLength + 本地204响应.byteLength);
  response.set(协议响应头, 0);
  response.set(本地204响应, 协议响应头.byteLength);
  log(`[TCP转发] 构造本地204响应: ${response.byteLength}B`);
  return response;
}

export function 构造WS本地204响应(respHeader = null) {
  const WS本地204响应 = new TextEncoder().encode(
    'HTTP/1.1 204 No Content\r\n' + 'Content-Length: 0\r\n' + 'Connection: keep-alive\r\n' + '\r\n',
  );
  if (有效数据长度(respHeader) === 0) return WS本地204响应;
  const 协议响应头 = 数据转Uint8Array(respHeader);
  const response = new Uint8Array(协议响应头.byteLength + WS本地204响应.byteLength);
  response.set(协议响应头, 0);
  response.set(WS本地204响应, 协议响应头.byteLength);
  return response;
}
