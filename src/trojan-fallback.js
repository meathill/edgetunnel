import { stripIPv6Brackets } from './utils/address.js';
import { 有效数据长度, 数据转Uint8Array } from './utils/bytes.js';
import { 创建请求TCP连接器 } from './tcp-connect.js';
import { closeSocketQuietly } from './utils/socket.js';
import { connectStreams } from './streams/bridge.js';
export function 解析木马反代地址(address) {
  const raw = String(address || '').trim();
  if (!raw || raw.includes('/') || raw.includes('@') || raw.includes('://'))
    throw new Error('木马反代仅支持 host:port');
  let hostname = '',
    portText = '';
  if (raw.startsWith('[')) {
    const 匹配 = raw.match(/^(\[[^\]]+\]):(\d+)$/);
    if (!匹配) throw new Error('无效的 IPv6 木马反代地址');
    hostname = 匹配[1];
    portText = 匹配[2];
  } else {
    const parts = raw.split(':');
    if (parts.length !== 2) throw new Error('木马反代仅支持 host:port');
    hostname = parts[0];
    portText = parts[1];
  }
  const port = Number(portText);
  if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('无效的木马反代端口');
  return { hostname, port };
}

export async function 连接木马反代(首包数据, TCP连接, 木马反代目标) {
  if (!木马反代目标) throw new Error('trojan fallback is not configured');
  const socket = TCP连接({ hostname: stripIPv6Brackets(木马反代目标.hostname), port: 木马反代目标.port });
  let writer = null;
  try {
    if (socket.opened) await socket.opened;
    if (有效数据长度(首包数据) > 0) {
      writer = socket.writable.getWriter();
      await writer.write(数据转Uint8Array(首包数据));
    }
    return socket;
  } catch (error) {
    try {
      socket?.close?.();
    } catch (e) {}
    throw error;
  } finally {
    try {
      writer?.releaseLock();
    } catch (e) {}
  }
}

export function 提取木马反代握手数据(首包数据, rawData) {
  const 首包 = 数据转Uint8Array(首包数据);
  const payload = 数据转Uint8Array(rawData);
  if (!payload.byteLength) return 首包;
  const 握手长度 = 首包.byteLength - payload.byteLength;
  if (握手长度 <= 0) return 首包;
  for (let i = 0; i < payload.byteLength; i++) {
    if (首包[握手长度 + i] !== payload[i]) return 首包;
  }
  return 首包.subarray(0, 握手长度);
}

export async function 转发木马UDP反代数据(chunk, webSocket, 上下文, request) {
  const data = 数据转Uint8Array(chunk);
  if (!上下文.反代Socket) {
    const TCP连接 = 创建请求TCP连接器(request);
    const socket = await 连接木马反代(data, TCP连接, 上下文.反代地址);
    上下文.反代Socket = socket;
    socket.closed.catch(() => {}).finally(() => closeSocketQuietly(webSocket));
    void connectStreams(socket, webSocket, null, null).catch(() => {
      try {
        socket.close();
      } catch (error) {}
      closeSocketQuietly(webSocket);
    });
    return;
  }
  if (!data.byteLength) return;
  const writer = 上下文.反代Socket.writable.getWriter();
  try {
    await writer.write(data);
  } finally {
    try {
      writer.releaseLock();
    } catch (e) {}
  }
}
