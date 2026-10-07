import { 创建WS本地测速会话 } from './ws-speed-test.js';
import { 创建日志器 } from './utils/log.js';
import { 失效TCP连接世代 } from './connection.js';
import { closeSocketQuietly } from './utils/socket.js';
import { isSpeedTestSite } from './speed-test.js';
import { 数据转Uint8Array, 有效数据长度 } from './utils/bytes.js';
import { 解析木马请求, 解析魏烈思请求 } from './protocol.js';
import { 创建上行写入队列 } from './streams/upload-queue.js';
import { 创建SS上下文获取器 } from './ws-shadowsocks.js';
import { forwardataTCP } from './tunnel.js';
import { SS文本解码器 } from './shadowsocks.js';
import { 转发木马UDP数据 } from './trojan-udp.js';
import { forwardataudp } from './udp.js';
import { 上行队列最大字节, 上行队列最大条目 } from './state.js';
import { 解码WS早期数据 } from './ws-early-data.js';
export async function 处理WS请求(request, yourUUID, url, 反代上下文 = {}) {
  const 本地测速 = 创建WS本地测速会话();
  const log = 创建日志器(反代上下文.调试日志打印);
  const WS套接字对 = new WebSocketPair();
  const [clientSock, serverSock] = Object.values(WS套接字对);
  try {
    /** @type {any} */ (serverSock).accept({ allowHalfOpen: true });
  } catch (_) {
    serverSock.accept();
  }
  serverSock.binaryType = 'arraybuffer';
  let remoteConnWrapper = {
    socket: null,
    connectingPromise: null,
    retryConnect: null,
    downlinkDrain: Promise.resolve(),
  };
  const 失效远端连接 = () => 失效TCP连接世代(remoteConnWrapper);
  let isDnsQuery = false;
  let 判断是否是木马 = null;
  const 木马UDP上下文 = { 缓存: new Uint8Array(0), 反代地址: 反代上下文.木马反代地址 };
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const SS模式禁用EarlyData = !!url.searchParams.get('enc');
  let WS上行写入队列 = null;
  let WS显式传输链 = Promise.resolve();
  let WS显式传输停止接收 = false,
    WS显式传输失败 = false,
    WS显式传输收尾已入队 = false;
  let WS显式队列字节 = 0,
    WS显式队列条目 = 0;
  let 判断协议类型 = null,
    当前写入Socket = null,
    远端写入器 = null;

  const 释放远端写入器 = () => {
    if (远端写入器) {
      try {
        远端写入器.releaseLock();
      } catch (e) {}
      远端写入器 = null;
    }
    当前写入Socket = null;
  };

  const 上行写入队列 = (WS上行写入队列 = 创建上行写入队列({
    获取写入器: () => {
      const socket = remoteConnWrapper.socket;
      if (!socket) return null;
      if (socket !== 当前写入Socket) {
        释放远端写入器();
        当前写入Socket = socket;
        远端写入器 = socket.writable.getWriter();
      }
      return 远端写入器;
    },
    获取连接任务: () => remoteConnWrapper.connectingPromise,
    释放写入器: 释放远端写入器,
    重试连接: async () => {
      if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
      await remoteConnWrapper.retryConnect();
    },
    关闭连接: (err) => 处理WS显式传输错误(err),
    名称: 'WS上行',
  }));

  const 写入远端 = async (chunk, allowRetry = true) => {
    return 上行写入队列.写入(chunk, allowRetry);
  };

  const 获取SS上下文 = 创建SS上下文获取器(url, yourUUID, serverSock, log);

  const 处理SS数据 = async (chunk) => {
    const 上下文 = await 获取SS上下文();
    let 明文块数组 = null;
    try {
      明文块数组 = await 上下文.入站解密器.输入(chunk);
    } catch (err) {
      const msg = err?.message || `${err}`;
      if (
        msg.includes('Decryption failed') ||
        msg.includes('SS handshake decrypt failed') ||
        msg.includes('SS length decrypt failed')
      ) {
        log(`[SS入站] 解密失败，连接关闭: ${msg}`);
        closeSocketQuietly(serverSock);
        return;
      }
      throw err;
    }
    for (const 明文块 of 明文块数组) {
      if (本地测速.已启用) {
        await 本地测速.输入(明文块);
        continue;
      }
      let 已写入 = false;
      try {
        已写入 = await 写入远端(明文块, false);
      } catch (err) {
        if (/** @type {any} */ (err)?.isQueueOverflow) throw err;
        已写入 = false;
      }
      if (已写入) continue;
      if (上下文.首包已建立 && 上下文.目标主机 && 上下文.目标端口 > 0) {
        await forwardataTCP(
          上下文.目标主机,
          上下文.目标端口,
          明文块,
          上下文.回包Socket,
          null,
          remoteConnWrapper,
          yourUUID,
          request,
          反代上下文,
        );
        continue;
      }
      const 明文数据 = 数据转Uint8Array(明文块);
      if (明文数据.byteLength < 3) throw new Error('invalid ss data');
      const addressType = 明文数据[0];
      let cursor = 1;
      let hostname = '';
      if (addressType === 1) {
        if (明文数据.byteLength < cursor + 4 + 2) throw new Error('invalid ss ipv4 length');
        hostname = `${明文数据[cursor]}.${明文数据[cursor + 1]}.${明文数据[cursor + 2]}.${明文数据[cursor + 3]}`;
        cursor += 4;
      } else if (addressType === 3) {
        if (明文数据.byteLength < cursor + 1) throw new Error('invalid ss domain length');
        const domainLength = 明文数据[cursor];
        cursor += 1;
        if (明文数据.byteLength < cursor + domainLength + 2) throw new Error('invalid ss domain data');
        hostname = SS文本解码器.decode(明文数据.subarray(cursor, cursor + domainLength));
        cursor += domainLength;
      } else if (addressType === 4) {
        if (明文数据.byteLength < cursor + 16 + 2) throw new Error('invalid ss ipv6 length');
        const ipv6 = [];
        const ipv6View = new DataView(明文数据.buffer, 明文数据.byteOffset + cursor, 16);
        for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
        hostname = ipv6.join(':');
        cursor += 16;
      } else {
        throw new Error(`invalid ss addressType: ${addressType}`);
      }
      if (!hostname) throw new Error(`invalid ss address: ${addressType}`);
      const port = (明文数据[cursor] << 8) | 明文数据[cursor + 1];
      cursor += 2;
      const rawClientData = 明文数据.subarray(cursor);
      if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
        await 本地测速.启用(上下文.回包Socket, null, rawClientData);
        return;
      }
      上下文.首包已建立 = true;
      上下文.目标主机 = hostname;
      上下文.目标端口 = port;
      await forwardataTCP(
        hostname,
        port,
        rawClientData,
        上下文.回包Socket,
        null,
        remoteConnWrapper,
        yourUUID,
        request,
        反代上下文,
      );
    }
  };

  const 处理WS入站数据 = async (chunk) => {
    let 当前块字节 = null;
    if (isDnsQuery) {
      if (判断是否是木马) return await 转发木马UDP数据(chunk, serverSock, 木马UDP上下文, request);
      return await forwardataudp(chunk, serverSock, null, request);
    }
    if (判断协议类型 === 'ss') {
      await 处理SS数据(chunk);
      return;
    }
    if (本地测速.已启用) {
      await 本地测速.输入(chunk);
      return;
    }
    if (await 写入远端(chunk)) return;

    if (判断协议类型 === null) {
      if (url.searchParams.get('enc')) 判断协议类型 = 'ss';
      else {
        当前块字节 = 当前块字节 || 数据转Uint8Array(chunk);
        const bytes = 当前块字节;
        判断协议类型 = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a ? '木马' : '魏烈思';
      }
      判断是否是木马 = 判断协议类型 === '木马';
      log(
        `[WS转发] 协议类型: ${判断协议类型} | 来自: ${url.host} | UA: ${request.headers.get('user-agent') || '未知'}`,
      );
    }

    if (判断协议类型 === 'ss') {
      await 处理SS数据(chunk);
      return;
    }
    if (await 写入远端(chunk)) return;
    if (判断协议类型 === '木马') {
      const 解析结果 = 解析木马请求(chunk, yourUUID);
      if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid trojan request');
      const { port, hostname, rawClientData, isUDP } = 解析结果;
      if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
        await 本地测速.启用(serverSock, null, rawClientData);
        return;
      }
      if (isUDP) {
        isDnsQuery = true;
        木马UDP上下文.目标主机 = hostname;
        木马UDP上下文.目标端口 = port;
        if (木马UDP上下文.反代地址)
          return 转发木马UDP数据(当前块字节 || 数据转Uint8Array(chunk), serverSock, 木马UDP上下文, request);
        if (有效数据长度(rawClientData) > 0) return 转发木马UDP数据(rawClientData, serverSock, 木马UDP上下文, request);
        return;
      }
      await forwardataTCP(
        hostname,
        port,
        rawClientData,
        serverSock,
        null,
        remoteConnWrapper,
        yourUUID,
        request,
        反代上下文,
        true,
        当前块字节 || 数据转Uint8Array(chunk),
      );
    } else {
      判断是否是木马 = false;
      当前块字节 = 当前块字节 || 数据转Uint8Array(chunk);
      const bytes = 当前块字节;
      const 解析结果 = 解析魏烈思请求(bytes, yourUUID);
      if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid 魏烈思 request');
      const { port, hostname, version, isUDP, rawClientData } = 解析结果;
      const respHeader = new Uint8Array([version, 0]);
      if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
        await 本地测速.启用(serverSock, respHeader, rawClientData);
        return;
      }
      if (isUDP) {
        if (port === 53) isDnsQuery = true;
        else throw new Error('UDP is not supported');
      }
      const rawData = rawClientData;
      if (isDnsQuery) {
        if (判断是否是木马) return 转发木马UDP数据(rawData, serverSock, 木马UDP上下文, request);
        return forwardataudp(rawData, serverSock, respHeader, request);
      }
      await forwardataTCP(
        hostname,
        port,
        rawData,
        serverSock,
        respHeader,
        remoteConnWrapper,
        yourUUID,
        request,
        反代上下文,
      );
    }
  };

  const 处理WS显式传输错误 = (err) => {
    if (WS显式传输失败) return;
    WS显式传输失败 = true;
    WS显式传输停止接收 = true;
    WS显式队列字节 = 0;
    WS显式队列条目 = 0;
    const msg = err?.message || `${err}`;
    if (msg.includes('Network connection lost') || msg.includes('ReadableStream is closed')) {
      log(`[WS转发] 连接结束: ${msg}`);
    } else {
      log(`[WS转发] 处理失败: ${msg}`);
    }
    上行写入队列.清空();
    释放远端写入器();
    失效远端连接();
    try {
      木马UDP上下文.反代Socket?.close();
    } catch (e) {}
    closeSocketQuietly(serverSock);
  };

  const 追加WS显式传输任务 = (任务) => {
    WS显式传输链 = WS显式传输链.then(任务).catch(处理WS显式传输错误);
    return WS显式传输链;
  };

  const 入队WS显式传输 = (data) => {
    if (WS显式传输停止接收 || WS显式传输失败) return;
    const chunkSize = Math.max(0, 有效数据长度(data));
    const nextBytes = WS显式队列字节 + chunkSize;
    const nextItems = WS显式队列条目 + 1;
    if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
      处理WS显式传输错误(new Error(`[WS显式传输] 队列溢出: ${nextBytes}B/${nextItems}`));
      return;
    }
    WS显式队列字节 = nextBytes;
    WS显式队列条目 = nextItems;
    追加WS显式传输任务(async () => {
      WS显式队列字节 = Math.max(0, WS显式队列字节 - chunkSize);
      WS显式队列条目 = Math.max(0, WS显式队列条目 - 1);
      if (WS显式传输失败) return;
      await 处理WS入站数据(data);
    });
  };

  const 收尾WS显式传输 = () => {
    if (WS显式传输收尾已入队) return;
    WS显式传输收尾已入队 = true;
    WS显式传输停止接收 = true;
    追加WS显式传输任务(async () => {
      if (WS显式传输失败) return;
      await 上行写入队列.等待空();
      释放远端写入器();
      失效远端连接();
      try {
        木马UDP上下文.反代Socket?.close();
      } catch (e) {}
    });
  };

  serverSock.addEventListener('message', (event) => {
    入队WS显式传输(event.data);
  });
  serverSock.addEventListener('close', () => {
    closeSocketQuietly(serverSock);
    收尾WS显式传输();
  });
  serverSock.addEventListener('error', (err) => {
    处理WS显式传输错误(err);
  });

  // SS 模式下禁用 sec-websocket-protocol early-data，避免把子协议值（如 "binary"）误当作 base64 数据注入首包导致 AEAD 解密失败。
  if (!SS模式禁用EarlyData && earlyDataHeader) {
    try {
      const bytes = 解码WS早期数据(earlyDataHeader, yourUUID);
      if (bytes?.byteLength) 入队WS显式传输(bytes.buffer);
    } catch (error) {
      处理WS显式传输错误(error);
    }
  }

  return new Response(null, { status: 101, webSocket: clientSock, headers: { 'Sec-WebSocket-Extensions': '' } });
}
