import { 创建日志器, log } from './utils/log.js';
import { 获取叉HTTPPadding标识, 校验叉HTTPPadding, 生成叉HTTPPadding串 } from './xhttp-padding.js';
import { 读取叉HTTP首包 } from './xhttp-protocol.js';
import { isSpeedTestSite, 构造本地204响应 } from './speed-test.js';
import { 失效TCP连接世代 } from './connection.js';
import { forwardataTCP } from './tunnel.js';
import { 创建上行Grain合包流 } from './streams/upload-stream.js';
import { 有效数据长度 } from './utils/bytes.js';
import { 转发木马UDP数据 } from './trojan-udp.js';
import { forwardataudp } from './udp.js';
import { closeSocketQuietly } from './utils/socket.js';
export async function 处理叉HTTP请求(request, yourUUID, 反代上下文 = {}) {
  const log = 创建日志器(反代上下文.调试日志打印);
  if (!request.body) return new Response('Bad Request', { status: 400 });
  const { 头: 本机Padding头, 键: 本机Padding键 } = 获取叉HTTPPadding标识(yourUUID);
  if (!校验叉HTTPPadding(request, 本机Padding头, 本机Padding键)) return new Response('Bad Request', { status: 400 });
  const reader = request.body.getReader();
  const 首包 = await 读取叉HTTP首包(reader, yourUUID);
  if (!首包) {
    try {
      reader.releaseLock();
    } catch (e) {}
    return new Response('Invalid request', { status: 400 });
  }
  if (isSpeedTestSite(首包.hostname) && 反代上下文.代理类型 === null) {
    try {
      reader.releaseLock();
    } catch (e) {}
    return new Response(构造本地204响应(首包.respHeader), {
      status: 200,
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-Accel-Buffering': 'no',
        'Cache-Control': 'no-store',
      },
    });
  }
  if (首包.isUDP && 首包.协议 !== 'trojan' && 首包.port !== 53) {
    try {
      reader.releaseLock();
    } catch (e) {}
    return new Response('UDP is not supported', { status: 400 });
  }

  const responseHeaders = new Headers({
    'Content-Type': 'application/octet-stream',
    'X-Accel-Buffering': 'no',
    'Cache-Control': 'no-store',
  });

  try {
    const 响应URL = new URL('https://x.invalid/');
    响应URL.searchParams.set(本机Padding键, 生成叉HTTPPadding串(100 + Math.floor(Math.random() * 901)));
    responseHeaders.set(本机Padding头, 响应URL.toString());
  } catch (e) {}

  if (首包.isUDP) return 处理叉HTTPUDP请求(首包, reader, request, 反代上下文, responseHeaders);

  try {
    reader.releaseLock();
  } catch (e) {}

  const remoteConnWrapper = {
    socket: null,
    connectingPromise: null,
    retryConnect: null,
    downlinkDrain: Promise.resolve(),
  };
  const abortController = new AbortController();
  let 已清理 = false;
  const 清理 = (reason) => {
    if (已清理) return;
    已清理 = true;
    try {
      abortController.abort(reason);
    } catch (e) {}
    失效TCP连接世代(remoteConnWrapper);
  };

  const 占位WS = { readyState: WebSocket.OPEN };

  let socket;
  try {
    socket = await forwardataTCP(
      首包.hostname,
      首包.port,
      首包.rawData,
      占位WS,
      首包.respHeader,
      remoteConnWrapper,
      yourUUID,
      request,
      反代上下文,
      首包.协议 === 'trojan',
      首包.原始数据,
      true,
    );
  } catch (err) {
    log(`[叉HTTP-Pipe] 连接失败: ${err?.message || err}`);
    清理(err);
    return new Response('bad gateway', { status: 502 });
  }
  if (!socket) {
    清理(new Error('socket is null'));
    return new Response('bad gateway', { status: 502 });
  }

  const 上行Promise = (async () => {
    const 上行合包器 = 创建上行Grain合包流();
    const 搬运Promise = 上行合包器.readable.pipeTo(socket.writable, { signal: abortController.signal });
    void 搬运Promise.catch(清理);
    const 上行reader = request.body.getReader();
    const 取消上行reader = () => {
      try {
        上行reader.cancel(abortController.signal.reason).catch(() => {});
      } catch (e) {}
    };
    abortController.signal.addEventListener('abort', 取消上行reader, { once: true });
    try {
      try {
        while (true) {
          const { done, value } = await 上行reader.read();
          if (done) break;
          if (value?.byteLength) await 上行合包器.写入(value);
        }
      } finally {
        abortController.signal.removeEventListener('abort', 取消上行reader);
        try {
          上行reader.releaseLock();
        } catch (e) {}
      }
    } finally {
      try {
        await 上行合包器.结束();
      } catch (e) {}
    }
    await 搬运Promise;
  })();

  const 响应流 = typeof IdentityTransformStream !== 'undefined' ? new IdentityTransformStream() : new TransformStream();
  const 下行Promise = (async () => {
    const writer = 响应流.writable.getWriter();
    try {
      if (有效数据长度(首包.respHeader) > 0) await writer.write(首包.respHeader);
    } catch (error) {
      try {
        await writer.abort(error);
      } catch (e) {}
      throw error;
    } finally {
      try {
        writer.releaseLock();
      } catch (e) {}
    }
    await socket.readable.pipeTo(响应流.writable, { signal: abortController.signal });
  })();

  void 上行Promise.catch(清理);
  void 下行Promise.then(() => 清理(), 清理);
  void Promise.allSettled([上行Promise, 下行Promise]);

  return new Response(响应流.readable, { status: 200, headers: responseHeaders });
}

export function 处理叉HTTPUDP请求(首包, reader, request, 反代上下文, responseHeaders) {
  const 木马UDP上下文 = { 缓存: new Uint8Array(0), 反代地址: 反代上下文.木马反代地址 };
  return new Response(
    new ReadableStream({
      async start(controller) {
        let 已关闭 = false;
        let udpRespHeader = 首包.respHeader;
        const 叉桥 = {
          readyState: WebSocket.OPEN,
          send(data) {
            if (已关闭) return;
            try {
              const chunk =
                data instanceof Uint8Array
                  ? data
                  : data instanceof ArrayBuffer
                    ? new Uint8Array(data)
                    : ArrayBuffer.isView(data)
                      ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
                      : new Uint8Array(data);
              controller.enqueue(chunk);
            } catch (e) {
              已关闭 = true;
              this.readyState = WebSocket.CLOSED;
            }
          },
          close() {
            if (已关闭) return;
            已关闭 = true;
            this.readyState = WebSocket.CLOSED;
            try {
              controller.close();
            } catch (e) {}
          },
        };
        let 转发失败 = false;
        try {
          if (首包.协议 === 'trojan') {
            木马UDP上下文.目标主机 = 首包.hostname;
            木马UDP上下文.目标端口 = 首包.port;
            if (木马UDP上下文.反代地址) await 转发木马UDP数据(首包.原始数据, 叉桥, 木马UDP上下文, request);
          }
          if (!(首包.协议 === 'trojan' && 木马UDP上下文.反代地址) && 首包.rawData?.byteLength) {
            if (首包.协议 === 'trojan') await 转发木马UDP数据(首包.rawData, 叉桥, 木马UDP上下文, request);
            else await forwardataudp(首包.rawData, 叉桥, udpRespHeader, request);
            udpRespHeader = null;
          }
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!value || value.byteLength === 0) continue;
            if (首包.协议 === 'trojan') await 转发木马UDP数据(value, 叉桥, 木马UDP上下文, request);
            else await forwardataudp(value, 叉桥, udpRespHeader, request);
            udpRespHeader = null;
          }
        } catch (err) {
          转发失败 = true;
          log(`[叉HTTP转发] 处理失败: ${err?.message || err}`);
          closeSocketQuietly(叉桥);
        } finally {
          const 保持木马UDP反代下行 =
            !转发失败 && 首包.协议 === 'trojan' && 木马UDP上下文.反代地址 && 木马UDP上下文.反代Socket;
          if (!保持木马UDP反代下行) {
            try {
              木马UDP上下文.反代Socket?.close();
            } catch (e) {}
            closeSocketQuietly(叉桥);
          }
          try {
            reader.releaseLock();
          } catch (e) {}
        }
      },
      cancel() {
        try {
          木马UDP上下文.反代Socket?.close();
        } catch (e) {}
        try {
          reader.releaseLock();
        } catch (e) {}
      },
    }),
    { status: 200, headers: responseHeaders },
  );
}
