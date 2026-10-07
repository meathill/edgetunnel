import { WebSocket发送并等待 } from './utils/socket.js';
import { 构造WS本地204响应 } from './speed-test.js';
import { 数据转Uint8Array, 拼接字节数据, 有效数据长度 } from './utils/bytes.js';
import { 魏烈思文本解码器 } from './protocol.js';
export function 创建WS本地测速会话() {
  let WS本地测速模式 = false,
    WS本地测速回包Socket = null;
  let WS本地测速请求缓存 = new Uint8Array(0);
  let WS本地测速首包响应头 = null;
  const WS本地测速请求上限 = 64 * 1024;
  const 发送WS本地测速响应 = async () => {
    if (!WS本地测速回包Socket) return;
    const respHeader = WS本地测速首包响应头;
    WS本地测速首包响应头 = null;
    await WebSocket发送并等待(WS本地测速回包Socket, 构造WS本地204响应(respHeader));
  };
  const 查找HTTP请求头结尾 = (data) => {
    for (let i = 0; i <= data.byteLength - 4; i++) {
      if (data[i] === 0x0d && data[i + 1] === 0x0a && data[i + 2] === 0x0d && data[i + 3] === 0x0a) return i + 4;
    }
    return -1;
  };
  const 处理WS本地测速数据 = async (data) => {
    const chunk = 数据转Uint8Array(data);
    if (!chunk.byteLength) return;
    if (WS本地测速请求缓存.byteLength + chunk.byteLength > WS本地测速请求上限)
      throw new Error('WS local speed-test request is too large');
    WS本地测速请求缓存 = 拼接字节数据(WS本地测速请求缓存, chunk);

    while (WS本地测速请求缓存.byteLength) {
      const headerEnd = 查找HTTP请求头结尾(WS本地测速请求缓存);
      if (headerEnd === -1) return;
      const headerText = 魏烈思文本解码器.decode(WS本地测速请求缓存.subarray(0, headerEnd));
      const contentLengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
      const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : 0;
      const requestLength = headerEnd + contentLength;
      if (!Number.isSafeInteger(contentLength) || requestLength > WS本地测速请求上限)
        throw new Error('WS local speed-test request body is too large');
      if (WS本地测速请求缓存.byteLength < requestLength) return;
      WS本地测速请求缓存 = WS本地测速请求缓存.slice(requestLength);
      await 发送WS本地测速响应();
    }
  };
  const 启用WS本地测速模式 = async (回包Socket, respHeader = null, 首请求数据 = null) => {
    WS本地测速模式 = true;
    WS本地测速回包Socket = 回包Socket;
    WS本地测速请求缓存 = new Uint8Array(0);
    WS本地测速首包响应头 = respHeader;
    if (有效数据长度(首请求数据) > 0) await 处理WS本地测速数据(首请求数据);
  };
  return {
    get 已启用() {
      return WS本地测速模式;
    },
    输入: 处理WS本地测速数据,
    启用: 启用WS本地测速模式,
  };
}
