import {
  SS支持加密配置,
  SS派生主密钥,
  SSNonce长度,
  SSAEAD标签长度,
  SS派生会话密钥,
  SSAEAD解密,
  SSAEAD加密,
} from './shadowsocks.js';
import { 数据转Uint8Array, 拼接字节数据 } from './utils/bytes.js';
import { WebSocket发送并等待, closeSocketQuietly } from './utils/socket.js';
export function 创建SS上下文获取器(url, yourUUID, serverSock, log) {
  let ss上下文 = null,
    ss初始化任务 = null;
  return async () => {
    if (ss上下文) return ss上下文;
    if (!ss初始化任务) {
      ss初始化任务 = (async () => {
        const 请求加密方式 = (url.searchParams.get('enc') || '').toLowerCase();
        const 首选加密配置 = SS支持加密配置[请求加密方式] || SS支持加密配置['aes-128-gcm'];
        const 入站候选加密配置 = [
          首选加密配置,
          ...Object.values(SS支持加密配置).filter((c) => c.method !== 首选加密配置.method),
        ];
        const 入站主密钥任务缓存 = new Map();
        const 取入站主密钥任务 = (config) => {
          if (!入站主密钥任务缓存.has(config.method))
            入站主密钥任务缓存.set(config.method, SS派生主密钥(yourUUID, config.keyLen));
          return 入站主密钥任务缓存.get(config.method);
        };
        const 入站状态 = {
          buffer: new Uint8Array(0),
          hasSalt: false,
          waitPayloadLength: null,
          decryptKey: null,
          nonceCounter: new Uint8Array(SSNonce长度),
          加密配置: null,
        };
        const 初始化入站解密状态 = async () => {
          const lengthCipherTotalLength = 2 + SSAEAD标签长度;
          const 最大盐长度 = Math.max(...入站候选加密配置.map((c) => c.saltLen));
          const 最大对齐扫描字节 = 16;
          const 可扫描最大偏移 = Math.min(
            最大对齐扫描字节,
            Math.max(
              0,
              入站状态.buffer.byteLength -
                (lengthCipherTotalLength + Math.min(...入站候选加密配置.map((c) => c.saltLen))),
            ),
          );
          for (let offset = 0; offset <= 可扫描最大偏移; offset++) {
            for (const 加密配置 of 入站候选加密配置) {
              const 初始化最小长度 = offset + 加密配置.saltLen + lengthCipherTotalLength;
              if (入站状态.buffer.byteLength < 初始化最小长度) continue;
              const salt = 入站状态.buffer.subarray(offset, offset + 加密配置.saltLen);
              const lengthCipher = 入站状态.buffer.subarray(offset + 加密配置.saltLen, 初始化最小长度);
              const masterKey = await 取入站主密钥任务(加密配置);
              const decryptKey = await SS派生会话密钥(加密配置, masterKey, salt, ['decrypt']);
              const nonceCounter = new Uint8Array(SSNonce长度);
              try {
                const lengthPlain = await SSAEAD解密(decryptKey, nonceCounter, lengthCipher);
                if (lengthPlain.byteLength !== 2) continue;
                const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
                if (payloadLength < 0 || payloadLength > 加密配置.maxChunk) continue;
                if (offset > 0) log(`[SS入站] 检测到前导噪声 ${offset}B，已自动对齐`);
                if (加密配置.method !== 首选加密配置.method)
                  log(
                    `[SS入站] URL enc=${请求加密方式 || 首选加密配置.method} 与实际 ${加密配置.method} 不一致，已自动切换`,
                  );
                入站状态.buffer = 入站状态.buffer.subarray(初始化最小长度);
                入站状态.decryptKey = decryptKey;
                入站状态.nonceCounter = nonceCounter;
                入站状态.waitPayloadLength = payloadLength;
                入站状态.加密配置 = 加密配置;
                入站状态.hasSalt = true;
                return true;
              } catch (_) {}
            }
          }
          const 初始化失败判定长度 = 最大盐长度 + lengthCipherTotalLength + 最大对齐扫描字节;
          if (入站状态.buffer.byteLength >= 初始化失败判定长度) {
            throw new Error(
              `SS handshake decrypt failed (enc=${请求加密方式 || 'auto'}, candidates=${入站候选加密配置.map((c) => c.method).join('/')})`,
            );
          }
          return false;
        };
        const 入站解密器 = {
          async 输入(dataChunk) {
            const chunk = 数据转Uint8Array(dataChunk);
            if (chunk.byteLength > 0) 入站状态.buffer = 拼接字节数据(入站状态.buffer, chunk);
            if (!入站状态.hasSalt) {
              const 初始化成功 = await 初始化入站解密状态();
              if (!初始化成功) return [];
            }
            const plaintextChunks = [];
            while (true) {
              if (入站状态.waitPayloadLength === null) {
                const lengthCipherTotalLength = 2 + SSAEAD标签长度;
                if (入站状态.buffer.byteLength < lengthCipherTotalLength) break;
                const lengthCipher = 入站状态.buffer.subarray(0, lengthCipherTotalLength);
                入站状态.buffer = 入站状态.buffer.subarray(lengthCipherTotalLength);
                const lengthPlain = await SSAEAD解密(入站状态.decryptKey, 入站状态.nonceCounter, lengthCipher);
                if (lengthPlain.byteLength !== 2) throw new Error('SS length decrypt failed');
                const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
                if (payloadLength < 0 || payloadLength > 入站状态.加密配置.maxChunk)
                  throw new Error(`SS payload length invalid: ${payloadLength}`);
                入站状态.waitPayloadLength = payloadLength;
              }
              const payloadCipherTotalLength = 入站状态.waitPayloadLength + SSAEAD标签长度;
              if (入站状态.buffer.byteLength < payloadCipherTotalLength) break;
              const payloadCipher = 入站状态.buffer.subarray(0, payloadCipherTotalLength);
              入站状态.buffer = 入站状态.buffer.subarray(payloadCipherTotalLength);
              const payloadPlain = await SSAEAD解密(入站状态.decryptKey, 入站状态.nonceCounter, payloadCipher);
              plaintextChunks.push(payloadPlain);
              入站状态.waitPayloadLength = null;
            }
            return plaintextChunks;
          },
        };
        let 出站加密器 = null;
        const SS单批最大字节 = 32 * 1024;
        const 获取出站加密器 = async () => {
          if (出站加密器) return 出站加密器;
          if (!入站状态.加密配置) throw new Error('SS cipher is not negotiated');
          const 出站加密配置 = 入站状态.加密配置;
          const 出站主密钥 = await SS派生主密钥(yourUUID, 出站加密配置.keyLen);
          const 出站随机字节 = crypto.getRandomValues(new Uint8Array(出站加密配置.saltLen));
          const 出站加密密钥 = await SS派生会话密钥(出站加密配置, 出站主密钥, 出站随机字节, ['encrypt']);
          const 出站Nonce计数器 = new Uint8Array(SSNonce长度);
          let 随机字节已发送 = false;
          出站加密器 = {
            async 加密并发送(dataChunk, sendChunk) {
              const plaintextData = 数据转Uint8Array(dataChunk);
              if (!随机字节已发送) {
                await sendChunk(出站随机字节);
                随机字节已发送 = true;
              }
              if (plaintextData.byteLength === 0) return;
              let offset = 0;
              while (offset < plaintextData.byteLength) {
                const end = Math.min(offset + 出站加密配置.maxChunk, plaintextData.byteLength);
                const payloadPlain = plaintextData.subarray(offset, end);
                const lengthPlain = new Uint8Array(2);
                lengthPlain[0] = (payloadPlain.byteLength >>> 8) & 0xff;
                lengthPlain[1] = payloadPlain.byteLength & 0xff;
                const lengthCipher = await SSAEAD加密(出站加密密钥, 出站Nonce计数器, lengthPlain);
                const payloadCipher = await SSAEAD加密(出站加密密钥, 出站Nonce计数器, payloadPlain);
                const frame = new Uint8Array(lengthCipher.byteLength + payloadCipher.byteLength);
                frame.set(lengthCipher, 0);
                frame.set(payloadCipher, lengthCipher.byteLength);
                await sendChunk(frame);
                offset = end;
              }
            },
          };
          return 出站加密器;
        };
        let SS发送队列 = Promise.resolve();
        const SS入队发送 = (chunk) => {
          SS发送队列 = SS发送队列.then(async () => {
            if (serverSock.readyState !== WebSocket.OPEN) return;
            const 已初始化出站加密器 = await 获取出站加密器();
            await 已初始化出站加密器.加密并发送(chunk, async (encryptedChunk) => {
              if (encryptedChunk.byteLength > 0 && serverSock.readyState === WebSocket.OPEN) {
                await WebSocket发送并等待(serverSock, encryptedChunk.buffer);
              }
            });
          }).catch((error) => {
            log(`[SS发送] 加密失败: ${error?.message || error}`);
            closeSocketQuietly(serverSock);
          });
          return SS发送队列;
        };
        const 回包Socket = {
          get readyState() {
            return serverSock.readyState;
          },
          send(data) {
            const chunk = 数据转Uint8Array(data);
            if (chunk.byteLength <= SS单批最大字节) {
              return SS入队发送(chunk);
            }
            for (let i = 0; i < chunk.byteLength; i += SS单批最大字节) {
              SS入队发送(chunk.subarray(i, Math.min(i + SS单批最大字节, chunk.byteLength)));
            }
            return SS发送队列;
          },
          close() {
            closeSocketQuietly(serverSock);
          },
        };
        ss上下文 = {
          入站解密器,
          回包Socket,
          首包已建立: false,
          目标主机: '',
          目标端口: 0,
        };
        return ss上下文;
      })().finally(() => {
        ss初始化任务 = null;
      });
    }
    return ss初始化任务;
  };
}
