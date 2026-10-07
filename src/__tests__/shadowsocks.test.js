import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { 创建SS上下文获取器 } from '../ws-shadowsocks.js';
import { SS支持加密配置, SS派生主密钥, SS派生会话密钥, SSAEAD加密, SSAEAD解密 } from '../shadowsocks.js';
import { 拼接字节数据 } from '../utils/bytes.js';
import { UUID, webSocket } from './fixtures/helpers.js';

beforeEach(() => {
  vi.stubGlobal('WebSocket', { OPEN: 1, CLOSING: 2 });
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Shadowsocks AEAD 分片与协商', () => {
  it.each(['aes-128-gcm', 'aes-256-gcm'])('%s 首包可分片接收，URL enc 不匹配时自动协商实际算法', async (method) => {
    const config = SS支持加密配置[method],
      salt = new Uint8Array(config.saltLen).fill(4);
    const master = await SS派生主密钥(UUID, config.keyLen);
    const key = await SS派生会话密钥(config, master, salt, ['encrypt']);
    const plaintext = new TextEncoder().encode('payload');
    const nonce = new Uint8Array(12);
    const encrypted = 拼接字节数据(
      salt,
      await SSAEAD加密(key, nonce, new Uint8Array([0, plaintext.length])),
      await SSAEAD加密(key, nonce, plaintext),
    );
    const ws = webSocket();
    const preferred = method === 'aes-128-gcm' ? 'aes-256-gcm' : 'aes-128-gcm';
    const getContext = 创建SS上下文获取器(new URL(`https://worker.example/?enc=${preferred}`), UUID, ws, () => {});
    const context = await getContext();
    expect(await getContext()).toBe(context);
    expect(await context.入站解密器.输入(encrypted.slice(0, 8))).toEqual([]);
    expect(await context.入站解密器.输入(encrypted.slice(8))).toEqual([plaintext]);
    const response = new Uint8Array(33000).fill(7);
    await context.回包Socket.send(response);
    const returned = 拼接字节数据(...ws.send.mock.calls.map(([data]) => new Uint8Array(data)));
    const responseSalt = returned.slice(0, config.saltLen);
    const decryptKey = await SS派生会话密钥(config, master, responseSalt, ['decrypt']);
    const responseNonce = new Uint8Array(12),
      decoded = [];
    let offset = config.saltLen;
    while (offset < returned.length) {
      const length = await SSAEAD解密(decryptKey, responseNonce, returned.slice(offset, offset + 18));
      offset += 18;
      const size = (length[0] << 8) | length[1];
      decoded.push(await SSAEAD解密(decryptKey, responseNonce, returned.slice(offset, offset + size + 16)));
      offset += size + 16;
    }
    expect(拼接字节数据(...decoded)).toEqual(response);
  });
});
