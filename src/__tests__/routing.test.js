import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import worker from '../index.js';
import { MD5MD5 } from '../utils/crypto.js';
import { 获取请求设置 } from '../state.js';
import { 反代参数获取 } from '../proxy.js';
import { base64SecretEncode } from '../utils/secret.js';
import { 获取叉HTTPPadding标识, 校验叉HTTPPadding, 计算HPACKHuffman字节长度 } from '../xhttp-padding.js';
import { 解码WS早期数据 } from '../ws-early-data.js';
import { UUID, HOST, UA, ADMIN, KEY, memoryKV, context, request, vlessPacket } from './fixtures/helpers.js';

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      throw new Error('unexpected external request');
    }),
  );
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function environment() {
  return { ADMIN, KEY, UUID, KV: memoryKV() };
}

describe('认证与路由', () => {
  it('登录成功的 Cookie 保留安全属性，管理路由验证真实 Cookie', async () => {
    const env = environment();
    const login = await worker.fetch(request('/login', { method: 'POST', body: `password=${ADMIN}` }), env, context());
    const cookie = login.headers.get('Set-Cookie');
    expect(cookie).toContain('HttpOnly; Secure; SameSite=Strict');
    expect(cookie).toContain(await MD5MD5(UA + KEY + ADMIN));
    const denied = await worker.fetch(request('/admin/config.json'), env, context());
    expect(denied.headers.get('Location')).toBe('/login');
    const allowed = await worker.fetch(request('/admin/config.json', { headers: { Cookie: cookie } }), env, context());
    expect((await allowed.json()).UUID).toBe(UUID);
  });

  it('保留密码换行兼容，管理员派生凭证不改变', async () => {
    const env = { ...environment(), ADMIN: ADMIN + '\n' };
    const response = await worker.fetch(
      request('/login', { method: 'POST', body: `password=${ADMIN}` }),
      env,
      context(),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get('Set-Cookie')).toContain(await MD5MD5(UA + KEY + env.ADMIN));
  });

  it('版本接口拒绝上游宽松校验可接受的 UUID 碰撞', async () => {
    const env = environment();
    const collision = '21345678-ffff-4fff-8fff-123456789abc';
    const accepted = await worker.fetch(request(`/version?uuid=${UUID.toUpperCase()}`), env, context());
    expect((await accepted.json()).Version).toBe(20260922200117);
    const rejected = await worker.fetch(request(`/version?uuid=${collision}`), env, context());
    expect(rejected.headers.get('Content-Type')).toContain('text/html');
  });

  it('订阅快捷路径保留 TOKEN 规则和查询参数', async () => {
    const response = await worker.fetch(request(`/${KEY}?target=clash`), environment(), context());
    const location = new URL(response.headers.get('Location'), `https://${HOST}`);
    expect(location.searchParams.get('token')).toBe(await MD5MD5(HOST + UUID));
    expect(location.searchParams.get('target')).toBe('clash');
  });

  it('已移除的用量查询不发送 URL 中的凭证', async () => {
    const cookie = await MD5MD5(UA + KEY + ADMIN);
    await worker.fetch(
      request('/admin/getCloudflareUsage?APIToken=test-secret', { headers: { Cookie: `auth=${cookie}` } }),
      environment(),
      context(),
    );
    expect(fetch.mock.calls.every(([url]) => !String(url).includes('test-secret'))).toBe(true);
  });
});

describe('请求独立设置和代理上下文', () => {
  it('中国移动默认单路，显式并发覆盖；下一请求恢复默认值', () => {
    expect(获取请求设置({}, { cf: { country: 'CN', asn: 9808 } }).TCP并发拨号数).toBe(1);
    expect(获取请求设置({ TCP_CONCURRENT_DIAL: '4' }, { cf: { country: 'CN', asn: 9808 } }).TCP并发拨号数).toBe(4);
    expect(获取请求设置()).toMatchObject({ TCP并发拨号数: 2, 反代并发拨号数: 1, 预加载竞速拨号: false });
    expect(获取请求设置({ PRELOAD_RACE_DIAL: 'true' }).预加载竞速拨号).toBe(true);
    expect(获取请求设置({ TCP_CONCURRENT_DIAL: '-1', PROXY_CONCURRENT_DIAL: 'bad' }).反代并发拨号数).toBe(1);
  });

  it('GO2SOCKS5 追加去重且不会污染下一请求', () => {
    const custom = 获取请求设置({ GO2SOCKS5: 'custom.example,custom.example' }).SOCKS5白名单;
    expect(custom).toContain('scholar.google.com');
    expect(custom.filter((x) => x === 'custom.example')).toHaveLength(1);
    expect(获取请求设置().SOCKS5白名单).not.toContain('custom.example');
  });

  it.each(['socks5', 'http', 'https', 'turn', 'sstp'])('解析 %s 代理，与其他请求隔离', async (protocol) => {
    const parsed = await 反代参数获取(
      new URL(`https://${HOST}/?${protocol}=alice:password@proxy.example:1234&globalproxy`),
      UUID,
      'fallback.example',
    );
    const other = await 反代参数获取(new URL(`https://${HOST}/?proxyip=other.example`), UUID, 'default.example');
    expect(parsed).toMatchObject({
      代理类型: protocol,
      代理全局: true,
      代理参数: { hostname: 'proxy.example', port: 1234, username: 'alice', password: 'password' },
    });
    expect(other).toMatchObject({ 代理类型: null, 反代IP: 'other.example' });
    expect(parsed.代理参数.hostname).toBe('proxy.example');
  });

  it('链式代理路径允许结尾斜杠', async () => {
    const encoded = base64SecretEncode(JSON.stringify({ type: 'turn', hostname: 'proxy.example', port: 3478 }), UUID);
    const parsed = await 反代参数获取(new URL(`https://${HOST}/video/${encoded}/`), UUID);
    expect(parsed).toMatchObject({
      代理类型: 'turn',
      代理全局: true,
      代理参数: { hostname: 'proxy.example', port: 3478 },
    });
  });
});

describe('WS early data 与 XHTTP padding', () => {
  it('只将有效协议首包作为 early data，拒绝超大头', () => {
    const packet = vlessPacket();
    const encoded = btoa(String.fromCharCode(...packet))
      .replaceAll('+', '-')
      .replaceAll('/', '_');
    expect(解码WS早期数据(encoded, UUID)).toEqual(packet);
    expect(解码WS早期数据('chat', UUID)).toBeNull();
    expect(() => 解码WS早期数据('a'.repeat(12000), UUID)).toThrow('too large');
  });

  it('padding 同时支持 header 和 query，边界按 HPACK 长度判定', () => {
    const { 头, 键 } = 获取叉HTTPPadding标识(UUID);
    const valid = 'a'.repeat(200);
    expect(计算HPACKHuffman字节长度(valid)).toBe(125);
    expect(校验叉HTTPPadding(request(`/?${键}=${valid}`), 头, 键)).toBe(true);
    expect(校验叉HTTPPadding(request('/', { headers: { [头]: `https://x.invalid/?${键}=${valid}` } }), 头, 键)).toBe(
      true,
    );
    expect(校验叉HTTPPadding(request(`/?${键}=tiny`), 头, 键)).toBe(false);
    expect(校验叉HTTPPadding(request(`/?${键}=${'a'.repeat(1700)}`), 头, 键)).toBe(false);
  });
});
