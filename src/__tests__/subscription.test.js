import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { 读取config_JSON } from '../config.js';
import { handleSubscription } from '../subscription/index.js';
import { 获取优选订阅生成器数据, 请求优选API } from '../best-ip.js';
import { MD5MD5 } from '../utils/crypto.js';
import { base64SecretEncode } from '../utils/secret.js';
import { 汇聚订阅_UA } from '../state.js';
import { UUID, HOST, UA, memoryKV, context, request } from './fixtures/helpers.js';

const saved = {
  PATH: '/custom',
  ALPN: 'h2,http/1.1',
  优选订阅生成: { local: true, SUBNAME: '我的节点', 本地IP库: { 随机IP: false } },
  订阅转换配置: { SUBAPI: 'https://converter.example', EXPAND: false, UDP: true },
  反代: { 路径模板: { HTTP: { 标准: 'http={{IP:PORT}}', 全局: 'http://{{IP:PORT}}' } } },
};
function env(config = saved, cf = {}) {
  return {
    KV: memoryKV({
      'config.json': JSON.stringify(config),
      'ADD.txt': '104.16.0.1:443#测试',
      'cf.json': JSON.stringify(cf),
    }),
  };
}
async function token() {
  return MD5MD5(HOST + UUID);
}
async function temporaryToken(offset = 0) {
  return MD5MD5(base64SecretEncode(await token(), UUID) + (Math.floor(Date.now() / 86400000) + offset));
}
async function subscribe(path, options = {}, environment = env(), cf = {}) {
  const req = request(path, options, cf);
  return handleSubscription(
    req,
    new URL(req.url),
    environment,
    UUID,
    HOST,
    req.headers.get('User-Agent'),
    '127.0.0.1',
    context(),
  );
}

beforeEach(() => {
  vi.spyOn(Date, 'now').mockReturnValue(Date.UTC(2026, 9, 7, 10));
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

describe('旧 KV 配置兼容', () => {
  it('补齐嵌套缺失项并保留用户设置，不回写旧 config.json', async () => {
    const environment = env();
    const config = await 读取config_JSON(environment, HOST, UUID);
    expect(config.ALPN).toBe(saved.ALPN);
    expect(config.PATH).toBe('/custom');
    expect(config.订阅转换配置).toMatchObject({
      UDP: true,
      EXPAND: false,
      XUDP: false,
      SUBLIST: false,
      SORT: false,
      TLS13: false,
      APPEND_TYPE: false,
    });
    expect(config.反代.路径模板).toHaveProperty('HTTPS');
    expect(config.反代.路径模板).toHaveProperty('TURN');
    expect(config.反代.路径模板).toHaveProperty('SSTP');
    expect(config.LINK).toContain('alpn=h2%2Chttp%2F1.1');
    expect(environment.KV.put.mock.calls.some(([key]) => key === 'config.json')).toBe(false);
  });

  it('并发读配置不会覆盖另一请求的域名或 UUID', async () => {
    const first = env(),
      second = env({ ...saved, PATH: '/other' });
    let release;
    first.KV.get.mockImplementation(async (key) => {
      if (key === 'tg.json')
        await new Promise((resolve) => {
          release = resolve;
        });
      return first.KV.data.get(key) ?? null;
    });
    const pending = 读取config_JSON(first, HOST, UUID);
    await vi.waitFor(() => expect(release).toBeTypeOf('function'));
    const other = await 读取config_JSON(second, 'other.example', '22345678-1234-4123-8123-123456789abc');
    release();
    const original = await pending;
    expect(original.HOST).toBe(HOST);
    expect(original.UUID).toBe(UUID);
    expect(original.PATH).toBe('/custom');
    expect(other.HOST).toBe('other.example');
    expect(other.PATH).toBe('/other');
  });

  it('不调用已移除的 Cloudflare 凭证查询', async () => {
    const config = await 读取config_JSON(
      env(saved, { AccountID: 'test-account', APIToken: 'test-api-token' }),
      HOST,
      UUID,
    );
    expect(config.CF.Usage).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('订阅凭证与节点输出', () => {
  it('永久 TOKEN 正常生成真实节点，Usage 为 null 不崩溃', async () => {
    const response = await subscribe(`/sub?token=${await token()}`);
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain(UUID);
    expect(text).toContain(HOST);
    expect(text).toContain('alpn=h2%2Chttp%2F1.1');
    expect(text).not.toContain('allowInsecure');
    expect(response.headers.has('Subscription-Userinfo')).toBe(false);
  });

  it.each([0, -1])('接受第 %i 天的转换 TOKEN，响应保持占位凭证', async (offset) => {
    const response = await subscribe(`/sub?target=mixed&token=${await temporaryToken(offset)}`, {
      headers: { 'User-Agent': 'Subconverter' },
    });
    const text = atob(await response.text());
    expect(text).toContain('00000000-0000-4000-8000-000000000000');
    expect(text).toContain('example.com');
    expect(text).not.toContain(UUID);
    expect(text).not.toContain(HOST);
  });

  it.each([-2, 1])('拒绝过期和未来临时 TOKEN（%i 天）', async (offset) => {
    expect(await subscribe(`/sub?token=${await temporaryToken(offset)}`)).toBeUndefined();
  });

  it('转换请求发送临时 TOKEN、运营商和新增选项，不泄露永久 TOKEN', async () => {
    fetch.mockResolvedValue(new Response('proxies: []'));
    const permanent = await token();
    const response = await subscribe(`/sub?target=clash&token=${permanent}`, {}, env(), { country: 'CN', asn: 9808 });
    expect(response.status).toBe(200);
    const url = new URL(fetch.mock.calls[0][0]);
    const source = new URL(url.searchParams.get('url'));
    expect(source.searchParams.get('token')).toBe(await temporaryToken());
    expect(source.searchParams.get('token')).not.toBe(permanent);
    expect(source.searchParams.get('cnIspCode')).toBe('cmcc');
    expect(url.searchParams.get('udp')).toBe('true');
    expect(url.searchParams.get('expand')).toBe('false');
    expect(url.searchParams.get('tls13')).toBe('false');
  });

  it('转换失败对外不返回内部异常', async () => {
    const response = await subscribe(`/sub?target=clash&token=${await token()}`);
    expect(response.status).toBe(403);
    expect(await response.text()).toBe('订阅转换后端异常：');
  });

  it.each(['gun', 'multi'])('gRPC %s 模式使用 authority/serviceName 且剔除查询串', async (mode) => {
    const config = { ...saved, PATH: '/grpc?ed=2560', 传输协议: 'grpc', gRPC模式: mode };
    const response = await subscribe(`/sub?token=${await token()}`, {}, env(config));
    const text = await response.text();
    expect(text).toContain(`type=grpc&mode=${mode}`);
    expect(text).toContain(`authority=${HOST}`);
    expect(text).toContain('serviceName=%2Fgrpc');
  });

  it('Shadowsocks 无 TLS 映射优选端口', async () => {
    const environment = env({ ...saved, 协议类型: 'ss', SS: { 加密方式: 'aes-128-gcm', TLS: false } });
    environment.KV.data.set('ADD.txt', '104.16.0.1:8443#测试');
    const response = await subscribe(`/sub?token=${await token()}`, {}, environment);
    expect(await response.text()).toContain('@104.16.0.1:8080?plugin=');
  });

  it('汇聚订阅请求统一 User-Agent', async () => {
    fetch.mockResolvedValue(
      new Response(btoa('vless://00000000-0000-4000-8000-000000000000@104.16.0.1:443?host=example.com#test')),
    );
    await 获取优选订阅生成器数据('sub://upstream.example');
    expect(fetch.mock.calls[0][1].headers['User-Agent']).toBe(汇聚订阅_UA);
    fetch.mockClear();
    fetch.mockResolvedValue(new Response('104.16.0.1:443#test'));
    await 请求优选API(['https://addresses.example']);
    expect(fetch.mock.calls[0][1].headers['User-Agent']).toBe(汇聚订阅_UA);
  });
});
