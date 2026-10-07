import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { connect } from 'cloudflare:sockets';
import { httpConnect, socks5Connect } from '../proxy-connect.js';
import { forwardataTCP } from '../tunnel.js';
import { 转发木马UDP数据 } from '../trojan-udp.js';
import { DoH查询, DoH缓存, 解析地址端口 } from '../dns.js';
import { turnConnect } from '../proxy-turn.js';
import { sstpConnect } from '../proxy-sstp.js';
import { 提取木马反代握手数据, 解析木马反代地址 } from '../trojan-fallback.js';
import { createTurnStunMessage, createTurnStunAttribute, TURN_STUN_TYPE, TURN_STUN_ATTR } from '../turn-protocol.js';
import { UUID, bytes, socket, webSocket } from './fixtures/helpers.js';

beforeEach(() => {
  vi.stubGlobal('WebSocket', { OPEN: 1, CLOSING: 2 });
  vi.stubGlobal('fetch', vi.fn());
  connect.mockReset();
  for (const key of Object.keys(DoH缓存)) delete DoH缓存[key];
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('代理握手与 TCP 重试', () => {
  it('HTTP CONNECT 不丢弃同包下行数据，且不会等待消费者才返回', async () => {
    const writes = [],
      remote = socket([bytes('HTTP/1.1 200 OK\r\n\r\nfirst'), bytes('second')], async (data) => writes.push(data));
    const connector = vi.fn(() => remote);
    const opened = await httpConnect('target.example', 443, bytes('upload'), false, connector, {
      hostname: 'proxy.example',
      port: 8080,
    });
    expect(await new Response(opened.readable).text()).toBe('firstsecond');
    expect(new TextDecoder().decode(writes[0])).toContain('CONNECT target.example:443');
    expect(new TextDecoder().decode(writes[1])).toBe('upload');
    expect(remote.writable.locked).toBe(false);
  });

  it('CONNECT 首包写失败释放 writer 并关闭 socket', async () => {
    let writes = 0;
    const remote = socket([bytes('HTTP/1.1 200 OK\r\n\r\n')], async () => {
      if (++writes === 2) throw new Error('write failed');
    });
    await expect(
      httpConnect('target.example', 443, bytes('upload'), false, () => remote, {
        hostname: 'proxy.example',
        port: 8080,
      }),
    ).rejects.toThrow('write failed');
    expect(remote.writable.locked).toBe(false);
    expect(remote.close).toHaveBeenCalled();
  });

  it('SOCKS5 鉴权失败关闭 socket 并释放读写锁', async () => {
    const remote = socket([new Uint8Array([5, 2]), new Uint8Array([1, 1])]);
    await expect(
      socks5Connect('target.example', 443, null, () => remote, {
        hostname: 'proxy.example',
        port: 1080,
        username: 'a',
        password: 'b',
      }),
    ).rejects.toThrow('authentication failed');
    expect(remote.close).toHaveBeenCalled();
    expect(remote.readable.locked).toBe(false);
    expect(remote.writable.locked).toBe(false);
  });

  it('并发拨号选中首个连接，关闭其他成功连接且只写一次首包', async () => {
    const writes = [];
    const first = socket([], async (data) => writes.push([...data]), { keepOpen: true });
    const second = socket(
      [],
      async () => {
        throw new Error('loser must not receive data');
      },
      { keepOpen: true },
    );
    connect.mockReturnValueOnce(first).mockReturnValueOnce(second);
    const wrapper = { socket: null };
    const result = await forwardataTCP(
      'target.example',
      443,
      new Uint8Array([1, 2]),
      webSocket(),
      null,
      wrapper,
      UUID,
      {},
      { TCP并发拨号数: 2 },
      false,
      null,
      true,
    );
    expect(result).toBe(first);
    await vi.waitFor(() => expect(second.close).toHaveBeenCalledTimes(1));
    expect(writes).toEqual([[1, 2]]);
    first.close();
  });

  it('直连失败切换指定反代，连接配置来自本次请求', async () => {
    connect.mockImplementationOnce(() => {
      throw new Error('direct failure');
    });
    const proxy = socket([], async () => {}, { keepOpen: true });
    connect.mockReturnValue(proxy);
    const wrapper = { socket: null };
    const result = await forwardataTCP(
      'target.example',
      443,
      bytes('first'),
      webSocket(),
      null,
      wrapper,
      UUID,
      {},
      { TCP并发拨号数: 1, 反代IP: '192.0.2.1:443', 反代兜底: false, 代理类型: null },
      false,
      null,
      true,
    );
    expect(result).toBe(proxy);
    expect(connect.mock.calls[1][0]).toEqual({ hostname: '192.0.2.1', port: 443 });
    proxy.close();
  });
});

function dnsAnswer(type, payload) {
  const header = [0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0];
  return new Uint8Array([
    ...header,
    0xc0,
    0x0c,
    0,
    type,
    0,
    1,
    0,
    0,
    0,
    60,
    payload.length >> 8,
    payload.length & 255,
    ...payload,
  ]);
}

describe('DoH 缓存和反代解析', () => {
  it('域名大小写归一化、TTL 到期重查，返回数据不暴露缓存对象', async () => {
    const now = vi.spyOn(Date, 'now').mockReturnValue(100000);
    fetch.mockImplementation(async () => new Response(dnsAnswer(1, [192, 0, 2, 1])));
    const original = await DoH查询('EXAMPLE.COM.', 'a');
    expect(original).toMatchObject([{ type: 1, data: '192.0.2.1' }]);
    original[0].data = 'corrupted';
    expect(await DoH查询('example.com', 'A')).toEqual([{ type: 1, data: '192.0.2.1' }]);
    expect(fetch).toHaveBeenCalledTimes(1);
    now.mockReturnValue(401000);
    await DoH查询('example.com', 'A');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('负结果短暂缓存，不混用不同 DoH 服务结果', async () => {
    fetch.mockImplementation(async () => new Response(new Uint8Array([0, 1, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0])));
    expect(await DoH查询('missing.example', 'A')).toEqual([]);
    await DoH查询('missing.example', 'A');
    expect(fetch).toHaveBeenCalledTimes(1);
    await DoH查询('missing.example', 'A', 'https://other.example/dns-query');
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('TXT 反代优先于 A，IPv4/IPv6 字面量跳过 DNS', async () => {
    const text = bytes('192.0.2.7:8443');
    fetch.mockImplementation(async (_, init) => {
      const query = new Uint8Array(init.body);
      const type = query[query.length - 3];
      return new Response(type === 16 ? dnsAnswer(16, [text.length, ...text]) : dnsAnswer(1, [192, 0, 2, 8]));
    });
    expect(await 解析地址端口('proxy.example')).toEqual([['192.0.2.7', 8443]]);
    fetch.mockClear();
    expect(await 解析地址端口('192.0.2.1:443,[2001:db8::1]:8443')).toHaveLength(2);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('Trojan UDP 与 TURN', () => {
  it('Trojan fallback 保留握手、分离已发送首包，支持 IPv6 地址', () => {
    expect(提取木马反代握手数据(new Uint8Array([1, 2, 3, 4]), new Uint8Array([3, 4]))).toEqual(new Uint8Array([1, 2]));
    expect(解析木马反代地址('[2001:db8::1]:1234')).toEqual({ hostname: '[2001:db8::1]', port: 1234 });
    expect(() => 解析木马反代地址('proxy.example:0')).toThrow();
  });

  it('SSTP 使用 TLS 连接，HTTP 握手失败后释放资源', async () => {
    const writes = [],
      remote = socket([bytes('HTTP/1.1 503 Unavailable\r\n\r\n')], async (data) => writes.push(data));
    const connector = vi.fn(() => remote);
    await expect(sstpConnect({ hostname: 'sstp.example', port: 443 }, '192.0.2.1', 443, connector)).rejects.toThrow(
      'SSTP HTTP handshake failed',
    );
    expect(connector.mock.calls[0][1]).toEqual({ secureTransport: 'on', allowHalfOpen: false });
    expect(new TextDecoder().decode(writes[0])).toContain('SSTP_DUPLEX_POST');
    expect(remote.close).toHaveBeenCalled();
    expect(remote.writable.locked).toBe(false);
    expect(remote.readable.locked).toBe(false);
  });

  it('分片 Trojan UDP DNS 请求完整组装并保留返回帧格式', async () => {
    const writes = [],
      ws = webSocket();
    const remote = socket([new Uint8Array([0, 2, 8, 9])], async (data) => writes.push([...data]));
    connect.mockReturnValue(remote);
    const frame = new Uint8Array([1, 8, 8, 8, 8, 0, 53, 0, 2, 13, 10, 5, 6]);
    const ctx = { 缓存: new Uint8Array() };
    await 转发木马UDP数据(frame.slice(0, 8), ws, ctx, {});
    expect(connect).not.toHaveBeenCalled();
    await 转发木马UDP数据(frame.slice(8), ws, ctx, {});
    expect(writes).toEqual([[0, 2, 5, 6]]);
    expect([...new Uint8Array(ws.send.mock.calls[0][0])]).toEqual([1, 8, 8, 8, 8, 0, 53, 0, 2, 13, 10, 8, 9]);
    expect(ctx.缓存).toHaveLength(0);
  });

  it('没有 fallback 的非 DNS UDP 请求明确拒绝', async () => {
    const frame = new Uint8Array([1, 8, 8, 8, 8, 1, 187, 0, 1, 13, 10, 5]);
    await expect(转发木马UDP数据(frame, webSocket(), { 缓存: new Uint8Array() }, {})).rejects.toThrow(
      'UDP is not supported',
    );
  });

  it('TURN 允许空 REALM，继续发出鉴权 Allocate；后续失败清理连接', async () => {
    const attrs = [
      createTurnStunAttribute(TURN_STUN_ATTR.ERROR_CODE, new Uint8Array([0, 0, 4, 1])),
      createTurnStunAttribute(TURN_STUN_ATTR.REALM, new Uint8Array()),
      createTurnStunAttribute(TURN_STUN_ATTR.NONCE, bytes('nonce')),
    ];
    const error = createTurnStunMessage(TURN_STUN_TYPE.ALLOCATE_ERROR, new Uint8Array(12), attrs);
    const writes = [],
      remote = socket([error], async (data) => writes.push(data));
    await expect(
      turnConnect(
        { hostname: 'turn.example', port: 3478, username: 'a', password: 'b' },
        '192.0.2.1',
        443,
        () => remote,
      ),
    ).rejects.not.toThrow('missing realm');
    expect(writes).toHaveLength(2);
    expect(remote.close).toHaveBeenCalled();
    expect(remote.readable.locked).toBe(false);
  });
});
