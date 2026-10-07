import { describe, expect, it } from 'vitest';
import { Singbox订阅配置文件热补丁 } from '../subscription/singbox.js';
import { Clash订阅配置文件热补丁 } from '../subscription/clash.js';
import { Surge订阅配置文件热补丁 } from '../subscription/surge.js';
import { UUID } from './fixtures/helpers.js';

describe('客户端配置兼容', () => {
  it('Sing-box 迁移旧 DNS、TUN 和地理规则，保留自定义设置', async () => {
    const source = {
      inbounds: [{ type: 'tun', tag: 'tun-in', inet4_address: '172.19.0.1/30', sniff: true }],
      outbounds: [{ type: 'vless', tag: 'my-proxy', uuid: UUID }],
      route: { rules: [{ geosite: ['cn'], outbound: 'DIRECT' }] },
      dns: {
        servers: [{ tag: 'local', address: 'https://dns.example/custom-dns' }],
        rules: [{ outbound: 'any', server: 'local' }],
      },
    };
    const result = JSON.parse(
      await Singbox订阅配置文件热补丁(JSON.stringify(source), {
        UUID,
        Fingerprint: 'firefox',
        ECH: true,
        ECHConfig: { SNI: 'ech.example' },
      }),
    );
    expect(result.inbounds[0].address).toEqual(['172.19.0.1/30']);
    expect(result.inbounds[0]).not.toHaveProperty('inet4_address');
    expect(result.route.rule_set[0].tag).toBe('geosite-cn');
    expect(result.route.rules).toContainEqual({ inbound: 'tun-in', action: 'sniff' });
    expect(result.route.default_domain_resolver).toBe('local');
    expect(result.dns.servers[0]).toMatchObject({ type: 'https', server: 'dns.example', path: '/custom-dns' });
    expect(result.outbounds[0].tls).toMatchObject({
      utls: { fingerprint: 'firefox' },
      ech: { enabled: true, query_server_name: 'ech.example' },
    });
  });

  it('Clash gRPC 节点透传 User-Agent，非 gRPC 节点不受影响', () => {
    const source = `mode: Rule\nproxies:\n  - {name: mine, type: vless, uuid: ${UUID}, network: grpc, grpc-opts: {grpc-service-name: test}}\n  - {name: other, type: vless, uuid: other-uuid, network: ws}\nproxy-groups: []\n`;
    const patched = Clash订阅配置文件热补丁(source, { UUID, 传输协议: 'grpc', gRPCUserAgent: 'test-client' });
    expect(patched).toContain('mode: rule');
    expect(patched).toContain('grpc-user-agent: "test-client"');
    expect(patched.split('\n').find((line) => line.includes('name: other'))).not.toContain('grpc-user-agent');
  });

  it('Surge 增加 WebSocket 参数和保留永久订阅管理地址', () => {
    const result = Surge订阅配置文件热补丁(
      '[Proxy]\nnode = trojan, 192.0.2.1, 443, password=test, sni=worker.example, skip-cert-verify=false\n',
      'https://worker.example/sub?token=permanent&surge',
      {
        完整节点路径: '/proxyip=a,b',
        随机路径: false,
        跳过证书验证: false,
        优选订阅生成: { SUBUpdateTime: 3 },
      },
    );
    expect(result).toContain('#!MANAGED-CONFIG https://worker.example/sub?token=permanent&surge interval=10800');
    expect(result).toContain('ws=true, ws-path=/proxyip=a%2Cb');
  });
});
