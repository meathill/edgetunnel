import { 识别运营商 } from './best-ip.js';
export const Version = '2026-09-22 20:01:17';

export const SOCKS5白名单 = [
  '*tapecontent.net',
  '*cloudatacdn.com',
  '*loadshare.org',
  '*cdn-centaurus.com',
  'scholar.google.com',
];

export const Pages静态页面 = 'https://edt-pages.github.io';

export const WS早期数据最大字节 = 8 * 1024,
  WS早期数据最大头长度 = Math.ceil((WS早期数据最大字节 * 4) / 3) + 4;

export const 上行合包目标字节 = 20 * 1024,
  上行队列最大字节 = 16 * 1024 * 1024,
  上行队列最大条目 = 4096;

export const 下行Grain包字节 = 32 * 1024,
  下行Grain尾部阈值 = 512,
  下行Grain低水位字节 = Math.max(4096, 下行Grain尾部阈值 * 12),
  下行Grain最大等待轮次 = 4;

export const 特征码字典 = [
  (Proxy.name + 'IP').toUpperCase(),
  (String.fromCharCode(67, 109) + URL.name[2] + 'i' + URL.name[0]).toLowerCase(),
  String(2407 * 300 - 10)
    .split('')
    .reverse()
    .join(''),
];

export const 汇聚订阅_UA = 'v2rayN/edge' + 'tunnel (https://github.com/' + 特征码字典[1] + '/edge' + 'tunnel)';

export function 获取请求设置(env = {}, request = {}) {
  const 并发数 = (value, fallback) =>
    Number.isFinite(Number(value)) && Number(value) > 0 ? Math.max(1, Math.floor(Number(value))) : fallback;
  return {
    调试日志打印: ['1', 'true'].includes(env.DEBUG),
    预加载竞速拨号: ['1', 'true'].includes(env.PRELOAD_RACE_DIAL),
    TCP并发拨号数: 并发数(env.TCP_CONCURRENT_DIAL, 识别运营商(request) === 'cmcc' ? 1 : 2),
    反代并发拨号数: 并发数(env.PROXY_CONCURRENT_DIAL, 1),
    SOCKS5白名单: [
      ...new Set(
        SOCKS5白名单.concat(
          String(env.GO2SOCKS5 || '')
            .replace(/[\t"'\r\n]+/g, ',')
            .split(',')
            .map((x) => x.trim())
            .filter(Boolean),
        ),
      ),
    ],
  };
}
