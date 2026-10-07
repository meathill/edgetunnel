import { MD5MD5 } from '../utils/crypto.js';
import { 特征码字典 } from '../state.js';
import { base64SecretEncode } from '../utils/secret.js';
import { 读取config_JSON } from '../config.js';
import { 请求日志记录 } from '../logging.js';
import { 生成随机IP, 请求优选API, 获取优选订阅生成器数据, 识别运营商 } from '../best-ip.js';
import { 整理成数组, 替换星号为随机字符 } from '../utils/format.js';
import { 获取传输协议配置, 获取传输路径参数值 } from './transport.js';
import { 获取SOCKS5账号, 获取代理默认端口 } from '../proxy.js';
import { 随机路径 } from '../utils/path.js';
import { Surge订阅配置文件热补丁 } from './surge.js';
import { Singbox订阅配置文件热补丁 } from './singbox.js';
import { Clash订阅配置文件热补丁 } from './clash.js';
export async function handleSubscription(request, url, env, userID, host, UA, 访问IP, ctx) {
  let config_JSON;
  //处理订阅请求
  const 订阅TOKEN = await MD5MD5(host + userID),
    作为优选订阅生成器 =
      ['1', 'true'].includes(env.BEST_SUB) &&
      url.searchParams.get('host') === 'example.com' &&
      url.searchParams.get('uuid') === '00000000-0000-4000-8000-000000000000' &&
      UA.toLowerCase().includes('tunnel (https://github.com/' + 特征码字典[1] + '/edge');
  const 请求TOKEN = url.searchParams.get('token');
  const 用户客户端请求订阅 = 请求TOKEN === 订阅TOKEN;
  const 当前日序号 = Math.floor(Date.now() / 86400000);
  const 订阅转换后端TOKEN种子 = base64SecretEncode(订阅TOKEN, userID);
  const [今日订阅转换后端专属TOKEN, 昨日订阅转换后端专属TOKEN] = await Promise.all([
    MD5MD5(订阅转换后端TOKEN种子 + 当前日序号),
    MD5MD5(订阅转换后端TOKEN种子 + (当前日序号 - 1)),
  ]);
  const 订阅转换后端请求订阅 = 请求TOKEN === 今日订阅转换后端专属TOKEN || 请求TOKEN === 昨日订阅转换后端专属TOKEN;
  if (用户客户端请求订阅 || 订阅转换后端请求订阅 || 作为优选订阅生成器) {
    config_JSON = await 读取config_JSON(env, host, userID, UA);
    if (作为优选订阅生成器) ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_Best_SUB', config_JSON, false));
    else ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_SUB', config_JSON));
    const ua = UA.toLowerCase();
    const responseHeaders = {
      'content-type': 'text/plain; charset=utf-8',
      'Profile-Update-Interval': config_JSON.优选订阅生成.SUBUpdateTime,
      'Profile-web-page-url': url.protocol + '//' + url.host + '/admin',
      'Cache-Control': 'no-store',
    };
    if (config_JSON.CF.Usage?.success) {
      const pagesSum = config_JSON.CF.Usage.pages;
      const workersSum = config_JSON.CF.Usage.workers;
      const total = Number.isFinite(config_JSON.CF.Usage.max) ? (config_JSON.CF.Usage.max / 1000) * 1024 : 1024 * 100;
      responseHeaders['Subscription-Userinfo'] =
        `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=4102329600`; // 2099-12-31 到期时间
    }
    const isSubConverterRequest =
      url.searchParams.has('b64') ||
      url.searchParams.has('base64') ||
      request.headers.get('subconverter-request') ||
      request.headers.get('subconverter-version') ||
      ua.includes('subconverter') ||
      ua.includes('CF-Workers-SUB'.toLowerCase()) ||
      作为优选订阅生成器;
    const 订阅类型 = isSubConverterRequest
      ? 'mixed'
      : url.searchParams.has('target')
        ? url.searchParams.get('target')
        : url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
          ? 'clash'
          : url.searchParams.has('sb') ||
              url.searchParams.has('singbox') ||
              ua.includes('singbox') ||
              ua.includes('sing-box')
            ? 'singbox'
            : url.searchParams.has('surge') || ua.includes('surge')
              ? 'surge&ver=4'
              : url.searchParams.has('quanx') || ua.includes('quantumult')
                ? 'quanx'
                : url.searchParams.has('loon') || ua.includes('loon')
                  ? 'loon'
                  : 'mixed';

    if (!ua.includes('mozilla'))
      responseHeaders['Content-Disposition'] =
        `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
    const 协议类型 =
      (url.searchParams.has('surge') || ua.includes('surge')) && config_JSON.协议类型 !== 'ss'
        ? 'tro' + 'jan'
        : config_JSON.协议类型;
    let 订阅内容 = '';
    if (订阅类型 === 'mixed') {
      const TLS分片参数 =
        config_JSON.TLS分片 == 'Shadowrocket'
          ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}`
          : config_JSON.TLS分片 == 'Happ'
            ? `&fragment=${encodeURIComponent('3,1,tlshello')}`
            : '';
      let 完整优选IP = [],
        其他节点LINK = '',
        反代IP池 = [];

      if (!url.searchParams.has('sub') && config_JSON.优选订阅生成.local) {
        // 本地生成订阅
        const 完整优选列表 = config_JSON.优选订阅生成.本地IP库.随机IP
          ? (
              await 生成随机IP(
                request,
                config_JSON.优选订阅生成.本地IP库.随机数量,
                config_JSON.优选订阅生成.本地IP库.指定端口,
              )
            )[0]
          : (await env.KV.get('ADD.txt'))
            ? await 整理成数组(await env.KV.get('ADD.txt'))
            : (
                await 生成随机IP(
                  request,
                  config_JSON.优选订阅生成.本地IP库.随机数量,
                  config_JSON.优选订阅生成.本地IP库.指定端口,
                )
              )[0];
        const 优选API = [],
          优选IP = [],
          其他节点 = [];
        for (const 元素 of 完整优选列表) {
          if (元素.toLowerCase().startsWith('sub://')) {
            优选API.push(元素);
          } else {
            const 备注位置 = 元素.indexOf('#');
            const 地址部分 = 备注位置 > -1 ? 元素.slice(0, 备注位置) : 元素;
            const 备注部分 = 备注位置 > -1 ? 元素.slice(备注位置) : '';
            const subMatch = 元素.match(/sub\s*=\s*([^\s&#]+)/i);
            if (subMatch && subMatch[1].trim().includes('.')) {
              const 优选IP作为反代IP = 元素.toLowerCase().includes('proxyip=true');
              if (优选IP作为反代IP)
                优选API.push(
                  'sub://' +
                    subMatch[1].trim() +
                    '?proxyip=true' +
                    (元素.includes('#') ? '#' + 元素.split('#')[1] : ''),
                );
              else 优选API.push('sub://' + subMatch[1].trim() + (元素.includes('#') ? '#' + 元素.split('#')[1] : ''));
            } else if (地址部分.toLowerCase().startsWith('https://')) {
              优选API.push(元素);
            } else if (地址部分.toLowerCase().includes('://')) {
              if (元素.includes('#')) {
                const 地址备注分离 = 元素.split('#');
                其他节点.push(地址备注分离[0] + '#' + encodeURIComponent(decodeURIComponent(地址备注分离[1])));
              } else 其他节点.push(元素);
            } else {
              if (地址部分.includes('*')) {
                优选IP.push(替换星号为随机字符(地址部分) + 备注部分);
              } else 优选IP.push(元素);
            }
          }
        }
        const 请求优选API内容 = await 请求优选API(优选API, '443');
        const 合并其他节点数组 = [...new Set(其他节点.concat(请求优选API内容[1]))];
        其他节点LINK = 合并其他节点数组.length > 0 ? 合并其他节点数组.join('\n') + '\n' : '';
        const 优选API的IP = 请求优选API内容[0];
        反代IP池 = 请求优选API内容[3] || [];
        完整优选IP = [...new Set(优选IP.concat(优选API的IP))];
      } else {
        // 优选订阅生成器
        let 优选订阅生成器HOST = url.searchParams.get('sub') || config_JSON.优选订阅生成.SUB;
        const [优选生成器IP数组, 优选生成器其他节点] = await 获取优选订阅生成器数据(优选订阅生成器HOST);
        完整优选IP = 完整优选IP.concat(优选生成器IP数组);
        其他节点LINK += 优选生成器其他节点;
      }
      const ECHLINK参数 = config_JSON.ECH
        ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}`
        : '';
      const isLoonOrSurge = ua.includes('loon') || ua.includes('surge');
      const { type: 传输协议, 路径字段名, 域名字段名 } = 获取传输协议配置(config_JSON);
      订阅内容 =
        其他节点LINK +
        完整优选IP
          .map((原始地址) => {
            // 统一正则: 匹配 域名/IPv4/IPv6地址 + 可选端口 + 可选备注
            // 示例:
            //   - 域名: hj.xmm1993.top:2096#备注 或 example.com
            //   - IPv4: 166.0.188.128:443#Los Angeles 或 166.0.188.128
            //   - IPv6: [2606:4700::]:443#CMCC 或 [2606:4700::]
            const regex =
              /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
            const match = 原始地址.match(regex);

            let 节点地址,
              节点端口 = '443',
              节点备注;

            if (match) {
              节点地址 = match[1]; // IP地址或域名(可能带方括号)
              节点端口 = match[2] ? match[2] : '443'; // 端口默认443，SS noTLS在生成链接时再映射
              节点备注 = match[3] || 节点地址; // 备注,默认为地址本身
            } else {
              // 不规范的格式，跳过处理返回null
              console.warn(`[订阅内容] 不规范的IP格式已忽略: ${原始地址}`);
              return null;
            }

            let 完整节点路径 = config_JSON.完整节点路径;

            const 链式代理匹配 = 节点备注.match(/\$(socks5|http|https|turn|sstp):\/\/([^#\s]+)/i);
            if (链式代理匹配) {
              try {
                const 代理协议 = 链式代理匹配[1].toLowerCase(),
                  代理参数 = 链式代理匹配[2];
                const 链式代理数据 = { type: 代理协议, ...获取SOCKS5账号(代理参数, 获取代理默认端口(代理协议)) };
                完整节点路径 = `/video/${base64SecretEncode(JSON.stringify(链式代理数据), userID) + (config_JSON.启用0RTT ? '?ed=2560' : '')}`;
                节点备注 = 节点备注.replace(链式代理匹配[0], '').trim() || 节点地址;
              } catch (error) {
                console.warn(
                  `[订阅内容] 链式代理解析失败，已忽略该指令: ${链式代理匹配[0]} (${error && error.message ? error.message : error})`,
                );
              }
            } else if (反代IP池.length > 0) {
              const 匹配到的反代IP = 反代IP池.find((p) => p.includes(节点地址));
              if (匹配到的反代IP)
                完整节点路径 =
                  `${config_JSON.PATH}/proxyip=${匹配到的反代IP}`.replace(/\/\//g, '/') +
                  (config_JSON.启用0RTT ? '?ed=2560' : '');
            }
            if (isLoonOrSurge) 完整节点路径 = 完整节点路径.replace(/,/g, '%2C');

            if (协议类型 === 'ss' && !作为优选订阅生成器) {
              if (!config_JSON.SS.TLS) {
                const TLS端口 = [443, 2053, 2083, 2087, 2096, 8443];
                const NOTLS端口 = [80, 2052, 2082, 2086, 2095, 8080];
                节点端口 = String(NOTLS端口[TLS端口.indexOf(Number(节点端口))] ?? 节点端口);
              }
              完整节点路径 = (
                完整节点路径.includes('?')
                  ? 完整节点路径.replace('?', '?enc=' + config_JSON.SS.加密方式 + '&')
                  : 完整节点路径 + '?enc=' + config_JSON.SS.加密方式
              ).replace(/([=,])/g, '\\$1');
              if (!isSubConverterRequest) 完整节点路径 = 完整节点路径 + ';mux=0';
              return `${协议类型}://${btoa(config_JSON.SS.加密方式 + ':00000000-0000-4000-8000-000000000000')}@${节点地址}:${节点端口}?plugin=v2${encodeURIComponent('ray-plugin;mode=websocket;host=example.com;path=' + (config_JSON.随机路径 ? 随机路径(完整节点路径) : 完整节点路径) + (config_JSON.SS.TLS ? ';tls' : '')) + ECHLINK参数 + TLS分片参数}#${encodeURIComponent(节点备注)}`;
            } else {
              const 传输路径参数值 = 获取传输路径参数值(config_JSON, 完整节点路径, 作为优选订阅生成器);
              return `${协议类型}://00000000-0000-4000-8000-000000000000@${节点地址}:${节点端口}?security=tls&type=${传输协议 + ECHLINK参数}&${域名字段名}=example.com&fp=${config_JSON.Fingerprint}&sni=example.com&${路径字段名}=${encodeURIComponent(传输路径参数值) + TLS分片参数}&encryption=none&alpn=${encodeURIComponent(config_JSON.ALPN)}#${encodeURIComponent(节点备注)}`;
            }
          })
          .filter((item) => item !== null)
          .join('\n');
    } else {
      // 订阅转换
      const 订阅转换URL = `${config_JSON.订阅转换配置.SUBAPI}/sub?target=${订阅类型}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + 今日订阅转换后端专属TOKEN + '&cnIspCode=' + 识别运营商(request) + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(config_JSON.订阅转换配置.SUBCONFIG)}&emoji=${config_JSON.订阅转换配置.SUBEMOJI}&list=${config_JSON.订阅转换配置.SUBLIST}&scv=${config_JSON.跳过证书验证}&xudp=${config_JSON.订阅转换配置.XUDP}&udp=${config_JSON.订阅转换配置.UDP}&tls13=${config_JSON.订阅转换配置.TLS13}&append_type=${config_JSON.订阅转换配置.APPEND_TYPE}&sort=${config_JSON.订阅转换配置.SORT}&expand=${config_JSON.订阅转换配置.EXPAND}`;
      try {
        const response = await fetch(订阅转换URL, {
          headers: {
            'User-Agent':
              'Subconverter for ' +
              订阅类型 +
              ' edge' +
              'tunnel (https://github.com/' +
              特征码字典[1] +
              '/edge' +
              'tunnel)',
          },
        });
        if (response.ok) {
          订阅内容 = await response.text();
          if (url.searchParams.has('surge') || ua.includes('surge'))
            订阅内容 = Surge订阅配置文件热补丁(
              订阅内容,
              url.protocol + '//' + url.host + '/sub?token=' + 订阅TOKEN + '&surge',
              config_JSON,
            );
        } else return new Response('订阅转换后端异常：' + response.statusText, { status: response.status });
      } catch (error) {
        return new Response('订阅转换后端异常：', { status: 403 });
      }
    }

    if (!ua.includes('subconverter') && 用户客户端请求订阅) {
      const 打乱后HOSTS = [...config_JSON.HOSTS].sort(() => Math.random() - 0.5);
      let 替换域名计数 = 0,
        当前随机HOST = null;
      订阅内容 = 订阅内容
        .replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID)
        .replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(config_JSON.UUID))
        .replace(/example\.com/g, () => {
          if (替换域名计数 % 2 === 0) {
            const 原始host = 打乱后HOSTS[Math.floor(替换域名计数 / 2) % 打乱后HOSTS.length];
            当前随机HOST = 替换星号为随机字符(原始host);
          }
          替换域名计数++;
          return 当前随机HOST;
        });
    }

    if (
      订阅类型 === 'mixed' &&
      (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))
    )
      订阅内容 = btoa(订阅内容);

    if (订阅类型 === 'singbox') {
      订阅内容 = await Singbox订阅配置文件热补丁(订阅内容, config_JSON);
      responseHeaders['content-type'] = 'application/json; charset=utf-8';
    } else if (订阅类型 === 'clash') {
      订阅内容 = Clash订阅配置文件热补丁(订阅内容, config_JSON);
      responseHeaders['content-type'] = 'application/x-yaml; charset=utf-8';
    }
    return new Response(订阅内容, { status: 200, headers: responseHeaders });
  }
}
