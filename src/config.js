import { state } from './state.js';
import { log } from './utils/log.js';
import { MD5MD5 } from './utils/crypto.js';
import { 掩码敏感信息, 整理成数组 } from './utils/format.js';
import { 随机路径 } from './utils/path.js';

/**
 * Read and initialize config_JSON from KV storage.
 *
 * Builds the default config object, loads/saves config from KV,
 * validates UUID format, constructs node paths, generates subscription
 * tokens, and reads CF and Telegram config from KV.
 *
 * @param {object} env - Cloudflare Worker environment bindings
 * @param {string} hostname - The request hostname
 * @param {string} userID - The user UUID
 * @param {string} [UA="Mozilla/5.0"] - User-Agent string
 * @param {boolean} [重置配置=false] - Whether to reset config to defaults
 * @returns {Promise<object>} The resolved config_JSON object
 */
export async function 读取config_JSON(env, hostname, userID, UA = "Mozilla/5.0", 重置配置 = false) {
  const _p = atob("UFJPWFlJUA==");
  const host = hostname, Ali_DoH = "https://dns.alidns.com/dns-query", ECH_SNI = "cloudflare-ech.com", 占位符 = '{{IP:PORT}}', 初始化开始时间 = performance.now(), 默认配置JSON = {
    TIME: new Date().toISOString(),
    HOST: host,
    HOSTS: [hostname],
    UUID: userID,
    PATH: "/",
    协议类型: "v" + "le" + "ss",
    传输协议: "ws",
    gRPC模式: "gun",
    gRPCUserAgent: UA,
    跳过证书验证: false,
    启用0RTT: false,
    TLS分片: null,
    随机路径: false,
    ECH: false,
    ECHConfig: {
      DNS: Ali_DoH,
      SNI: ECH_SNI,
    },
    SS: {
      加密方式: "aes-128-gcm",
      TLS: true,
    },
    Fingerprint: "chrome",
    优选订阅生成: {
      local: true, // true: 基于本地的优选地址  false: 优选订阅生成器
      本地IP库: {
        随机IP: true, // 当 随机IP 为true时生效，启用随机IP的数量，否则使用KV内的ADD.txt
        随机数量: 16,
        指定端口: -1,
      },
      SUB: null,
      SUBNAME: "edge" + "tunnel",
      SUBUpdateTime: 3, // 订阅更新时间（小时）
      TOKEN: await MD5MD5(hostname + userID),
    },
    订阅转换配置: {
      SUBAPI: "https://SUBAPI.cmliussss.net",
      SUBCONFIG: "https://raw.githubusercontent.com/cmliu/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini",
      SUBEMOJI: false,
    },
    反代: {
      [_p]: "auto",
      SOCKS5: {
        启用: state.启用SOCKS5反代,
        全局: state.启用SOCKS5全局反代,
        账号: state.我的SOCKS5账号,
        白名单: state.SOCKS5白名单,
      },
      路径模板: {
        [_p]: "proxyip=" + 占位符,
        SOCKS5: {
          全局: "socks5://" + 占位符,
          标准: "socks5=" + 占位符
        },
        HTTP: {
          全局: "http://" + 占位符,
          标准: "http=" + 占位符
        },
      },
    },
    TG: {
      启用: false,
      BotToken: null,
      ChatID: null,
    },
    CF: {
      Email: null,
      GlobalAPIKey: null,
      AccountID: null,
      APIToken: null,
      UsageAPI: null,
      Usage: {
        success: false,
        pages: 0,
        workers: 0,
        total: 0,
        max: 100000,
      },
    }
  };

  try {
    let configJSON = await env.KV.get('config.json');
    if (!configJSON || 重置配置 == true) {
      await env.KV.put('config.json', JSON.stringify(默认配置JSON, null, 2));
      state.config_JSON = 默认配置JSON;
    } else {
      state.config_JSON = JSON.parse(configJSON);
    }
  } catch (error) {
    console.error(`读取config_JSON出错: ${error.message}`);
    state.config_JSON = 默认配置JSON;
  }

  if (!state.config_JSON.gRPCUserAgent) state.config_JSON.gRPCUserAgent = UA;
  state.config_JSON.HOST = host;
  if (!state.config_JSON.HOSTS) state.config_JSON.HOSTS = [hostname];
  if (env.HOST) state.config_JSON.HOSTS = (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
  state.config_JSON.UUID = userID;
  if (!state.config_JSON.随机路径) state.config_JSON.随机路径 = false;
  if (!state.config_JSON.启用0RTT) state.config_JSON.启用0RTT = false;

  if (env.PATH) state.config_JSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
  else if (!state.config_JSON.PATH) state.config_JSON.PATH = '/';

  if (!state.config_JSON.gRPC模式) state.config_JSON.gRPC模式 = 'gun';
  if (!state.config_JSON.SS) state.config_JSON.SS = { 加密方式: "aes-128-gcm", TLS: false };

  if (!state.config_JSON.反代.路径模板?.[_p]) {
    state.config_JSON.反代.路径模板 = {
      [_p]: "proxyip=" + 占位符,
      SOCKS5: {
        全局: "socks5://" + 占位符,
        标准: "socks5=" + 占位符
      },
      HTTP: {
        全局: "http://" + 占位符,
        标准: "http=" + 占位符
      },
    };
  }

  const 代理配置 = state.config_JSON.反代.路径模板[state.config_JSON.反代.SOCKS5.启用?.toUpperCase()];

  let 路径反代参数 = '';
  if (代理配置 && state.config_JSON.反代.SOCKS5.账号) 路径反代参数 = (state.config_JSON.反代.SOCKS5.全局 ? 代理配置.全局 : 代理配置.标准).replace(占位符, state.config_JSON.反代.SOCKS5.账号);
  else if (state.config_JSON.反代[_p] !== 'auto') 路径反代参数 = state.config_JSON.反代.路径模板[_p].replace(占位符, state.config_JSON.反代[_p]);

  let 反代查询参数 = '';
  if (路径反代参数.includes('?')) {
    const [反代路径部分, 反代查询部分] = 路径反代参数.split('?');
    路径反代参数 = 反代路径部分;
    反代查询参数 = 反代查询部分;
  }

  state.config_JSON.PATH = state.config_JSON.PATH.replace(路径反代参数, '').replace('//', '/');
  const normalizedPath = state.config_JSON.PATH === '/' ? '' : state.config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
  const [路径部分, ...查询数组] = normalizedPath.split('?');
  const 查询部分 = 查询数组.length ? '?' + 查询数组.join('?') : '';
  const 最终查询部分 = 反代查询参数 ? (查询部分 ? 查询部分 + '&' + 反代查询参数 : '?' + 反代查询参数) : 查询部分;
  state.config_JSON.完整节点路径 = (路径部分 || '/') + (路径部分 && 路径反代参数 ? '/' : '') + 路径反代参数 + 最终查询部分 + (state.config_JSON.启用0RTT ? (最终查询部分 ? '&' : '?') + 'ed=2560' : '');

  if (!state.config_JSON.TLS分片 && state.config_JSON.TLS分片 !== null) state.config_JSON.TLS分片 = null;
  const TLS分片参数 = state.config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : state.config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
  if (!state.config_JSON.Fingerprint) state.config_JSON.Fingerprint = "chrome";
  if (!state.config_JSON.ECH) state.config_JSON.ECH = false;
  if (!state.config_JSON.ECHConfig) state.config_JSON.ECHConfig = { DNS: Ali_DoH, SNI: ECH_SNI };
  const ECHLINK参数 = state.config_JSON.ECH ? `&ech=${encodeURIComponent((state.config_JSON.ECHConfig.SNI ? state.config_JSON.ECHConfig.SNI + '+' : '') + state.config_JSON.ECHConfig.DNS)}` : '';
  state.config_JSON.LINK = state.config_JSON.协议类型 === 'ss'
    ? `${state.config_JSON.协议类型}://${btoa(state.config_JSON.SS.加密方式 + ':' + userID)}@${host}:${state.config_JSON.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${((state.config_JSON.完整节点路径.includes('?') ? state.config_JSON.完整节点路径.replace('?', '?enc=' + state.config_JSON.SS.加密方式 + '&') : (state.config_JSON.完整节点路径 + '?enc=' + state.config_JSON.SS.加密方式)) + (state.config_JSON.SS.TLS ? ';tls' : ''))};mux=0`) + ECHLINK参数}#${encodeURIComponent(state.config_JSON.优选订阅生成.SUBNAME)}`
    : `${state.config_JSON.协议类型}://${userID}@${host}:443?security=tls&type=${state.config_JSON.传输协议 + ECHLINK参数}&host=${host}&fp=${state.config_JSON.Fingerprint}&sni=${host}&path=${encodeURIComponent(state.config_JSON.随机路径 ? 随机路径(state.config_JSON.完整节点路径) : state.config_JSON.完整节点路径) + TLS分片参数}&encryption=none${state.config_JSON.跳过证书验证 ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(state.config_JSON.优选订阅生成.SUBNAME)}`;
  state.config_JSON.优选订阅生成.TOKEN = await MD5MD5(hostname + userID);

  const 初始化TG_JSON = { BotToken: null, ChatID: null };
  state.config_JSON.TG = { 启用: state.config_JSON.TG.启用 ? state.config_JSON.TG.启用 : false, ...初始化TG_JSON };
  try {
    const TG_TXT = await env.KV.get('tg.json');
    if (!TG_TXT) {
      await env.KV.put('tg.json', JSON.stringify(初始化TG_JSON, null, 2));
    } else {
      const TG_JSON = JSON.parse(TG_TXT);
      state.config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
      state.config_JSON.TG.BotToken = TG_JSON.BotToken ? 掩码敏感信息(TG_JSON.BotToken) : null;
    }
  } catch (error) {
    console.error(`读取tg.json出错: ${error.message}`);
  }

  const 初始化CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
  state.config_JSON.CF = { ...初始化CF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
  try {
    const CF_TXT = await env.KV.get('cf.json');
    if (!CF_TXT) {
      await env.KV.put('cf.json', JSON.stringify(初始化CF_JSON, null, 2));
    } else {
      const CF_JSON = JSON.parse(CF_TXT);
      if (CF_JSON.UsageAPI) {
        try {
          const response = await fetch(CF_JSON.UsageAPI);
          const Usage = await response.json();
          state.config_JSON.CF.Usage = Usage;
        } catch (err) {
          console.error(`请求 CF_JSON.UsageAPI 失败: ${err.message}`);
        }
      } else {
        state.config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
        state.config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? 掩码敏感信息(CF_JSON.GlobalAPIKey) : null;
        state.config_JSON.CF.AccountID = CF_JSON.AccountID ? 掩码敏感信息(CF_JSON.AccountID) : null;
        state.config_JSON.CF.APIToken = CF_JSON.APIToken ? 掩码敏感信息(CF_JSON.APIToken) : null;
        state.config_JSON.CF.UsageAPI = null;
        state.config_JSON.CF.Usage = null;
      }
    }
  } catch (error) {
    console.error(`读取cf.json出错: ${error.message}`);
  }

  state.config_JSON.加载时间 = (performance.now() - 初始化开始时间).toFixed(2) + 'ms';
  return state.config_JSON;
}
