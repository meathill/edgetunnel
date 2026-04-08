/**
 * Version identifier for the worker build.
 * @type {string}
 */
export const Version = '2026-04-06 18:42:41';

/**
 * Static pages CDN origin.
 * @type {string}
 */
export const Pages静态页面 = 'https://edt-pages.github.io';

/**
 * Global mutable state shared across the worker request lifecycle.
 *
 * Properties are intentionally kept with their original Chinese names
 * to stay consistent with the rest of the codebase.
 */
export const state = {
  /** @type {any} */
  config_JSON: undefined,

  /** @type {string} */
  反代IP: '',

  /** @type {string|null} */
  启用SOCKS5反代: null,

  /** @type {boolean} */
  启用SOCKS5全局反代: false,

  /** @type {string} */
  我的SOCKS5账号: '',

  /** @type {{ username?: string, password?: string, hostname?: string, port?: number }} */
  parsedSocks5Address: {},

  /** @type {string|undefined} */
  缓存反代IP: undefined,

  /** @type {Array<[string, number]>|undefined} */
  缓存反代解析数组: undefined,

  /** @type {number} */
  缓存反代数组索引: 0,

  /** @type {boolean} */
  启用反代兜底: true,

  /** @type {boolean} */
  调试日志打印: false,

  /** @type {string[]} */
  SOCKS5白名单: [
    '*tapecontent.net',
    '*cloudatacdn.com',
    '*loadshare.org',
    '*cdn-centaurus.com',
    'scholar.google.com',
  ],
};

/**
 * Reset per-request mutable state to its initial values.
 * Call this at the beginning of each incoming request.
 */
export function resetState() {
  state.config_JSON = undefined;
  state.反代IP = '';
  state.启用SOCKS5反代 = null;
  state.启用SOCKS5全局反代 = false;
  state.我的SOCKS5账号 = '';
  state.parsedSocks5Address = {};
  state.缓存反代IP = undefined;
  state.缓存反代解析数组 = undefined;
  state.缓存反代数组索引 = 0;
  state.启用反代兜底 = true;
  state.调试日志打印 = false;
  state.SOCKS5白名单 = [
    '*tapecontent.net',
    '*cloudatacdn.com',
    '*loadshare.org',
    '*cdn-centaurus.com',
    'scholar.google.com',
  ];
}
