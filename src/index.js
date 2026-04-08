import { connect } from 'cloudflare:sockets'; // eslint-disable-line no-unused-vars
import { state, resetState, Version, Pages静态页面 } from './state.js';
import { log } from './utils/log.js';
import { MD5MD5 } from './utils/crypto.js';
import { 整理成数组 } from './utils/format.js';
import { 处理WS请求 } from './handler-ws.js';
import { 处理gRPC请求 } from './handler-grpc.js';
import { 处理XHTTP请求 } from './handler-xhttp.js';
import { handleAdmin } from './admin.js';
import { handleSubscription } from './subscription/index.js';
import { 反代参数获取 } from './proxy.js';
import { nginx, html1101 } from './templates.js';
import { 请求日志记录 } from './logging.js';
import { 读取config_JSON } from './config.js';

// ─── Helpers ────────────────────────────────────────────────

/**
 * Normalise a raw request URL string.
 *
 * Strips stray backslashes and encoded backslashes, and converts a
 * percent-encoded '?' to a real query-string delimiter when no literal
 * '?' is present.
 *
 * @param {string} url文本 - The raw URL text from the request
 * @returns {string} The normalised URL string
 */
function 修正请求URL(url文本) {
  url文本 = url文本.replace(/%5[Cc]/g, '').replace(/\\/g, '');
  const 锚点索引 = url文本.indexOf('#');
  const 主体部分 = 锚点索引 === -1 ? url文本 : url文本.slice(0, 锚点索引);
  if (主体部分.includes('?') || !/%3f/i.test(主体部分)) return url文本;
  const 锚点部分 = 锚点索引 === -1 ? '' : url文本.slice(锚点索引);
  return 主体部分.replace(/%3f/i, '?') + 锚点部分;
}

// ─── Entry point ────────────────────────────────────────────

export default {
  /**
   * Cloudflare Worker fetch handler — main router.
   *
   * @param {Request} request
   * @param {object} env
   * @param {ExecutionContext} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    const url = new URL(修正请求URL(request.url));
    const UA = request.headers.get('User-Agent') || 'null';
    const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();
    const contentType = (request.headers.get('content-type') || '').toLowerCase();

    // ── Credentials & UUID ────────────────────────────────────
    const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
    const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
    const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
    const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
    const envUUID = env.UUID || env.uuid;
    const userID = (envUUID && uuidRegex.test(envUUID))
      ? envUUID.toLowerCase()
      : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');

    // ── Hosts ─────────────────────────────────────────────────
    const hosts = env.HOST
      ? (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0])
      : [url.hostname];
    const host = hosts[0];

    // ── Derived request metadata ──────────────────────────────
    const 访问路径 = url.pathname.slice(1).toLowerCase();
    state.调试日志打印 = ['1', 'true'].includes(env.DEBUG) || state.调试日志打印;

    // ── Proxy IP setup ────────────────────────────────────────
    if (env.PROXYIP) {
      const proxyIPs = await 整理成数组(env.PROXYIP);
      state.反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
      state.启用反代兜底 = false;
    } else {
      state.反代IP = (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
    }

    // ── Client IP ─────────────────────────────────────────────
    const 访问IP = request.headers.get('X-Real-IP')
      || request.headers.get('CF-Connecting-IP')
      || request.headers.get('X-Forwarded-For')
      || request.headers.get('True-Client-IP')
      || request.headers.get('Fly-Client-IP')
      || request.headers.get('X-Appengine-Remote-Addr')
      || request.headers.get('X-Forwarded-For')
      || request.headers.get('X-Real-IP')
      || request.headers.get('X-Cluster-Client-IP')
      || request.cf?.clientTcpRtt
      || '未知IP';

    // ── SOCKS5 whitelist ──────────────────────────────────────
    if (env.GO2SOCKS5) state.SOCKS5白名单 = await 整理成数组(env.GO2SOCKS5);

    // ═══════════════════════════════════════════════════════════
    //  Route: /version
    // ═══════════════════════════════════════════════════════════
    if (访问路径 === 'version' && url.searchParams.get('uuid') === userID) {
      return new Response(JSON.stringify({ Version: Number(String(Version).replace(/\D+/g, '')) }), {
        status: 200,
        headers: { 'Content-Type': 'application/json;charset=utf-8' },
      });
    }

    // ═══════════════════════════════════════════════════════════
    //  Route: WebSocket proxy
    // ═══════════════════════════════════════════════════════════
    if (管理员密码 && upgradeHeader === 'websocket') {
      await 反代参数获取(url);
      log(`[WebSocket] 命中请求: ${url.pathname}${url.search}`);
      return await 处理WS请求(request, userID, url);
    }

    // ═══════════════════════════════════════════════════════════
    //  Route: gRPC / XHTTP proxy (POST, non-admin, non-login)
    // ═══════════════════════════════════════════════════════════
    if (管理员密码 && !访问路径.startsWith('admin/') && 访问路径 !== 'login' && request.method === 'POST') {
      await 反代参数获取(url);
      const referer = request.headers.get('Referer') || '';
      const 命中XHTTP特征 = referer.includes('x_padding', 14) || referer.includes('x_padding=');
      if (!命中XHTTP特征 && contentType.startsWith('application/grpc')) {
        log(`[gRPC] 命中请求: ${url.pathname}${url.search}`);
        return await 处理gRPC请求(request, userID);
      }
      log(`[XHTTP] 命中请求: ${url.pathname}${url.search}`);
      return await 处理XHTTP请求(request, userID);
    }

    // ═══════════════════════════════════════════════════════════
    //  Non-proxy GET/other routes
    // ═══════════════════════════════════════════════════════════

    // Force HTTPS
    if (url.protocol === 'http:') {
      return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
    }

    // No admin password configured
    if (!管理员密码) {
      return fetch(Pages静态页面 + '/noADMIN').then(r => {
        const headers = new Headers(r.headers);
        headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        headers.set('Pragma', 'no-cache');
        headers.set('Expires', '0');
        return new Response(r.body, { status: 404, statusText: r.statusText, headers });
      });
    }

    // ── KV-backed routes (login, admin, sub, etc.) ────────────
    if (env.KV && typeof env.KV.get === 'function') {
      const 区分大小写访问路径 = url.pathname.slice(1);

      // Quick subscription shortcut via KEY path
      if (区分大小写访问路径 === 加密秘钥 && 加密秘钥 !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {
        const params = new URLSearchParams(url.search);
        params.set('token', await MD5MD5(host + userID));
        return new Response('重定向中...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
      }

      // ── /login ──────────────────────────────────────────────
      if (访问路径 === 'login') {
        const cookies = request.headers.get('Cookie') || '';
        const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
        if (authCookie === await MD5MD5(UA + 加密秘钥 + 管理员密码)) {
          return new Response('重定向中...', { status: 302, headers: { 'Location': '/admin' } });
        }
        if (request.method === 'POST') {
          const formData = await request.text();
          const params = new URLSearchParams(formData);
          const 输入密码 = params.get('password');
          if (输入密码 === 管理员密码) {
            const 响应 = new Response(JSON.stringify({ success: true }), {
              status: 200,
              headers: { 'Content-Type': 'application/json;charset=utf-8' },
            });
            响应.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + 加密秘钥 + 管理员密码)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`);
            return 响应;
          }
        }
        return fetch(Pages静态页面 + '/login');
      }

      // ── /admin/* and /logout ────────────────────────────────
      if (访问路径 === 'admin' || 访问路径.startsWith('admin/') || 访问路径 === 'logout' || uuidRegex.test(访问路径)) {
        const adminResponse = await handleAdmin(request, url, env, UA, 管理员密码, 加密秘钥, userID, host, hosts, 访问IP, ctx);
        if (adminResponse) return adminResponse;
      }

      // ── /sub — subscription ─────────────────────────────────
      if (访问路径 === 'sub') {
        const 订阅TOKEN = await MD5MD5(host + userID);
        const 作为优选订阅生成器 = ['1', 'true'].includes(env.BEST_SUB)
          && url.searchParams.get('host') === 'example.com'
          && url.searchParams.get('uuid') === '00000000-0000-4000-8000-000000000000'
          && UA.toLowerCase().includes('tunnel (https://github.com/cmliu/edge');
        if (url.searchParams.get('token') === 订阅TOKEN || 作为优选订阅生成器) {
          const config_JSON = await 读取config_JSON(env, host, userID, UA);
          if (作为优选订阅生成器) ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_Best_SUB', config_JSON, false));
          else ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_SUB', config_JSON));
          return await handleSubscription(request, url, env, config_JSON, userID, host, UA, 作为优选订阅生成器);
        }
      }

      // ── /locations — CF speed test locations ────────────────
      if (访问路径 === 'locations') {
        const cookies = request.headers.get('Cookie') || '';
        const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
        if (authCookie && authCookie === await MD5MD5(UA + 加密秘钥 + 管理员密码)) {
          return fetch(new Request('https://speed.cloudflare.com/locations', {
            headers: { 'Referer': 'https://speed.cloudflare.com/' },
          }));
        }
      }

      // ── /robots.txt ─────────────────────────────────────────
      if (访问路径 === 'robots.txt') {
        return new Response('User-agent: *\nDisallow: /', {
          status: 200,
          headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
        });
      }
    } else if (!envUUID) {
      // No KV and no UUID — show noKV page
      return fetch(Pages静态页面 + '/noKV').then(r => {
        const headers = new Headers(r.headers);
        headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        headers.set('Pragma', 'no-cache');
        headers.set('Expires', '0');
        return new Response(r.body, { status: 404, statusText: r.statusText, headers });
      });
    }

    // ═══════════════════════════════════════════════════════════
    //  Disguise page (伪装页) — reverse proxy or static fallback
    // ═══════════════════════════════════════════════════════════
    let 伪装页URL = env.URL || 'nginx';
    if (伪装页URL && 伪装页URL !== 'nginx' && 伪装页URL !== '1101') {
      伪装页URL = 伪装页URL.trim().replace(/\/$/, '');
      if (!伪装页URL.match(/^https?:\/\//i)) 伪装页URL = 'https://' + 伪装页URL;
      if (伪装页URL.toLowerCase().startsWith('http://')) 伪装页URL = 'https://' + 伪装页URL.substring(7);
      try {
        const u = new URL(伪装页URL);
        伪装页URL = u.protocol + '//' + u.host;
      } catch (e) {
        伪装页URL = 'nginx';
      }
    }

    if (伪装页URL === '1101') {
      return new Response(await html1101(url.host, 访问IP), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=UTF-8' },
      });
    }

    try {
      const 反代URL = new URL(伪装页URL);
      const 新请求头 = new Headers(request.headers);
      新请求头.set('Host', 反代URL.host);
      新请求头.set('Referer', 反代URL.origin);
      新请求头.set('Origin', 反代URL.origin);
      if (!新请求头.has('User-Agent') && UA && UA !== 'null') 新请求头.set('User-Agent', UA);

      const 反代响应 = await fetch(反代URL.origin + url.pathname + url.search, {
        method: request.method,
        headers: 新请求头,
        body: request.body,
        cf: request.cf,
      });
      const 内容类型 = 反代响应.headers.get('content-type') || '';
      // Only process text-type responses
      if (/text|javascript|json|xml/.test(内容类型)) {
        const 响应内容 = (await 反代响应.text()).replaceAll(反代URL.host, url.host);
        return new Response(响应内容, {
          status: 反代响应.status,
          headers: { ...Object.fromEntries(反代响应.headers), 'Cache-Control': 'no-store' },
        });
      }
      return 反代响应;
    } catch (error) {
      // Reverse proxy failed — fall through to nginx page
    }

    return new Response(await nginx(), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=UTF-8' },
    });
  },
};
