import { state, Pages静态页面 } from './state.js';
import { log } from './utils/log.js';
import { verifyAuth, createAuthCookie, clearAuthCookie } from './auth.js';
import { 读取config_JSON } from './config.js';
import { 请求优选API } from './best-ip.js';
import { SOCKS5可用性验证 } from './proxy.js';
import { 请求日志记录 } from './logging.js';

/**
 * Handle all /admin/* route requests as well as /logout.
 *
 * Performs cookie-based auth verification before serving any admin
 * endpoint.  POST routes persist data to KV; GET routes read from it.
 *
 * @param {Request} request - The incoming request
 * @param {URL} url - Parsed request URL
 * @param {object} env - Cloudflare Worker environment bindings
 * @param {string} UA - User-Agent string
 * @param {string} 管理员密码 - Admin password
 * @param {string} 加密秘钥 - Encryption key
 * @param {string} userID - User UUID
 * @param {string} host - Primary hostname
 * @param {string[]} hosts - All configured hostnames
 * @param {string} 访问IP - Client IP address
 * @param {ExecutionContext} ctx - Cloudflare execution context
 * @returns {Promise<Response|null>} Response for admin routes, or null if unhandled
 */
export async function handleAdmin(request, url, env, UA, 管理员密码, 加密秘钥, userID, host, hosts, 访问IP, ctx) {
  const 访问路径 = url.pathname.slice(1).toLowerCase();
  const 区分大小写访问路径 = url.pathname.slice(1);
  const cookies = request.headers.get('Cookie') || '';

  // ── /logout or bare UUID path ─────────────────────────────
  const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
  if (访问路径 === 'logout' || uuidRegex.test(访问路径)) {
    const 响应 = new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
    响应.headers.set('Set-Cookie', clearAuthCookie());
    return 响应;
  }

  // ── Only handle admin/* from here ─────────────────────────
  if (访问路径 !== 'admin' && !访问路径.startsWith('admin/')) return null;

  // ── Auth check ────────────────────────────────────────────
  const isAuthed = await verifyAuth(cookies, UA, 加密秘钥, 管理员密码);
  if (!isAuthed) {
    return new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
  }

  // ── /admin/log.json — read logs ───────────────────────────
  if (访问路径 === 'admin/log.json') {
    const 读取日志内容 = await env.KV.get('log.json') || '[]';
    return new Response(读取日志内容, {
      status: 200,
      headers: { 'Content-Type': 'application/json;charset=utf-8' },
    });
  }

  // ── /admin/getADDAPI — verify best IP API ─────────────────
  if (区分大小写访问路径 === 'admin/getADDAPI') {
    if (url.searchParams.get('url')) {
      const 待验证优选URL = url.searchParams.get('url');
      try {
        new URL(待验证优选URL);
        const 请求优选API内容 = await 请求优选API([待验证优选URL], url.searchParams.get('port') || '443');
        let 优选API的IP = 请求优选API内容[0].length > 0 ? 请求优选API内容[0] : 请求优选API内容[1];
        优选API的IP = 优选API的IP.map(item => item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)));
        return new Response(JSON.stringify({ success: true, data: 优选API的IP }, null, 2), {
          status: 200,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      } catch (err) {
        const errorResponse = { msg: '验证优选API失败，失败原因：' + err.message, error: err.message };
        return new Response(JSON.stringify(errorResponse, null, 2), {
          status: 500,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      }
    }
    return new Response(JSON.stringify({ success: false, data: [] }, null, 2), {
      status: 403,
      headers: { 'Content-Type': 'application/json;charset=utf-8' },
    });
  }

  // ── /admin/check — proxy validation ───────────────────────
  if (访问路径 === 'admin/check') {
    /** @type {any} */
    let 检测代理响应;
    if (url.searchParams.has('socks5')) {
      检测代理响应 = await SOCKS5可用性验证('socks5', url.searchParams.get('socks5'));
    } else if (url.searchParams.has('http')) {
      检测代理响应 = await SOCKS5可用性验证('http', url.searchParams.get('http'));
    } else if (url.searchParams.has('https')) {
      检测代理响应 = await SOCKS5可用性验证('https', url.searchParams.get('https'));
    } else {
      return new Response(JSON.stringify({ error: '缺少代理参数' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json;charset=utf-8' },
      });
    }
    return new Response(JSON.stringify(检测代理响应, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json;charset=utf-8' },
    });
  }

  // ── Read config for remaining routes ──────────────────────
  let config_JSON = await 读取config_JSON(env, host, userID, UA);

  // ── /admin/init — reset config ────────────────────────────
  if (访问路径 === 'admin/init') {
    try {
      config_JSON = await 读取config_JSON(env, host, userID, UA, true);
      ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Init_Config', config_JSON));
      config_JSON.init = '配置已重置为默认值';
      return new Response(JSON.stringify(config_JSON, null, 2), {
        status: 200,
        headers: { 'Content-Type': 'application/json;charset=utf-8' },
      });
    } catch (err) {
      const errorResponse = { msg: '配置重置失败，失败原因：' + err.message, error: err.message };
      return new Response(JSON.stringify(errorResponse, null, 2), {
        status: 500,
        headers: { 'Content-Type': 'application/json;charset=utf-8' },
      });
    }
  }

  // ── POST routes ───────────────────────────────────────────
  if (request.method === 'POST') {
    // /admin/config.json — save config
    if (访问路径 === 'admin/config.json') {
      try {
        const newConfig = await request.json();
        if (!newConfig.UUID || !newConfig.HOST) {
          return new Response(JSON.stringify({ error: '配置不完整' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json;charset=utf-8' },
          });
        }
        await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
        ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
        return new Response(JSON.stringify({ success: true, message: '配置已保存' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      } catch (error) {
        console.error('保存配置失败:', error);
        return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      }
    }

    // /admin/cf.json — save CF credentials
    if (访问路径 === 'admin/cf.json') {
      try {
        const newConfig = await request.json();
        const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
        if (!newConfig.init || newConfig.init !== true) {
          if (newConfig.Email && newConfig.GlobalAPIKey) {
            CF_JSON.Email = newConfig.Email;
            CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
          } else if (newConfig.AccountID && newConfig.APIToken) {
            CF_JSON.AccountID = newConfig.AccountID;
            CF_JSON.APIToken = newConfig.APIToken;
          } else if (newConfig.UsageAPI) {
            CF_JSON.UsageAPI = newConfig.UsageAPI;
          } else {
            return new Response(JSON.stringify({ error: '配置不完整' }), {
              status: 400,
              headers: { 'Content-Type': 'application/json;charset=utf-8' },
            });
          }
        }
        await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
        ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
        return new Response(JSON.stringify({ success: true, message: '配置已保存' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      } catch (error) {
        console.error('保存配置失败:', error);
        return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      }
    }

    // /admin/tg.json — save Telegram config
    if (访问路径 === 'admin/tg.json') {
      try {
        const newConfig = await request.json();
        if (newConfig.init && newConfig.init === true) {
          const TG_JSON = { BotToken: null, ChatID: null };
          await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
        } else {
          if (!newConfig.BotToken || !newConfig.ChatID) {
            return new Response(JSON.stringify({ error: '配置不完整' }), {
              status: 400,
              headers: { 'Content-Type': 'application/json;charset=utf-8' },
            });
          }
          await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
        }
        ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
        return new Response(JSON.stringify({ success: true, message: '配置已保存' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      } catch (error) {
        console.error('保存配置失败:', error);
        return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      }
    }

    // /admin/ADD.txt — save custom IPs
    if (区分大小写访问路径 === 'admin/ADD.txt') {
      try {
        const customIPs = await request.text();
        await env.KV.put('ADD.txt', customIPs);
        ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Custom_IPs', config_JSON));
        return new Response(JSON.stringify({ success: true, message: '自定义IP已保存' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      } catch (error) {
        console.error('保存自定义IP失败:', error);
        return new Response(JSON.stringify({ error: '保存自定义IP失败: ' + error.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      }
    }

    return new Response(JSON.stringify({ error: '不支持的POST请求路径' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json;charset=utf-8' },
    });
  }

  // ── GET /admin/config.json — return config ────────────────
  if (访问路径 === 'admin/config.json') {
    return new Response(JSON.stringify(config_JSON, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  // ── GET /admin/ADD.txt — return local best IPs ────────────
  if (区分大小写访问路径 === 'admin/ADD.txt') {
    let 本地优选IP = await env.KV.get('ADD.txt') || 'null';
    if (本地优选IP === 'null') {
      // Lazy-import to avoid circular dependency at module level
      const { 生成随机IP } = await import('./best-ip.js');
      本地优选IP = (await 生成随机IP(
        request,
        config_JSON.优选订阅生成.本地IP库.随机数量,
        config_JSON.优选订阅生成.本地IP库.指定端口,
        config_JSON.协议类型 === 'ss' ? config_JSON.SS.TLS : true,
      ))[1];
    }
    return new Response(本地优选IP, {
      status: 200,
      headers: {
        'Content-Type': 'text/plain;charset=utf-8',
        'asn': String(request.cf?.asn ?? ''),
      },
    });
  }

  // ── GET /admin/cf.json — CF runtime info ──────────────────
  if (访问路径 === 'admin/cf.json') {
    return new Response(JSON.stringify(request.cf, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json;charset=utf-8' },
    });
  }

  // ── GET /admin — serve admin page ─────────────────────────
  ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Admin_Login', config_JSON));
  return fetch(Pages静态页面 + '/admin' + url.search);
}
