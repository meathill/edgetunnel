import { MD5MD5 } from './utils/crypto.js';
import { 整理成数组 } from './utils/format.js';
import { 获取请求设置, 特征码字典, Version, Pages静态页面 } from './state.js';
import { 创建日志器 } from './utils/log.js';
import { 反代参数获取 } from './proxy.js';
import { 处理WS请求 } from './handler-ws.js';
import { 获取叉HTTPPadding标识 } from './xhttp-padding.js';
import { 处理gRPC请求 } from './handler-grpc.js';
import { 处理叉HTTP请求 } from './handler-xhttp.js';
import { handleAdmin } from './admin.js';
import { handleSubscription } from './subscription/index.js';
import { html1101, nginx } from './templates.js';
export default {
  async fetch(request, env, ctx) {
    let 请求URL文本 = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
    const 请求URL锚点索引 = 请求URL文本.indexOf('#');
    const 请求URL主体部分 = 请求URL锚点索引 === -1 ? 请求URL文本 : 请求URL文本.slice(0, 请求URL锚点索引);
    if (!请求URL主体部分.includes('?') && /%3f/i.test(请求URL主体部分)) {
      const 请求URL锚点部分 = 请求URL锚点索引 === -1 ? '' : 请求URL文本.slice(请求URL锚点索引);
      请求URL文本 = 请求URL主体部分.replace(/%3f/i, '?') + 请求URL锚点部分;
    }
    const url = new URL(请求URL文本);
    const UA = request.headers.get('User-Agent') || 'null';
    const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(),
      contentType = (request.headers.get('content-type') || '').toLowerCase();
    const 管理员密码 =
      env.ADMIN ||
      env.admin ||
      env.PASSWORD ||
      env.password ||
      env.pswd ||
      env.TOKEN ||
      env.KEY ||
      env.UUID ||
      env.uuid;
    const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
    const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
    const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
    const envUUID = env.UUID || env.uuid;
    const userID =
      envUUID && uuidRegex.test(envUUID)
        ? envUUID.toLowerCase()
        : [
            userIDMD5.slice(0, 8),
            userIDMD5.slice(8, 12),
            '4' + userIDMD5.slice(13, 16),
            '8' + userIDMD5.slice(17, 20),
            userIDMD5.slice(20),
          ].join('-');
    const hosts = env.HOST
      ? (await 整理成数组(env.HOST)).map(
          (h) =>
            h
              .toLowerCase()
              .replace(/^https?:\/\//, '')
              .split('/')[0]
              .split(':')[0],
        )
      : [url.hostname];
    const host = hosts[0];
    const 访问路径 = url.pathname.slice(1).toLowerCase();
    const 请求设置 = 获取请求设置(env, request);
    const log = 创建日志器(请求设置.调试日志打印);
    let 默认反代IP = `${request.cf?.colo || 'NRT'}.${特征码字典[0]}.${特征码字典[1]}SsSs.nEt`.toLowerCase(),
      默认反代兜底 = true;
    if (env.PROXYIP) {
      const proxyIPs = await 整理成数组(env.PROXYIP);
      默认反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
      默认反代兜底 = false;
    }
    const 访问IP =
      request.headers.get('CF-Connecting-IP') ||
      request.headers.get('True-Client-IP') ||
      request.headers.get('X-Real-IP') ||
      request.headers.get('X-Forwarded-For') ||
      request.headers.get('Fly-Client-IP') ||
      request.headers.get('X-Appengine-Remote-Addr') ||
      request.headers.get('X-Cluster-Client-IP') ||
      '未知IP';
    if (访问路径 === 'version') {
      if ((url.searchParams.get('uuid') || '').toLowerCase() === userID)
        return new Response(JSON.stringify({ Version: Number(String(Version).replace(/\D+/g, '')) }), {
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
    } else if (管理员密码 && upgradeHeader === 'websocket') {
      // WebSocket代理
      const 反代上下文 = { ...(await 反代参数获取(url, userID, 默认反代IP, 默认反代兜底)), ...请求设置 };
      log(`[WebSocket] 命中请求: ${url.pathname}${url.search}`);
      return await 处理WS请求(request, userID, url, 反代上下文);
    } else if (管理员密码 && !访问路径.startsWith('admin/') && 访问路径 !== 'login' && request.method === 'POST') {
      // gRPC/叉HTTP代理
      const 反代上下文 = { ...(await 反代参数获取(url, userID, 默认反代IP, 默认反代兜底)), ...请求设置 };
      const { 头: 本机Padding头, 键: 本机Padding键 } = 获取叉HTTPPadding标识(userID);
      const 命中叉HTTP特征 = !!request.headers.get(本机Padding头) || !!url.searchParams.get(本机Padding键);
      if (!命中叉HTTP特征 && contentType.startsWith('application/grpc')) {
        log(`[gRPC] 命中请求: ${url.pathname}${url.search}`);
        return await 处理gRPC请求(request, userID, 反代上下文);
      }
      log(`[叉HTTP] 命中请求: ${url.pathname}${url.search}`);
      return await 处理叉HTTP请求(request, userID, 反代上下文);
    } else {
      if (url.protocol === 'http:')
        return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
      if (!管理员密码)
        return fetch(Pages静态页面 + '/noADMIN').then((r) => {
          const headers = new Headers(r.headers);
          headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
          headers.set('Pragma', 'no-cache');
          headers.set('Expires', '0');
          return new Response(r.body, { status: 404, statusText: r.statusText, headers });
        });
      if (env.KV && typeof env.KV.get === 'function') {
        const 区分大小写访问路径 = url.pathname.slice(1);
        if (区分大小写访问路径 === 加密秘钥 && 加密秘钥 !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {
          //快速订阅
          const params = new URLSearchParams(url.search);
          params.set('token', await MD5MD5(host + userID));
          return new Response('重定向中...', { status: 302, headers: { Location: `/sub?${params.toString()}` } });
        } else if (访问路径 === 'login') {
          //处理登录页面和登录请求
          const cookies = request.headers.get('Cookie') || '';
          const authCookie = cookies
            .split(';')
            .find((c) => c.trim().startsWith('auth='))
            ?.split('=')[1];
          if (authCookie === (await MD5MD5(UA + 加密秘钥 + 管理员密码)))
            return new Response('重定向中...', { status: 302, headers: { Location: '/admin' } });
          if (request.method === 'POST') {
            const formData = await request.text();
            const params = new URLSearchParams(formData);
            const 输入密码 = params.get('password');
            if (输入密码 === (typeof 管理员密码 === 'string' ? 管理员密码.replace(/[\r\n]/g, '') : 管理员密码)) {
              // 密码正确，设置cookie并返回成功标记
              const 响应 = new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers: { 'Content-Type': 'application/json;charset=utf-8' },
              });
              响应.headers.set(
                'Set-Cookie',
                `auth=${await MD5MD5(UA + 加密秘钥 + 管理员密码)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`,
              );
              return 响应;
            }
          }
          return fetch(Pages静态页面 + '/login');
        } else if (访问路径 === 'admin' || 访问路径.startsWith('admin/')) {
          return await handleAdmin(request, url, env, UA, 管理员密码, 加密秘钥, userID, host, hosts, 访问IP, ctx);
        } else if (访问路径 === 'logout' || uuidRegex.test(访问路径)) {
          //清除cookie并跳转到登录页面
          const 响应 = new Response('重定向中...', { status: 302, headers: { Location: '/login' } });
          响应.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
          return 响应;
        } else if (访问路径 === 'sub') {
          const response = await handleSubscription(request, url, env, userID, host, UA, 访问IP, ctx);
          if (response) return response;
        } else if (访问路径 === 'locations') {
          //反代locations列表
          const cookies = request.headers.get('Cookie') || '';
          const authCookie = cookies
            .split(';')
            .find((c) => c.trim().startsWith('auth='))
            ?.split('=')[1];
          if (authCookie && authCookie === (await MD5MD5(UA + 加密秘钥 + 管理员密码)))
            return fetch(
              new Request('https://speed.cloudflare.com/locations', {
                headers: { Referer: 'https://speed.cloudflare.com/' },
              }),
            );
        } else if (访问路径 === 'robots.txt')
          return new Response('User-agent: *\nDisallow: /', {
            status: 200,
            headers: { 'Content-Type': 'text/plain; charset=UTF-8' },
          });
      } else if (!envUUID)
        return fetch(Pages静态页面 + '/noKV').then((r) => {
          const headers = new Headers(r.headers);
          headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
          headers.set('Pragma', 'no-cache');
          headers.set('Expires', '0');
          return new Response(r.body, { status: 404, statusText: r.statusText, headers });
        });
    }

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
    if (伪装页URL === '1101')
      return new Response(await html1101(url.host, 访问IP), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=UTF-8' },
      });
    try {
      const 反代URL = new URL(伪装页URL),
        新请求头 = new Headers(request.headers);
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
      // 只处理文本类型的响应
      if (/text|javascript|json|xml/.test(内容类型)) {
        const 响应内容 = (await 反代响应.text()).replaceAll(反代URL.host, url.host);
        return new Response(响应内容, {
          status: 反代响应.status,
          headers: { ...Object.fromEntries(反代响应.headers), 'Cache-Control': 'no-store' },
        });
      }
      return 反代响应;
    } catch (error) {}
    return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
  },
};
