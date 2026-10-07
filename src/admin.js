import { MD5MD5 } from './utils/crypto.js';
import { 请求优选API, 生成随机IP } from './best-ip.js';
import { 获取SOCKS5账号, 获取代理默认端口 } from './proxy.js';
import { 创建请求TCP连接器 } from './tcp-connect.js';
import { socks5Connect, httpsConnect, httpConnect } from './proxy-connect.js';
import { turnConnect } from './proxy-turn.js';
import { sstpConnect } from './proxy-sstp.js';
import { isIPHostname } from './utils/address.js';
import { TlsClient } from './tls/client.js';
import { 拼接字节数据 } from './utils/bytes.js';
import { 读取config_JSON } from './config.js';
import { 请求日志记录 } from './logging.js';
import { Pages静态页面 } from './state.js';
export async function handleAdmin(request, url, env, UA, 管理员密码, 加密秘钥, userID, host, hosts, 访问IP, ctx) {
  const 访问路径 = url.pathname.slice(1).toLowerCase(),
    区分大小写访问路径 = url.pathname.slice(1);
  let config_JSON;
  //验证cookie后响应管理页面
  const cookies = request.headers.get('Cookie') || '';
  const authCookie = cookies
    .split(';')
    .find((c) => c.trim().startsWith('auth='))
    ?.split('=')[1];
  // 没有cookie或cookie错误，跳转到/login页面
  if (!authCookie || authCookie !== (await MD5MD5(UA + 加密秘钥 + 管理员密码)))
    return new Response('重定向中...', { status: 302, headers: { Location: '/login' } });
  if (区分大小写访问路径 === 'admin/getCloudflareUsage') {
    return new Response(JSON.stringify({ error: '不支持的请求路径' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json;charset=utf-8' },
    });
  }
  if (访问路径 === 'admin/log.json') {
    // 读取日志内容
    const 读取日志内容 = (await env.KV.get('log.json')) || '[]';
    return new Response(读取日志内容, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
  } else if (区分大小写访问路径 === 'admin/getADDAPI') {
    // 验证优选API
    if (url.searchParams.get('url')) {
      const 待验证优选URL = url.searchParams.get('url');
      try {
        new URL(待验证优选URL);
        const 请求优选API内容 = await 请求优选API([待验证优选URL], url.searchParams.get('port') || '443');
        let 优选API的IP = 请求优选API内容[0].length > 0 ? 请求优选API内容[0] : 请求优选API内容[1];
        优选API的IP = 优选API的IP.map((item) =>
          item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)),
        );
        return new Response(JSON.stringify({ success: true, data: 优选API的IP }, null, 2), {
          status: 200,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      } catch (err) {
        const errorResponse = { msg: '验证优选API失败，失败原因：', error: '操作失败' };
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
  } else if (访问路径 === 'admin/check') {
    // 代理检查
    const 代理协议 = ['socks5', 'http', 'https', 'turn', 'sstp'].find((类型) => url.searchParams.has(类型)) || null;
    if (!代理协议)
      return new Response(JSON.stringify({ error: '缺少代理参数' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json;charset=utf-8' },
      });
    const 代理参数 = url.searchParams.get(代理协议);
    const startTime = Date.now();
    let 检测代理响应;
    try {
      const checkParsed = await 获取SOCKS5账号(代理参数, 获取代理默认端口(代理协议));
      const { username, password, hostname, port } = checkParsed;
      const 完整代理参数 = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
      try {
        const 检测主机 = 'cloudflare.com',
          检测端口 = 443,
          encoder = new TextEncoder(),
          decoder = new TextDecoder();
        const TCP连接 = 创建请求TCP连接器(request);
        let tcpSocket = null,
          tlsSocket = null;
        try {
          tcpSocket =
            代理协议 === 'socks5'
              ? await socks5Connect(检测主机, 检测端口, new Uint8Array(0), TCP连接, checkParsed)
              : 代理协议 === 'turn'
                ? await turnConnect(checkParsed, 检测主机, 检测端口, TCP连接)
                : 代理协议 === 'sstp'
                  ? await sstpConnect(checkParsed, 检测主机, 检测端口, TCP连接)
                  : 代理协议 === 'https' && isIPHostname(hostname)
                    ? await httpsConnect(检测主机, 检测端口, new Uint8Array(0), TCP连接, checkParsed)
                    : await httpConnect(
                        检测主机,
                        检测端口,
                        new Uint8Array(0),
                        代理协议 === 'https',
                        TCP连接,
                        checkParsed,
                      );
          if (!tcpSocket) throw new Error('无法连接到代理服务器');
          tlsSocket = new TlsClient(tcpSocket, { serverName: 检测主机, insecure: true });
          await tlsSocket.handshake();
          await tlsSocket.write(
            encoder.encode(
              `GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${检测主机}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`,
            ),
          );
          let responseBuffer = new Uint8Array(0),
            headerEndIndex = -1,
            contentLength = null,
            chunked = false;
          const 最大响应字节 = 64 * 1024;
          while (responseBuffer.length < 最大响应字节) {
            const value = await tlsSocket.read();
            if (!value) break;
            if (value.byteLength === 0) continue;
            responseBuffer = 拼接字节数据(responseBuffer, value);
            if (headerEndIndex === -1) {
              const crlfcrlf = responseBuffer.findIndex(
                (_, i) =>
                  i < responseBuffer.length - 3 &&
                  responseBuffer[i] === 0x0d &&
                  responseBuffer[i + 1] === 0x0a &&
                  responseBuffer[i + 2] === 0x0d &&
                  responseBuffer[i + 3] === 0x0a,
              );
              if (crlfcrlf !== -1) {
                headerEndIndex = crlfcrlf + 4;
                const headers = decoder.decode(responseBuffer.slice(0, headerEndIndex));
                const statusLine = headers.split('\r\n')[0] || '';
                const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
                const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
                if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300)
                  throw new Error(`代理检测请求失败: ${statusLine || '无效响应'}`);
                const lengthMatch = headers.match(/\r\nContent-Length:\s*(\d+)/i);
                if (lengthMatch) contentLength = parseInt(lengthMatch[1], 10);
                chunked = /\r\nTransfer-Encoding:\s*chunked/i.test(headers);
              }
            }
            if (
              headerEndIndex !== -1 &&
              contentLength !== null &&
              responseBuffer.length >= headerEndIndex + contentLength
            )
              break;
            if (headerEndIndex !== -1 && chunked && decoder.decode(responseBuffer).includes('\r\n0\r\n\r\n')) break;
          }
          if (headerEndIndex === -1) throw new Error('代理检测响应头过长或无效');
          const response = decoder.decode(responseBuffer);
          const ip = response.match(/(?:^|\n)ip=(.*)/)?.[1];
          const loc = response.match(/(?:^|\n)loc=(.*)/)?.[1];
          if (!ip || !loc) throw new Error('代理检测响应无效');
          检测代理响应 = {
            success: true,
            proxy: 代理协议 + '://' + 完整代理参数,
            ip,
            loc,
            responseTime: Date.now() - startTime,
          };
        } finally {
          try {
            tlsSocket ? tlsSocket.close() : await tcpSocket?.close?.();
          } catch (e) {}
        }
      } catch (error) {
        检测代理响应 = {
          success: false,
          error: '操作失败',
          proxy: 代理协议 + '://' + 完整代理参数,
          responseTime: Date.now() - startTime,
        };
      }
    } catch (err) {
      检测代理响应 = {
        success: false,
        error: '操作失败',
        proxy: 代理协议 + '://' + 代理参数,
        responseTime: Date.now() - startTime,
      };
    }
    return new Response(JSON.stringify(检测代理响应, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json;charset=utf-8' },
    });
  }

  config_JSON = await 读取config_JSON(env, host, userID, UA);

  if (访问路径 === 'admin/init') {
    // 重置配置为默认值
    try {
      config_JSON = await 读取config_JSON(env, host, userID, UA, true);
      ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Init_Config', config_JSON));
      config_JSON.init = '配置已重置为默认值';
      return new Response(JSON.stringify(config_JSON, null, 2), {
        status: 200,
        headers: { 'Content-Type': 'application/json;charset=utf-8' },
      });
    } catch (err) {
      const errorResponse = { msg: '配置重置失败，失败原因：', error: '操作失败' };
      return new Response(JSON.stringify(errorResponse, null, 2), {
        status: 500,
        headers: { 'Content-Type': 'application/json;charset=utf-8' },
      });
    }
  } else if (request.method === 'POST') {
    // 处理 KV 操作（POST 请求）
    if (访问路径 === 'admin/config.json') {
      // 保存config.json配置
      try {
        const newConfig = await request.json();
        // 验证配置完整性
        if (!newConfig.UUID || !newConfig.HOST)
          return new Response(JSON.stringify({ error: '配置不完整' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json;charset=utf-8' },
          });

        // 保存到 KV
        await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
        ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
        return new Response(JSON.stringify({ success: true, message: '配置已保存' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      } catch (error) {
        console.error('保存配置失败:', error);
        return new Response(JSON.stringify({ error: '保存配置失败: ' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      }
    } else if (访问路径 === 'admin/cf.json') {
      // 保存cf.json配置
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

        // 保存到 KV
        await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
        ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
        return new Response(JSON.stringify({ success: true, message: '配置已保存' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      } catch (error) {
        console.error('保存配置失败:', error);
        return new Response(JSON.stringify({ error: '保存配置失败: ' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      }
    } else if (访问路径 === 'admin/tg.json') {
      // 保存tg.json配置
      try {
        const newConfig = await request.json();
        if (newConfig.init && newConfig.init === true) {
          const TG_JSON = { BotToken: null, ChatID: null };
          await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
        } else {
          if (!newConfig.BotToken || !newConfig.ChatID)
            return new Response(JSON.stringify({ error: '配置不完整' }), {
              status: 400,
              headers: { 'Content-Type': 'application/json;charset=utf-8' },
            });
          await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
        }
        ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
        return new Response(JSON.stringify({ success: true, message: '配置已保存' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      } catch (error) {
        console.error('保存配置失败:', error);
        return new Response(JSON.stringify({ error: '保存配置失败: ' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      }
    } else if (区分大小写访问路径 === 'admin/ADD.txt') {
      // 保存自定义优选IP
      try {
        const customIPs = await request.text();
        await env.KV.put('ADD.txt', customIPs); // 保存到 KV
        ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Custom_IPs', config_JSON));
        return new Response(JSON.stringify({ success: true, message: '自定义IP已保存' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      } catch (error) {
        console.error('保存自定义IP失败:', error);
        return new Response(JSON.stringify({ error: '保存自定义IP失败: ' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json;charset=utf-8' },
        });
      }
    } else
      return new Response(JSON.stringify({ error: '不支持的POST请求路径' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json;charset=utf-8' },
      });
  } else if (访问路径 === 'admin/config.json') {
    // 处理 admin/config.json 请求，返回JSON
    return new Response(JSON.stringify(config_JSON, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } else if (区分大小写访问路径 === 'admin/ADD.txt') {
    // 处理 admin/ADD.txt 请求，返回本地优选IP
    let 本地优选IP = (await env.KV.get('ADD.txt')) || 'null';
    if (本地优选IP == 'null')
      本地优选IP = (
        await 生成随机IP(
          request,
          config_JSON.优选订阅生成.本地IP库.随机数量,
          config_JSON.优选订阅生成.本地IP库.指定端口,
        )
      )[1];
    return new Response(本地优选IP, {
      status: 200,
      headers: { 'Content-Type': 'text/plain;charset=utf-8', asn: request.cf.asn },
    });
  } else if (访问路径 === 'admin/cf.json') {
    // CF配置文件
    return new Response(JSON.stringify(request.cf, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json;charset=utf-8' },
    });
  }

  ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Admin_Login', config_JSON));
  return fetch(Pages静态页面 + '/admin' + url.search);
}
