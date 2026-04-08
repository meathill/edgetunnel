import { connect } from 'cloudflare:sockets';
import { state } from './state.js';
import { log } from './utils/log.js';

/**
 * Establish a SOCKS5 tunnel to the target host through the proxy
 * configured in `state.parsedSocks5Address`.
 *
 * @param {string} targetHost
 * @param {number} targetPort
 * @param {Uint8Array|ArrayBuffer|null} initialData - Data to send immediately after the handshake.
 * @param {(data: any) => number} 有效数据长度 - Helper that returns the byte length of valid data.
 * @returns {Promise<import('cloudflare:sockets').Socket>}
 */
export async function socks5Connect(targetHost, targetPort, initialData, 有效数据长度) {
	const { username, password, hostname, port } = state.parsedSocks5Address;
	const socket = connect({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	try {
		const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);
		let response = await reader.read();
		if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');

		const selectedMethod = new Uint8Array(response.value)[1];
		if (selectedMethod === 0x02) {
			if (!username || !password) throw new Error('S5 requires authentication');
			const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
			const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
			await writer.write(authPacket);
			response = await reader.read();
			if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
		} else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

		const hostBytes = new TextEncoder().encode(targetHost);
		const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
		await writer.write(connectPacket);
		response = await reader.read();
		if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');

		if (有效数据长度(initialData) > 0) await writer.write(initialData);
		writer.releaseLock(); reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

/**
 * Establish an HTTP(S) CONNECT tunnel to the target host through the proxy
 * configured in `state.parsedSocks5Address`.
 *
 * @param {string} targetHost
 * @param {number} targetPort
 * @param {Uint8Array|ArrayBuffer|null} initialData - Data to send after tunnel is established.
 * @param {boolean} [HTTPS代理=false] - Use TLS for the proxy connection itself.
 * @param {(data: any) => number} 有效数据长度 - Helper that returns the byte length of valid data.
 * @returns {Promise<import('cloudflare:sockets').Socket | { readable: ReadableStream, writable: WritableStream, closed: Promise<void>, close: () => void }>}
 */
export async function httpConnect(targetHost, targetPort, initialData, HTTPS代理 = false, 有效数据长度) {
	const { username, password, hostname, port } = state.parsedSocks5Address;
	const socket = HTTPS代理
		? connect({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
		: connect({ hostname, port });
	const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	try {
		if (HTTPS代理) await socket.opened;

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done || !value) throw new Error(`${HTTPS代理 ? 'HTTPS' : 'HTTP'} 代理在返回 CONNECT 响应前关闭连接`);
			responseBuffer = new Uint8Array([...responseBuffer, ...value]);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('代理 CONNECT 响应头过长或无效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		reader.releaseLock();

		if (有效数据长度(initialData) > 0) {
			const 远端写入器 = socket.writable.getWriter();
			await 远端写入器.write(initialData);
			远端写入器.releaseLock();
		}

		// CONNECT 响应头后可能夹带隧道数据，先回灌到可读流，避免首包被吞。
		if (bytesRead > headerEndIndex) {
			const { readable, writable } = new TransformStream();
			const transformWriter = writable.getWriter();
			await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
			transformWriter.releaseLock();
			socket.readable.pipeTo(writable).catch(() => { });
			return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
		}

		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

/**
 * Regex for detecting Base64-encoded SOCKS5 credentials.
 * @type {RegExp}
 */
const SOCKS5账号Base64正则 = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;

/**
 * Regex for detecting IPv6 addresses wrapped in brackets.
 * @type {RegExp}
 */
const IPv6方括号正则 = /^\[.*\]$/;

/**
 * Parse a SOCKS5 / HTTP proxy address string into its components.
 *
 * Supports formats like:
 *   - `host:port`
 *   - `user:pass@host:port`
 *   - `base64credentials@[ipv6]:port`
 *
 * @param {string} address - Raw proxy address string.
 * @param {number} [默认端口=80] - Default port when none is specified.
 * @returns {{ username: string|undefined, password: string|undefined, hostname: string, port: number }}
 */
export function 获取SOCKS5账号(address, 默认端口 = 80) {
	const firstAt = address.lastIndexOf("@");
	if (firstAt !== -1) {
		let auth = address.slice(0, firstAt).replaceAll("%3D", "=");
		if (!auth.includes(":") && SOCKS5账号Base64正则.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(firstAt + 1)}`;
	}

	const atIndex = address.lastIndexOf("@");
	const hostPart = atIndex === -1 ? address : address.slice(atIndex + 1);
	const authPart = atIndex === -1 ? "" : address.slice(0, atIndex);
	const [username, password] = authPart ? authPart.split(":") : [];
	if (authPart && !password) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');

	let hostname = hostPart, port = 默认端口;
	if (hostPart.includes("]:")) {
		const [ipv6Host, ipv6Port = ""] = hostPart.split("]:");
		hostname = ipv6Host + "]";
		port = Number(ipv6Port.replace(/[^\d]/g, ""));
	} else if (!hostPart.startsWith("[")) {
		const parts = hostPart.split(":");
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ""));
		}
	}

	if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
	if (hostname.includes(":") && !IPv6方括号正则.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
	return { username, password, hostname, port };
}

/**
 * Detect and parse proxy parameters from the incoming request URL.
 *
 * Mutates `state.反代IP`, `state.启用SOCKS5反代`, `state.启用SOCKS5全局反代`,
 * `state.我的SOCKS5账号`, `state.parsedSocks5Address`, and `state.启用反代兜底`.
 *
 * @param {URL} url - The incoming request URL.
 * @returns {Promise<void>}
 */
export async function 反代参数获取(url) {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();

	state.我的SOCKS5账号 = searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || null;
	state.启用SOCKS5全局反代 = searchParams.has('globalproxy');
	if (searchParams.get('socks5')) state.启用SOCKS5反代 = 'socks5';
	else if (searchParams.get('http')) state.启用SOCKS5反代 = 'http';
	else if (searchParams.get('https')) state.启用SOCKS5反代 = 'https';

	const 解析代理URL = (值, 强制全局 = true) => {
		const 匹配 = /^(socks5|http|https):\/\/(.+)$/i.exec(值 || '');
		if (!匹配) return false;
		state.启用SOCKS5反代 = 匹配[1].toLowerCase();
		state.我的SOCKS5账号 = 匹配[2].split('/')[0];
		if (强制全局) state.启用SOCKS5全局反代 = true;
		return true;
	};

	const 设置反代IP = (值) => {
		state.反代IP = 值;
		state.启用反代兜底 = false;
	};

	const 提取路径值 = (值) => {
		if (!值.includes('://')) {
			const 斜杠索引 = 值.indexOf('/');
			return 斜杠索引 > 0 ? 值.slice(0, 斜杠索引) : 值;
		}
		const 协议拆分 = 值.split('://');
		if (协议拆分.length !== 2) return 值;
		const 斜杠索引 = 协议拆分[1].indexOf('/');
		return 斜杠索引 > 0 ? `${协议拆分[0]}://${协议拆分[1].slice(0, 斜杠索引)}` : 值;
	};

	const 查询反代IP = searchParams.get('proxyip');
	if (查询反代IP !== null) {
		if (!解析代理URL(查询反代IP)) return 设置反代IP(查询反代IP);
	} else {
		let 匹配 = /\/(socks5?|http|https):\/?\/?([^/?#\s]+)/i.exec(pathname);
		if (匹配) {
			const 类型 = 匹配[1].toLowerCase();
			state.启用SOCKS5反代 = 类型 === 'http' ? 'http' : (类型 === 'https' ? 'https' : 'socks5');
			state.我的SOCKS5账号 = 匹配[2].split('/')[0];
			state.启用SOCKS5全局反代 = true;
		} else if ((匹配 = /\/(g?s5|socks5|g?http|g?https)=([^/?#\s]+)/i.exec(pathname))) {
			const 类型 = 匹配[1].toLowerCase();
			state.我的SOCKS5账号 = 匹配[2].split('/')[0];
			state.启用SOCKS5反代 = 类型.includes('https') ? 'https' : (类型.includes('http') ? 'http' : 'socks5');
			if (类型.startsWith('g')) state.启用SOCKS5全局反代 = true;
		} else if ((匹配 = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
			const 路径反代值 = 提取路径值(匹配[2]);
			if (!解析代理URL(路径反代值)) return 设置反代IP(路径反代值);
		}
	}

	if (!state.我的SOCKS5账号) {
		state.启用SOCKS5反代 = null;
		return;
	}

	try {
		state.parsedSocks5Address = await 获取SOCKS5账号(state.我的SOCKS5账号, state.启用SOCKS5反代 === 'https' ? 443 : 80);
		if (searchParams.get('socks5')) state.启用SOCKS5反代 = 'socks5';
		else if (searchParams.get('http')) state.启用SOCKS5反代 = 'http';
		else if (searchParams.get('https')) state.启用SOCKS5反代 = 'https';
		else state.启用SOCKS5反代 = state.启用SOCKS5反代 || 'socks5';
	} catch (err) {
		console.error('解析SOCKS5地址失败:', err.message);
		state.启用SOCKS5反代 = null;
	}
}

/**
 * Verify that a SOCKS5 / HTTP / HTTPS proxy is reachable by opening a
 * test connection through it.
 *
 * @param {string} [代理协议='socks5'] - Protocol: 'socks5', 'http', or 'https'.
 * @param {string} 代理参数 - Raw proxy address (user:pass@host:port).
 * @param {(data: any) => number} 有效数据长度 - Helper that returns the byte length of valid data.
 * @returns {Promise<{ success: boolean, error?: string, proxy: string, ip?: string, loc?: string, responseTime: number }>}
 */
export async function SOCKS5可用性验证(代理协议 = 'socks5', 代理参数, 有效数据长度) {
	const startTime = Date.now();
	try { state.parsedSocks5Address = await 获取SOCKS5账号(代理参数, 代理协议 === 'https' ? 443 : 80) } catch (err) { return { success: false, error: err.message, proxy: 代理协议 + "://" + 代理参数, responseTime: Date.now() - startTime } }
	const { username, password, hostname, port } = state.parsedSocks5Address;
	const 完整代理参数 = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
	try {
		const initialData = new Uint8Array(0);
		const tcpSocket = 代理协议 === 'socks5'
			? await socks5Connect('check.socks5.090227.xyz', 80, initialData, 有效数据长度)
			: (代理协议 === 'https'
				? await httpConnect('check.socks5.090227.xyz', 80, initialData, true, 有效数据长度)
				: await httpConnect('check.socks5.090227.xyz', 80, initialData, false, 有效数据长度));
		if (!tcpSocket) return { success: false, error: '无法连接到代理服务器', proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime };
		try {
			const writer = tcpSocket.writable.getWriter(), encoder = new TextEncoder();
			await writer.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: check.socks5.090227.xyz\r\nConnection: close\r\n\r\n`));
			writer.releaseLock();
			const reader = tcpSocket.readable.getReader(), decoder = new TextDecoder();
			let response = '';
			try { while (true) { const { done, value } = await reader.read(); if (done) break; response += decoder.decode(value, { stream: true }) } } finally { reader.releaseLock() }
			await tcpSocket.close();
			return { success: true, proxy: 代理协议 + "://" + 完整代理参数, ip: response.match(/ip=(.*)/)[1], loc: response.match(/loc=(.*)/)[1], responseTime: Date.now() - startTime };
		} catch (error) {
			try { await tcpSocket.close() } catch (e) { log('关闭连接时出错:', e) }
			return { success: false, error: error.message, proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime };
		}
	} catch (error) { return { success: false, error: error.message, proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime } }
}
