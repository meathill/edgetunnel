/**
 * TCP/UDP forwarding and stream management.
 *
 * Handles direct connections, proxy fallback, connection retries,
 * speed-test blocking, and bidirectional WebSocket-to-TCP stream piping
 * with BYOB read optimization.
 */

import { connect } from 'cloudflare:sockets';
import { state } from './state.js';
import { log } from './utils/log.js';
import { socks5Connect, httpConnect } from './proxy.js';
import { 解析地址端口 } from './dns.js';
import { 整理成数组 } from './utils/format.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Return the byte-length of `data`, or 0 if data is falsy.
 */
function 有效数据长度(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

/**
 * Check whether `hostname` is a known speed-test domain that should be
 * blocked from proxying.
 */
export function isSpeedTestSite(hostname) {
	const speedTestDomains = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')];
	if (speedTestDomains.includes(hostname)) {
		return true;
	}

	for (const domain of speedTestDomains) {
		if (hostname.endsWith('.' + domain) || hostname === domain) {
			return true;
		}
	}
	return false;
}

// ---------------------------------------------------------------------------
// Socket / WebSocket utilities
// ---------------------------------------------------------------------------

/**
 * Safely close a WebSocket without throwing.
 */
export function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}

/**
 * Send `payload` over a WebSocket, awaiting the result if the
 * implementation returns a thenable.
 */
export async function WebSocket发送并等待(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

// ---------------------------------------------------------------------------
// Bidirectional stream piping
// ---------------------------------------------------------------------------

/**
 * Pipe data from `remoteSocket.readable` into `webSocket`, prepending
 * `headerData` to the first chunk.  Uses BYOB reads when supported for
 * better throughput.  If no data was received and `retryFunc` is provided
 * it will be called (used for proxy fallback).
 */
export async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
	let header = headerData, hasData = false, reader, useBYOB = false;
	const BYOB缓冲区大小 = 512 * 1024, BYOB单次读取上限 = 64 * 1024, BYOB高吞吐阈值 = 50 * 1024 * 1024;
	const BYOB慢速刷新间隔 = 20, BYOB快速刷新间隔 = 2, BYOB安全阈值 = BYOB缓冲区大小 - BYOB单次读取上限;

	const 发送块 = async (chunk) => {
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		if (header) {
			const merged = new Uint8Array(header.length + chunk.byteLength);
			merged.set(header, 0); merged.set(chunk, header.length);
			await WebSocket发送并等待(webSocket, merged.buffer);
			header = null;
		} else await WebSocket发送并等待(webSocket, chunk);
	};

	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }
	catch (e) { reader = remoteSocket.readable.getReader() }

	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				await 发送块(value instanceof Uint8Array ? value : new Uint8Array(value));
			}
		} else {
			let mainBuf = new ArrayBuffer(BYOB缓冲区大小), offset = 0, totalBytes = 0;
			let flush间隔毫秒 = BYOB快速刷新间隔, flush定时器 = null, 等待刷新恢复 = null;
			let 正在读取 = false, 读取中待刷新 = false;

			const flush = async () => {
				if (正在读取) { 读取中待刷新 = true; return }
				try {
					if (offset > 0) { const p = new Uint8Array(mainBuf.slice(0, offset)); offset = 0; await 发送块(p) }
				} finally {
					读取中待刷新 = false;
					if (flush定时器) { clearTimeout(flush定时器); flush定时器 = null }
					if (等待刷新恢复) { const r = 等待刷新恢复; 等待刷新恢复 = null; r() }
				}
			};

			while (true) {
				正在读取 = true;
				const { done, value } = await reader.read(new Uint8Array(mainBuf, offset, BYOB单次读取上限));
				正在读取 = false;
				if (done) break;
				if (!value || value.byteLength === 0) { if (读取中待刷新) await flush(); continue }
				hasData = true;
				mainBuf = value.buffer;
				const len = value.byteLength;

				if (value.byteOffset !== offset) {
					log(`[BYOB] 偏移异常: 预期=${offset}, 实际=${value.byteOffset}`);
					await 发送块(new Uint8Array(value.buffer, value.byteOffset, len).slice());
					mainBuf = new ArrayBuffer(BYOB缓冲区大小); offset = 0; totalBytes = 0;
					continue;
				}

				if (len < BYOB单次读取上限) {
					flush间隔毫秒 = BYOB快速刷新间隔;
					if (len < 4096) totalBytes = 0;
					if (offset > 0) { offset += len; await flush() }
					else await 发送块(value.slice());
				} else {
					totalBytes += len; offset += len;
					if (!flush定时器) flush定时器 = setTimeout(() => { flush().catch(() => closeSocketQuietly(webSocket)) }, flush间隔毫秒);
					if (读取中待刷新) await flush();
					if (offset > BYOB安全阈值) {
						if (totalBytes > BYOB高吞吐阈值) flush间隔毫秒 = BYOB慢速刷新间隔;
						await new Promise(r => { 等待刷新恢复 = r });
					}
				}
			}
			正在读取 = false;
			await flush();
			if (flush定时器) { clearTimeout(flush定时器); flush定时器 = null }
		}
	} catch (err) { closeSocketQuietly(webSocket) }
	finally { try { reader.cancel() } catch (e) { } try { reader.releaseLock() } catch (e) { } }
	if (!hasData && retryFunc) await retryFunc();
}

// ---------------------------------------------------------------------------
// TCP forwarding
// ---------------------------------------------------------------------------

/**
 * Main TCP forwarding function.
 *
 * Handles direct connections, SOCKS5/HTTP/HTTPS proxy, proxy-IP round-robin
 * fallback, connection retries, and speed-test domain blocking.
 */
export async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID) {
	const { 反代IP, 启用反代兜底, 启用SOCKS5反代, 启用SOCKS5全局反代, SOCKS5白名单 } = state;
	log(`[TCP转发] 目标: ${host}:${portNum} | 反代IP: ${反代IP} | 反代兜底: ${启用反代兜底 ? '是' : '否'} | 反代类型: ${启用SOCKS5反代 || 'proxyip'} | 全局: ${启用SOCKS5全局反代 ? '是' : '否'}`);
	const 连接超时毫秒 = 1000;
	let 已通过代理发送首包 = false;

	async function 等待连接建立(remoteSock, timeoutMs = 连接超时毫秒) {
		await Promise.race([
			remoteSock.opened,
			new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), timeoutMs))
		]);
	}

	async function connectDirect(address, port, data = null, 所有反代数组 = null, 反代兜底 = true) {
		let remoteSock;
		if (所有反代数组 && 所有反代数组.length > 0) {
			for (let i = 0; i < 所有反代数组.length; i++) {
				const 反代数组索引 = (state.缓存反代数组索引 + i) % 所有反代数组.length;
				const [反代地址, 反代端口] = 所有反代数组[反代数组索引];
				try {
					log(`[反代连接] 尝试连接到: ${反代地址}:${反代端口} (索引: ${反代数组索引})`);
					remoteSock = connect({ hostname: 反代地址, port: 反代端口 });
					await 等待连接建立(remoteSock);
					if (有效数据长度(data) > 0) {
						const testWriter = remoteSock.writable.getWriter();
						await testWriter.write(data);
						testWriter.releaseLock();
					}
					log(`[反代连接] 成功连接到: ${反代地址}:${反代端口}`);
					state.缓存反代数组索引 = 反代数组索引;
					return remoteSock;
				} catch (err) {
					log(`[反代连接] 连接失败: ${反代地址}:${反代端口}, 错误: ${err.message}`);
					try { remoteSock?.close?.() } catch (e) { }
					continue;
				}
			}
		}

		if (反代兜底) {
			remoteSock = connect({ hostname: address, port: port });
			await 等待连接建立(remoteSock);
			if (有效数据长度(data) > 0) {
				const writer = remoteSock.writable.getWriter();
				await writer.write(data);
				writer.releaseLock();
			}
			return remoteSock;
		} else {
			closeSocketQuietly(ws);
			throw new Error('[反代连接] 所有反代连接失败，且未启用反代兜底，连接终止。');
		}
	}

	async function connecttoPry(允许发送首包 = true) {
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}

		const 本次发送首包 = 允许发送首包 && !已通过代理发送首包 && 有效数据长度(rawData) > 0;
		const 本次首包数据 = 本次发送首包 ? rawData : null;

		const 当前连接任务 = (async () => {
			let newSocket;
			if (启用SOCKS5反代 === 'socks5') {
				log(`[SOCKS5代理] 代理到: ${host}:${portNum}`);
				newSocket = await socks5Connect(host, portNum, 本次首包数据, 有效数据长度);
			} else if (启用SOCKS5反代 === 'http') {
				log(`[HTTP代理] 代理到: ${host}:${portNum}`);
				newSocket = await httpConnect(host, portNum, 本次首包数据, false, 有效数据长度);
			} else if (启用SOCKS5反代 === 'https') {
				log(`[HTTPS代理] 代理到: ${host}:${portNum}`);
				newSocket = await httpConnect(host, portNum, 本次首包数据, true, 有效数据长度);
			} else {
				log(`[反代连接] 代理到: ${host}:${portNum}`);
				const 所有反代数组 = await 解析地址端口(反代IP, host, yourUUID, 整理成数组);
				newSocket = await connectDirect(atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='), 1, 本次首包数据, 所有反代数组, 启用反代兜底);
			}
			if (本次发送首包) 已通过代理发送首包 = true;
			remoteConnWrapper.socket = newSocket;
			newSocket.closed.catch(() => { }).finally(() => closeSocketQuietly(ws));
			connectStreams(newSocket, ws, respHeader, null);
		})();

		remoteConnWrapper.connectingPromise = 当前连接任务;
		try {
			await 当前连接任务;
		} finally {
			if (remoteConnWrapper.connectingPromise === 当前连接任务) {
				remoteConnWrapper.connectingPromise = null;
			}
		}
	}
	remoteConnWrapper.retryConnect = async () => connecttoPry(!已通过代理发送首包);

	const 验证SOCKS5白名单 = (addr) => SOCKS5白名单.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(addr));
	if (启用SOCKS5反代 && (启用SOCKS5全局反代 || 验证SOCKS5白名单(host))) {
		log(`[TCP转发] 启用 SOCKS5/HTTP/HTTPS 全局代理`);
		try {
			await connecttoPry();
		} catch (err) {
			log(`[TCP转发] SOCKS5/HTTP/HTTPS 代理连接失败: ${err.message}`);
			throw err;
		}
	} else {
		try {
			log(`[TCP转发] 尝试直连到: ${host}:${portNum}`);
			const initialSocket = await connectDirect(host, portNum, rawData);
			remoteConnWrapper.socket = initialSocket;
			connectStreams(initialSocket, ws, respHeader, async () => {
				if (remoteConnWrapper.socket !== initialSocket) return;
				await connecttoPry();
			});
		} catch (err) {
			log(`[TCP转发] 直连 ${host}:${portNum} 失败: ${err.message}`);
			await connecttoPry();
		}
	}
}

// ---------------------------------------------------------------------------
// UDP forwarding
// ---------------------------------------------------------------------------

/**
 * Forward a single UDP chunk (DNS query) by piping it through a TCP
 * connection to 8.8.4.4:53, then streaming the response back over the
 * WebSocket.
 */
export async function forwardataudp(udpChunk, webSocket, respHeader) {
	try {
		const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(udpChunk);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				if (webSocket.readyState === WebSocket.OPEN) {
					if (vlessHeader) {
						const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
						response.set(vlessHeader, 0);
						response.set(chunk, vlessHeader.length);
						await WebSocket发送并等待(webSocket, response.buffer);
						vlessHeader = null;
					} else {
						await WebSocket发送并等待(webSocket, chunk);
					}
				}
			},
		}));
	} catch (error) {
		// console.error('UDP forward error:', error);
	}
}
