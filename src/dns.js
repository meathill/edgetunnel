import { state } from './state.js';
import { log } from './utils/log.js';

/**
 * @typedef {{ name: string, type: number, TTL: number, data: string, rdata: Uint8Array }} DnsAnswer
 */

/**
 * Perform a DNS-over-HTTPS query using the binary dns-message wire format.
 *
 * @param {string} 域名 - Domain name to query.
 * @param {string} 记录类型 - Record type string (A, AAAA, TXT, CNAME, HTTPS, etc.).
 * @param {string} [DoH解析服务="https://cloudflare-dns.com/dns-query"] - DoH endpoint URL.
 * @returns {Promise<DnsAnswer[]>}
 */
export async function DoH查询(域名, 记录类型, DoH解析服务 = "https://cloudflare-dns.com/dns-query") {
	const 开始时间 = performance.now();
	log(`[DoH查询] 开始查询 ${域名} ${记录类型} via ${DoH解析服务}`);
	try {
		// 记录类型字符串转数值
		const 类型映射 = { 'A': 1, 'NS': 2, 'CNAME': 5, 'MX': 15, 'TXT': 16, 'AAAA': 28, 'SRV': 33, 'HTTPS': 65 };
		const qtype = 类型映射[记录类型.toUpperCase()] || 1;

		// 编码域名为 DNS wire format labels
		const 编码域名 = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0);
			const result = new Uint8Array(total);
			let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length }
			return result;
		};

		// 构建 DNS 查询报文
		const qname = 编码域名(域名);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, 0);       // ID
		qview.setUint16(2, 0x0100);  // Flags: RD=1 (递归查询)
		qview.setUint16(4, 1);       // QDCOUNT
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

		// 通过 POST 发送 dns-message 请求
		log(`[DoH查询] 发送查询报文 ${域名} via ${DoH解析服务} (type=${qtype}, ${query.length}字节)`);
		const response = await fetch(DoH解析服务, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/dns-message',
				'Accept': 'application/dns-message',
			},
			body: query,
		});
		if (!response.ok) {
			console.warn(`[DoH查询] 请求失败 ${域名} ${记录类型} via ${DoH解析服务} 响应代码:${response.status}`);
			return [];
		}

		// 解析 DNS 响应报文
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		log(`[DoH查询] 收到响应 ${域名} ${记录类型} via ${DoH解析服务} (${buf.length}字节, ${ancount}条应答)`);

		// 解析域名（处理指针压缩）
		const 解析域名 = (pos) => {
			const labels = [];
			let p = pos, jumped = false, endPos = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) endPos = p + 1; break }
				if ((len & 0xC0) === 0xC0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3F) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join('.'), endPos];
		};

		// 跳过 Question Section
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = 解析域名(offset);
			offset = /** @type {number} */ (end) + 4; // +4 跳过 QTYPE + QCLASS
		}

		// 解析 Answer Section
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = 解析域名(offset);
			offset = /** @type {number} */ (nameEnd);
			const type = dv.getUint16(offset); offset += 2;
			offset += 2; // CLASS
			const ttl = dv.getUint32(offset); offset += 4;
			const rdlen = dv.getUint16(offset); offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;

			let data;
			if (type === 1 && rdlen === 4) {
				// A 记录
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				// AAAA 记录
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(':');
			} else if (type === 16) {
				// TXT 记录 (长度前缀字符串)
				let tOff = 0;
				const parts = [];
				while (tOff < rdlen) {
					const tLen = rdata[tOff++];
					parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
					tOff += tLen;
				}
				data = parts.join('');
			} else if (type === 5) {
				// CNAME 记录
				const [cname] = 解析域名(offset - rdlen);
				data = cname;
			} else {
				data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
			}
			answers.push({ name, type, TTL: ttl, data, rdata });
		}
		const 耗时 = (performance.now() - 开始时间).toFixed(2);
		log(`[DoH查询] 查询完成 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms 共${answers.length}条结果${answers.length > 0 ? '\n' + answers.map((a, i) => `  ${i + 1}. ${a.name} type=${a.type} TTL=${a.TTL} data=${a.data}`).join('\n') : ''}`);
		return answers;
	} catch (error) {
		const 耗时 = (performance.now() - 开始时间).toFixed(2);
		console.error(`[DoH查询] 查询失败 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms:`, error);
		return [];
	}
}

/**
 * Extract the Encrypted Client Hello (ECH) config for a host via HTTPS DNS records.
 *
 * @param {string} host - Hostname to look up ECH config for.
 * @returns {Promise<string>} Base64-encoded ECH config, or empty string if unavailable.
 */
export async function getECH(host) {
	try {
		const answers = await DoH查询(host, 'HTTPS');
		if (!answers.length) return '';
		for (const ans of answers) {
			if (ans.type !== 65 || !ans.rdata) continue;
			const bytes = ans.rdata;
			// 解析 SVCB/HTTPS rdata: SvcPriority(2) + TargetName(variable) + SvcParams
			let offset = 2; // 跳过 SvcPriority
			// 跳过 TargetName (域名编码)
			while (offset < bytes.length) {
				const len = bytes[offset];
				if (len === 0) { offset++; break }
				offset += len + 1;
			}
			// 遍历 SvcParams 键值对
			while (offset + 4 <= bytes.length) {
				const key = (bytes[offset] << 8) | bytes[offset + 1];
				const len = (bytes[offset + 2] << 8) | bytes[offset + 3];
				offset += 4;
				// key=5 是 ECH (Encrypted Client Hello)
				if (key === 5) return btoa(String.fromCharCode(...bytes.slice(offset, offset + len)));
				offset += len;
			}
		}
		return '';
	} catch {
		return '';
	}
}

/**
 * Resolve a proxy IP string (possibly containing multiple addresses, domains, or
 * william-style TXT-record lookups) into a cached array of [address, port] pairs.
 *
 * Results are shuffled deterministically based on target domain + UUID and cached
 * in `state.缓存反代IP` / `state.缓存反代解析数组`.
 *
 * @param {string} proxyIP - Comma / newline separated proxy addresses.
 * @param {string} [目标域名='dash.cloudflare.com'] - Target domain for deterministic shuffle seed.
 * @param {string} [UUID='00000000-0000-4000-8000-000000000000'] - UUID for shuffle seed.
 * @param {(内容: string) => Promise<string[]>} 整理成数组 - Helper that normalises a string into an array of entries.
 * @returns {Promise<Array<[string, number]>>}
 */
export async function 解析地址端口(proxyIP, 目标域名 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000', 整理成数组) {
	if (!state.缓存反代IP || !state.缓存反代解析数组 || state.缓存反代IP !== proxyIP) {
		proxyIP = proxyIP.toLowerCase();

		function 解析地址端口字符串(str) {
			let 地址 = str, 端口 = 443;
			if (str.includes(']:')) {
				const parts = str.split(']:');
				地址 = parts[0] + ']';
				端口 = parseInt(parts[1], 10) || 端口;
			} else if (str.includes(':') && !str.startsWith('[')) {
				const colonIndex = str.lastIndexOf(':');
				地址 = str.slice(0, colonIndex);
				端口 = parseInt(str.slice(colonIndex + 1), 10) || 端口;
			}
			return [地址, 端口];
		}

		const 反代IP数组 = await 整理成数组(proxyIP);
		let 所有反代数组 = [];

		// 遍历数组中的每个IP元素进行处理
		for (const singleProxyIP of 反代IP数组) {
			if (singleProxyIP.includes('.william')) {
				try {
					let txtRecords = await DoH查询(singleProxyIP, 'TXT');
					let txtData = txtRecords.filter(r => r.type === 16).map(r => /** @type {string} */(r.data));
					if (txtData.length === 0) {
						log(`[反代解析] 默认DoH未获取到TXT记录，切换Google DoH重试 ${singleProxyIP}`);
						txtRecords = await DoH查询(singleProxyIP, 'TXT', 'https://dns.google/dns-query');
						txtData = txtRecords.filter(r => r.type === 16).map(r => /** @type {string} */(r.data));
					}
					if (txtData.length > 0) {
						let data = txtData[0];
						if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
						const prefixes = data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
						所有反代数组.push(...prefixes.map(prefix => 解析地址端口字符串(prefix)));
					}
				} catch (error) {
					console.error('解析William域名失败:', error);
				}
			} else {
				let [地址, 端口] = 解析地址端口字符串(singleProxyIP);

				if (singleProxyIP.includes('.tp')) {
					const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
					if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
				}

				// 判断是否是域名（非IP地址）
				const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
				const ipv6Regex = /^\[?([a-fA-F0-9:]+)\]?$/;

				if (!ipv4Regex.test(地址) && !ipv6Regex.test(地址)) {
					// 并行查询 A 和 AAAA 记录
					let [aRecords, aaaaRecords] = await Promise.all([
						DoH查询(地址, 'A'),
						DoH查询(地址, 'AAAA')
					]);

					let ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
					let ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
					let ipAddresses = [...ipv4List, ...ipv6List];

					// 默认DoH无结果时，切换Google DoH重试
					if (ipAddresses.length === 0) {
						log(`[反代解析] 默认DoH未获取到解析结果，切换Google DoH重试 ${地址}`);
						[aRecords, aaaaRecords] = await Promise.all([
							DoH查询(地址, 'A', 'https://dns.google/dns-query'),
							DoH查询(地址, 'AAAA', 'https://dns.google/dns-query')
						]);
						ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
						ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
						ipAddresses = [...ipv4List, ...ipv6List];
					}

					if (ipAddresses.length > 0) {
						所有反代数组.push(...ipAddresses.map(ip => [ip, 端口]));
					} else {
						所有反代数组.push([地址, 端口]);
					}
				} else {
					所有反代数组.push([地址, 端口]);
				}
			}
		}
		const 排序后数组 = 所有反代数组.sort((a, b) => a[0].localeCompare(b[0]));
		const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
		let 随机种子 = [...(目标根域名 + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
		log(`[反代解析] 随机种子: ${随机种子}\n目标站点: ${目标根域名}`)
		const 洗牌后 = [...排序后数组].sort(() => (随机种子 = (随机种子 * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
		state.缓存反代解析数组 = 洗牌后.slice(0, 8);
		log(`[反代解析] 解析完成 总数: ${state.缓存反代解析数组.length}个\n${state.缓存反代解析数组.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
		state.缓存反代IP = proxyIP;
	} else log(`[反代解析] 读取缓存 总数: ${state.缓存反代解析数组.length}个\n${state.缓存反代解析数组.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
	return state.缓存反代解析数组;
}
