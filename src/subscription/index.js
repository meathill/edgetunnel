import { log } from '../utils/log.js';
import { state } from '../state.js';
import { MD5MD5 } from '../utils/crypto.js';
import { 批量替换域名, 整理成数组 } from '../utils/format.js';
import { 随机路径 } from '../utils/path.js';
import { Clash订阅配置文件热补丁 } from './clash.js';
import { Singbox订阅配置文件热补丁 } from './singbox.js';
import { Surge订阅配置文件热补丁 } from './surge.js';
import { 请求优选API, 获取优选订阅生成器数据, 生成随机IP } from '../best-ip.js';

/**
 * 处理 /sub 订阅请求
 *
 * @param {Request} request - 原始请求
 * @param {URL} url - 解析后的请求 URL
 * @param {object} env - Cloudflare Workers 环境绑定
 * @param {object} config_JSON - 已读取的配置对象
 * @param {string} userID - 用户 UUID
 * @param {string} host - 当前请求的 host
 * @param {string} UA - 原始 User-Agent 字符串
 * @param {boolean} 作为优选订阅生成器 - 是否以优选订阅生成器模式运行
 * @returns {Promise<Response>} 订阅响应
 */
export async function handleSubscription(request, url, env, config_JSON, userID, host, UA, 作为优选订阅生成器) {
	const ua = UA.toLowerCase();
	const expire = 4102329600; // 2099-12-31 到期时间
	const now = Date.now();
	const today = new Date(now);
	today.setHours(0, 0, 0, 0);
	const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
	let pagesSum = UD, workersSum = UD, total = 24 * 1099511627776;
	if (config_JSON.CF.Usage?.success) {
		pagesSum = config_JSON.CF.Usage.pages;
		workersSum = config_JSON.CF.Usage.workers;
		total = Number.isFinite(config_JSON.CF.Usage.max) ? (config_JSON.CF.Usage.max / 1000) * 1024 : 1024 * 100;
	}
	const responseHeaders = {
		"content-type": "text/plain; charset=utf-8",
		"Profile-Update-Interval": config_JSON.优选订阅生成.SUBUpdateTime,
		"Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
		"Subscription-Userinfo": `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expire}`,
		"Cache-Control": "no-store",
	};
	const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || ua.includes('subconverter') || ua.includes(('CF-Workers-SUB').toLowerCase()) || 作为优选订阅生成器;
	const 订阅TOKEN = await MD5MD5(host + userID);
	const 订阅类型 = isSubConverterRequest
		? 'mixed'
		: url.searchParams.has('target')
			? url.searchParams.get('target')
			: url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
				? 'clash'
				: url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
					? 'singbox'
					: url.searchParams.has('surge') || ua.includes('surge')
						? 'surge&ver=4'
						: url.searchParams.has('quanx') || ua.includes('quantumult')
							? 'quanx'
							: url.searchParams.has('loon') || ua.includes('loon')
								? 'loon'
								: 'mixed';

	if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
	const 协议类型 = ((url.searchParams.has('surge') || ua.includes('surge')) && config_JSON.协议类型 !== 'ss') ? 'tro' + 'jan' : config_JSON.协议类型;
	let 订阅内容 = '';
	if (订阅类型 === 'mixed') {
		const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
		let 完整优选IP = [], 其他节点LINK = '', 反代IP池 = [];

		if (!url.searchParams.has('sub') && config_JSON.优选订阅生成.local) { // 本地生成订阅
			const 完整优选列表 = config_JSON.优选订阅生成.本地IP库.随机IP ? (
				await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口, (协议类型 === 'ss' ? config_JSON.SS.TLS : true))
			)[0] : await env.KV.get('ADD.txt') ? await 整理成数组(await env.KV.get('ADD.txt')) : (
				await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口, (协议类型 === 'ss' ? config_JSON.SS.TLS : true))
			)[0];
			const 优选API = [], 优选IP = [], 其他节点 = [];
			for (const 元素 of 完整优选列表) {
				if (元素.toLowerCase().startsWith('sub://')) {
					优选API.push(元素);
				} else {
					const subMatch = 元素.match(/sub\s*=\s*([^\s&#]+)/i);
					if (subMatch && subMatch[1].trim().includes('.')) {
						const 优选IP作为反代IP = 元素.toLowerCase().includes('proxyip=true');
						if (优选IP作为反代IP) 优选API.push('sub://' + subMatch[1].trim() + "?proxyip=true" + (元素.includes('#') ? ('#' + 元素.split('#')[1]) : ''));
						else 优选API.push('sub://' + subMatch[1].trim() + (元素.includes('#') ? ('#' + 元素.split('#')[1]) : ''));
					} else if (元素.toLowerCase().startsWith('https://')) {
						优选API.push(元素);
					} else if (元素.toLowerCase().includes('://')) {
						if (元素.includes('#')) {
							const 地址备注分离 = 元素.split('#');
							其他节点.push(地址备注分离[0] + '#' + encodeURIComponent(decodeURIComponent(地址备注分离[1])));
						} else 其他节点.push(元素);
					} else {
						优选IP.push(元素);
					}
				}
			}
			const 请求优选API内容 = await 请求优选API(优选API, (协议类型 === 'ss' && !config_JSON.SS.TLS) ? '80' : '443');
			const 合并其他节点数组 = [...new Set(其他节点.concat(请求优选API内容[1]))];
			其他节点LINK = 合并其他节点数组.length > 0 ? 合并其他节点数组.join('\n') + '\n' : '';
			const 优选API的IP = 请求优选API内容[0];
			反代IP池 = 请求优选API内容[3] || [];
			完整优选IP = [...new Set(优选IP.concat(优选API的IP))];
		} else { // 优选订阅生成器
			let 优选订阅生成器HOST = url.searchParams.get('sub') || config_JSON.优选订阅生成.SUB;
			const [优选生成器IP数组, 优选生成器其他节点] = await 获取优选订阅生成器数据(优选订阅生成器HOST);
			完整优选IP = 完整优选IP.concat(优选生成器IP数组);
			其他节点LINK += 优选生成器其他节点;
		}
		const ECHLINK参数 = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
		const isLoonOrSurge = ua.includes('loon') || ua.includes('surge');
		const 传输协议 = config_JSON.传输协议 === 'xhttp' ? 'xhttp&mode=stream-one' : (config_JSON.传输协议 === 'grpc' ? (config_JSON.gRPC模式 === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun') : 'ws');
		let 路径字段名 = 'path', 域名字段名 = 'host';
		if (config_JSON.传输协议 === 'grpc') 路径字段名 = 'serviceName', 域名字段名 = 'authority';
		订阅内容 = 其他节点LINK + 完整优选IP.map(原始地址 => {
			// 统一正则: 匹配 域名/IPv4/IPv6地址 + 可选端口 + 可选备注
			const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
			const match = 原始地址.match(regex);

			let 节点地址, 节点端口 = "443", 节点备注;

			if (match) {
				节点地址 = match[1];
				节点端口 = match[2] ? match[2] : (协议类型 === 'ss' && !config_JSON.SS.TLS) ? '80' : '443';
				节点备注 = match[3] || 节点地址;
			} else {
				console.warn(`[订阅内容] 不规范的IP格式已忽略: ${原始地址}`);
				return null;
			}

			let 完整节点路径 = config_JSON.完整节点路径;
			if (反代IP池.length > 0) {
				const 匹配到的反代IP = 反代IP池.find(p => p.includes(节点地址));
				if (匹配到的反代IP) 完整节点路径 = (`${config_JSON.PATH}/proxyip=${匹配到的反代IP}`).replace(/\/\//g, '/') + (config_JSON.启用0RTT ? '?ed=2560' : '');
			}
			if (isLoonOrSurge) 完整节点路径 = 完整节点路径.replace(/,/g, '%2C');

			if (协议类型 === 'ss' && !作为优选订阅生成器) {
				完整节点路径 = (完整节点路径.includes('?') ? 完整节点路径.replace('?', '?enc=' + config_JSON.SS.加密方式 + '&') : (完整节点路径 + '?enc=' + config_JSON.SS.加密方式)).replace(/([=,])/g, '\\$1');
				if (!isSubConverterRequest) 完整节点路径 = 完整节点路径 + ';mux=0';
				return `${协议类型}://${btoa(config_JSON.SS.加密方式 + ':00000000-0000-4000-8000-000000000000')}@${节点地址}:${节点端口}?plugin=v2${encodeURIComponent('ray-plugin;mode=websocket;host=example.com;path=' + (config_JSON.随机路径 ? 随机路径(完整节点路径) : 完整节点路径) + (config_JSON.SS.TLS ? ';tls' : '')) + ECHLINK参数 + TLS分片参数}#${encodeURIComponent(节点备注)}`;
			} else return `${协议类型}://00000000-0000-4000-8000-000000000000@${节点地址}:${节点端口}?security=tls&type=${传输协议 + ECHLINK参数}&${域名字段名}=example.com&fp=${config_JSON.Fingerprint}&sni=example.com&${路径字段名}=${encodeURIComponent(作为优选订阅生成器 ? '/' : (config_JSON.随机路径 ? 随机路径(完整节点路径) : 完整节点路径)) + TLS分片参数}&encryption=none${config_JSON.跳过证书验证 ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(节点备注)}`;
		}).filter(item => item !== null).join('\n');
	} else { // 订阅转换
		const 订阅转换URL = `${config_JSON.订阅转换配置.SUBAPI}/sub?target=${订阅类型}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + 订阅TOKEN + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(config_JSON.订阅转换配置.SUBCONFIG)}&emoji=${config_JSON.订阅转换配置.SUBEMOJI}&scv=${config_JSON.跳过证书验证}`;
		try {
			const response = await fetch(订阅转换URL, { headers: { 'User-Agent': 'Subconverter for ' + 订阅类型 + ' edge' + 'tunnel (https://github.com/cmliu/edge' + 'tunnel)' } });
			if (response.ok) {
				订阅内容 = await response.text();
				if (url.searchParams.has('surge') || ua.includes('surge')) 订阅内容 = Surge订阅配置文件热补丁(订阅内容, url.protocol + '//' + url.host + '/sub?token=' + 订阅TOKEN + '&surge', config_JSON);
			} else return new Response('订阅转换后端异常：' + response.statusText, { status: response.status });
		} catch (error) {
			console.error('订阅转换后端异常:', error.message);
			return new Response('订阅转换后端异常', { status: 403 });
		}
	}

	if (!ua.includes('subconverter') && !作为优选订阅生成器) 订阅内容 = 批量替换域名(订阅内容.replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID).replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(config_JSON.UUID)), config_JSON.HOSTS);

	if (订阅类型 === 'mixed' && (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) 订阅内容 = btoa(订阅内容);

	if (订阅类型 === 'singbox') {
		订阅内容 = await Singbox订阅配置文件热补丁(订阅内容, config_JSON);
		responseHeaders["content-type"] = 'application/json; charset=utf-8';
	} else if (订阅类型 === 'clash') {
		订阅内容 = Clash订阅配置文件热补丁(订阅内容, config_JSON);
		responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
	}
	return new Response(订阅内容, { status: 200, headers: responseHeaders });
}
