import { log } from '../utils/log.js';
import { getECH } from '../dns.js';

/**
 * Singbox 订阅配置文件热补丁
 *
 * - 迁移 TUN 入站地址（1.10.0+）
 * - 将 Geosite/GeoIP 转换为 rule_set（1.8.0+）
 * - 迁移到 action-based 规则（1.11.0+）
 * - 为匹配 UUID 的节点注入 TLS (utls & ech)
 *
 * @param {string} SingBox_原始订阅内容 - 原始 SingBox JSON 订阅内容
 * @param {object} config_JSON - 配置对象
 * @returns {Promise<string>} 修补后的 SingBox JSON 订阅内容
 */
export async function Singbox订阅配置文件热补丁(SingBox_原始订阅内容, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const fingerprint = config_JSON?.Fingerprint || "chrome";
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || config_JSON?.HOST || null;
	const ech_config = config_JSON?.ECH && ECH_SNI ? await getECH(ECH_SNI) : null;
	const sb_json_text = SingBox_原始订阅内容.replace('1.1.1.1', '8.8.8.8').replace('1.0.0.1', '8.8.4.4');
	try {
		let config = JSON.parse(sb_json_text);

		// --- 1. TUN 入站迁移 (1.10.0+) ---
		if (Array.isArray(config.inbounds)) {
			config.inbounds.forEach(inbound => {
				if (inbound.type === 'tun') {
					const addresses = [];
					if (inbound.inet4_address) addresses.push(inbound.inet4_address);
					if (inbound.inet6_address) addresses.push(inbound.inet6_address);
					if (addresses.length > 0) {
						inbound.address = addresses;
						delete inbound.inet4_address;
						delete inbound.inet6_address;
					}

					const route_addresses = [];
					if (Array.isArray(inbound.inet4_route_address)) route_addresses.push(...inbound.inet4_route_address);
					if (Array.isArray(inbound.inet6_route_address)) route_addresses.push(...inbound.inet6_route_address);
					if (route_addresses.length > 0) {
						inbound.route_address = route_addresses;
						delete inbound.inet4_route_address;
						delete inbound.inet6_route_address;
					}

					const route_exclude_addresses = [];
					if (Array.isArray(inbound.inet4_route_exclude_address)) route_exclude_addresses.push(...inbound.inet4_route_exclude_address);
					if (Array.isArray(inbound.inet6_route_exclude_address)) route_exclude_addresses.push(...inbound.inet6_route_exclude_address);
					if (route_exclude_addresses.length > 0) {
						inbound.route_exclude_address = route_exclude_addresses;
						delete inbound.inet4_route_exclude_address;
						delete inbound.inet6_route_exclude_address;
					}
				}
			});
		}

		// --- 2. 迁移 Geosite/GeoIP 到 rule_set (1.8.0+) 及 Actions (1.11.0+) ---
		const ruleSetsDefinitions = new Map();
		const processRules = (rules, isDns = false) => {
			if (!Array.isArray(rules)) return;
			rules.forEach(rule => {
				if (rule.geosite) {
					const geositeList = Array.isArray(rule.geosite) ? rule.geosite : [rule.geosite];
					rule.rule_set = geositeList.map(name => {
						const tag = `geosite-${name}`;
						if (!ruleSetsDefinitions.has(tag)) {
							ruleSetsDefinitions.set(tag, {
								tag: tag,
								type: "remote",
								format: "binary",
								url: `https://gh.090227.xyz/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-${name}.srs`,
								download_detour: "DIRECT"
							});
						}
						return tag;
					});
					delete rule.geosite;
				}
				if (rule.geoip) {
					const geoipList = Array.isArray(rule.geoip) ? rule.geoip : [rule.geoip];
					rule.rule_set = rule.rule_set || [];
					geoipList.forEach(name => {
						const tag = `geoip-${name}`;
						if (!ruleSetsDefinitions.has(tag)) {
							ruleSetsDefinitions.set(tag, {
								tag: tag,
								type: "remote",
								format: "binary",
								url: `https://gh.090227.xyz/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-${name}.srs`,
								download_detour: "DIRECT"
							});
						}
						rule.rule_set.push(tag);
					});
					delete rule.geoip;
				}
				const targetField = isDns ? 'server' : 'outbound';
				const actionValue = String(rule[targetField]).toUpperCase();
				if (actionValue === 'REJECT' || actionValue === 'BLOCK') {
					rule.action = 'reject';
					rule.method = 'drop'; // 强制使用现代方式
					delete rule[targetField];
				}
			});
		};

		if (config.dns && config.dns.rules) processRules(config.dns.rules, true);
		if (config.route && config.route.rules) processRules(config.route.rules, false);

		if (ruleSetsDefinitions.size > 0) {
			if (!config.route) config.route = {};
			config.route.rule_set = Array.from(ruleSetsDefinitions.values());
		}

		// --- 3. 兼容性与纠错 ---
		if (!config.outbounds) config.outbounds = [];

		// 移除 outbounds 中冗余的 block 类型节点 (如果它们已经被 action 替代)
		// 但保留 DIRECT 这种必需的特殊出站
		config.outbounds = config.outbounds.filter(o => {
			if (o.tag === 'REJECT' || o.tag === 'block') {
				return false; // 移除，因为已经改用 action: reject 了
			}
			return true;
		});

		const existingOutboundTags = new Set(config.outbounds.map(o => o.tag));

		if (!existingOutboundTags.has('DIRECT')) {
			config.outbounds.push({ "type": "direct", "tag": "DIRECT" });
			existingOutboundTags.add('DIRECT');
		}

		if (config.dns && config.dns.servers) {
			const dnsServerTags = new Set(config.dns.servers.map(s => s.tag));
			if (config.dns.rules) {
				config.dns.rules.forEach(rule => {
					if (rule.server && !dnsServerTags.has(rule.server)) {
						if (rule.server === 'dns_block' && dnsServerTags.has('block')) {
							rule.server = 'block';
						} else if (rule.server.toLowerCase().includes('block') && !dnsServerTags.has(rule.server)) {
							config.dns.servers.push({ "tag": rule.server, "address": "rcode://success" });
							dnsServerTags.add(rule.server);
						}
					}
				});
			}
		}

		config.outbounds.forEach(outbound => {
			if (outbound.type === 'selector' || outbound.type === 'urltest') {
				if (Array.isArray(outbound.outbounds)) {
					// 修正：如果选择器引用了被移除的 REJECT/block，直接将其过滤掉
					// 因为路由规则已经通过 action 拦截了，不需要走选择器
					outbound.outbounds = outbound.outbounds.filter(tag => {
						const upperTag = tag.toUpperCase();
						return existingOutboundTags.has(tag) && upperTag !== 'REJECT' && upperTag !== 'BLOCK';
					});
					if (outbound.outbounds.length === 0) outbound.outbounds.push("DIRECT");
				}
			}
		});

		// --- 4. UUID 匹配节点的 TLS 热补丁 (utls & ech) ---
		if (uuid) {
			config.outbounds.forEach(outbound => {
				// 仅处理包含 uuid 或 password 且匹配的节点
				if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid)) {
					// 确保 tls 对象存在
					if (!outbound.tls) {
						outbound.tls = { enabled: true };
					}

					// 添加/更新 utls 配置
					if (fingerprint) {
						outbound.tls.utls = {
							enabled: true,
							fingerprint: fingerprint
						};
					}

					// 如果提供了 ech_config，添加/更新 ech 配置
					if (ech_config) {
						outbound.tls.ech = {
							enabled: true,
							//query_server_name: "cloudflare-ech.com",// 等待 1.13.0+ 版本上线
							config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----`
						};
					}
				}
			});
		}

		return JSON.stringify(config, null, 2);
	} catch (e) {
		console.error("Singbox热补丁执行失败:", e);
		return JSON.stringify(JSON.parse(sb_json_text), null, 2);
	}
}
