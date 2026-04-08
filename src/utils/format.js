/**
 * 掩码敏感信息
 * @param {string} 文本
 * @param {number} 前缀长度
 * @param {number} 后缀长度
 * @returns {string}
 */
export function 掩码敏感信息(文本, 前缀长度 = 3, 后缀长度 = 2) {
	if (!文本 || typeof 文本 !== 'string') return 文本;
	if (文本.length <= 前缀长度 + 后缀长度) return 文本; // 如果长度太短，直接返回

	const 前缀 = 文本.slice(0, 前缀长度);
	const 后缀 = 文本.slice(-后缀长度);
	const 星号数量 = 文本.length - 前缀长度 - 后缀长度;

	return `${前缀}${'*'.repeat(星号数量)}${后缀}`;
}

/**
 * 将文本内容整理成数组
 * @param {string} 内容
 * @returns {Promise<string[]>}
 */
export async function 整理成数组(内容) {
	var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
	if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
	const 地址数组 = 替换后的内容.split(',');
	return 地址数组;
}

/**
 * 批量替换 example.com 为实际域名
 * @param {string} 内容
 * @param {string[]} hosts
 * @param {number} 每组数量
 * @returns {string}
 */
export function 批量替换域名(内容, hosts, 每组数量 = 2) {
	const 打乱后HOSTS = [...hosts].sort(() => Math.random() - 0.5);
	const 字符集 = 'abcdefghijklmnopqrstuvwxyz0123456789';
	let count = 0;
	let currentRandomHost = null;
	return 内容.replace(/example\.com/g, () => {
		if (count % 每组数量 === 0) {
			const 原始host = 打乱后HOSTS[Math.floor(count / 每组数量) % 打乱后HOSTS.length];
			currentRandomHost = 原始host?.includes('*') ? 原始host.replace(/\*/g, () => {
				let s = '';
				for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++) s += 字符集[Math.floor(Math.random() * 36)];
				return s;
			}) : 原始host;
		}
		count++;
		return currentRandomHost;
	});
}
