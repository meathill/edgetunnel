/**
 * Shadowsocks AEAD encryption/decryption primitives and helpers.
 */

/** @type {Record<string, { method: string, keyLen: number, saltLen: number, maxChunk: number, aesLength: number }>} */
export const SS支持加密配置 = {
	'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
	'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};

/** @type {number} */
export const SSAEAD标签长度 = 16;

/** @type {number} */
export const SSNonce长度 = 12;

const SS子密钥信息 = new TextEncoder().encode('ss-subkey');
const SS文本编码器 = new TextEncoder();

/** @type {TextDecoder} */
export const SS文本解码器 = new TextDecoder();

const SS主密钥缓存 = new Map();

/**
 * Convert various data types to Uint8Array.
 * @param {Uint8Array | ArrayBuffer | ArrayBufferView | null} data
 * @returns {Uint8Array}
 */
export function SS数据转Uint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

/**
 * Concatenate multiple byte chunks into a single Uint8Array.
 * @param {...(Uint8Array | ArrayBuffer | ArrayBufferView)} chunkList
 * @returns {Uint8Array}
 */
export function SS拼接字节(...chunkList) {
	if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
	const chunks = chunkList.map(SS数据转Uint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) { result.set(c, offset); offset += c.byteLength }
	return result;
}

/**
 * Increment a little-endian nonce counter in place.
 * @param {Uint8Array} counter
 */
export function SS递增Nonce计数器(counter) {
	for (let i = 0; i < counter.length; i++) { counter[i] = (counter[i] + 1) & 0xff; if (counter[i] !== 0) return }
}

/**
 * Derive a master key from a password using repeated MD5 hashing (EVP_BytesToKey).
 * Results are cached by keyLen + password.
 * @param {string} passwordText
 * @param {number} keyLen
 * @returns {Promise<Uint8Array>}
 */
export async function SS派生主密钥(passwordText, keyLen) {
	const cacheKey = `${keyLen}:${passwordText}`;
	if (SS主密钥缓存.has(cacheKey)) return SS主密钥缓存.get(cacheKey);
	const deriveTask = (async () => {
		const pwBytes = SS文本编码器.encode(passwordText || '');
		let prev = new Uint8Array(0), result = new Uint8Array(0);
		while (result.byteLength < keyLen) {
			const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
			input.set(prev, 0); input.set(pwBytes, prev.byteLength);
			prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
			result = SS拼接字节(result, prev);
		}
		return result.slice(0, keyLen);
	})();
	SS主密钥缓存.set(cacheKey, deriveTask);
	try { return await deriveTask }
	catch (error) { SS主密钥缓存.delete(cacheKey); throw error }
}

/**
 * Derive a session (sub) key via HKDF-SHA1 from master key + salt.
 * @param {{ keyLen: number, aesLength: number }} config
 * @param {Uint8Array} masterKey
 * @param {Uint8Array} salt
 * @param {KeyUsage[]} usages - e.g. ['encrypt'] or ['decrypt']
 * @returns {Promise<CryptoKey>}
 */
export async function SS派生会话密钥(config, masterKey, salt, usages) {
	const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
	const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
	const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
	const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
	const subKey = new Uint8Array(config.keyLen);
	let prev = new Uint8Array(0), written = 0, counter = 1;
	while (written < config.keyLen) {
		const input = SS拼接字节(prev, SS子密钥信息, new Uint8Array([counter]));
		prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
		const copyLen = Math.min(prev.byteLength, config.keyLen - written);
		subKey.set(prev.subarray(0, copyLen), written);
		written += copyLen; counter += 1;
	}
	return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: config.aesLength }, false, usages);
}

/**
 * AEAD encrypt a plaintext chunk using AES-GCM, then increment the nonce counter.
 * @param {CryptoKey} cryptoKey
 * @param {Uint8Array} nonceCounter - 12-byte nonce, mutated in place
 * @param {Uint8Array} plaintext
 * @returns {Promise<Uint8Array>}
 */
export async function SSAEAD加密(cryptoKey, nonceCounter, plaintext) {
	const iv = nonceCounter.slice();
	const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
	SS递增Nonce计数器(nonceCounter);
	return new Uint8Array(ct);
}

/**
 * AEAD decrypt a ciphertext chunk using AES-GCM, then increment the nonce counter.
 * @param {CryptoKey} cryptoKey
 * @param {Uint8Array} nonceCounter - 12-byte nonce, mutated in place
 * @param {Uint8Array} ciphertext
 * @returns {Promise<Uint8Array>}
 */
export async function SSAEAD解密(cryptoKey, nonceCounter, ciphertext) {
	const iv = nonceCounter.slice();
	const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
	SS递增Nonce计数器(nonceCounter);
	return new Uint8Array(pt);
}
