import { createHash } from 'node:crypto';

// Cloudflare Workers 的 crypto.subtle.digest 支持 MD5，但 Node.js 不支持。
// 用 Node.js 的 createHash 来 polyfill。
const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
crypto.subtle.digest = async function (algorithm, data) {
  const algoName = typeof algorithm === 'string' ? algorithm : algorithm.name;
  if (algoName === 'MD5') {
    const hash = createHash('md5');
    hash.update(Buffer.from(data));
    return hash.digest().buffer;
  }
  return originalDigest(algorithm, data);
};
