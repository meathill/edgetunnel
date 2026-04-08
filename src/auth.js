import { MD5MD5 } from './utils/crypto.js';

/**
 * Verify an authentication cookie against the expected hash.
 *
 * The expected value is MD5MD5(UA + 加密秘钥 + 管理员密码).
 *
 * @param {string} cookies - The raw Cookie header value
 * @param {string} UA - User-Agent string
 * @param {string} 加密秘钥 - Encryption key
 * @param {string} 管理员密码 - Admin password
 * @returns {Promise<boolean>} Whether the auth cookie is valid
 */
export async function verifyAuth(cookies, UA, 加密秘钥, 管理员密码) {
  const authCookie = cookies
    .split(';')
    .find(c => c.trim().startsWith('auth='))
    ?.split('=')[1];
  if (!authCookie) return false;
  const expected = await MD5MD5(UA + 加密秘钥 + 管理员密码);
  return authCookie === expected;
}

/**
 * Generate a Set-Cookie header value for authentication.
 *
 * The cookie value is MD5MD5(UA + 加密秘钥 + 管理员密码), valid for 24 hours,
 * HttpOnly, Secure, SameSite=Strict.
 *
 * @param {string} UA - User-Agent string
 * @param {string} 加密秘钥 - Encryption key
 * @param {string} 管理员密码 - Admin password
 * @returns {Promise<string>} The Set-Cookie header value
 */
export async function createAuthCookie(UA, 加密秘钥, 管理员密码) {
  const hash = await MD5MD5(UA + 加密秘钥 + 管理员密码);
  return `auth=${hash}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`;
}

/**
 * Return a Set-Cookie header value that clears the auth cookie.
 *
 * @returns {string} The Set-Cookie header value to clear the cookie
 */
export function clearAuthCookie() {
  return 'auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict';
}
