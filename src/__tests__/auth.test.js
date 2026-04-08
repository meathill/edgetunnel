import { describe, it, expect } from 'vitest';
import { verifyAuth, createAuthCookie, clearAuthCookie } from '../auth.js';
import { MD5MD5 } from '../utils/crypto.js';

const UA = 'TestAgent/1.0';
const KEY = 'test-key';
const PASSWORD = 'test-password';

describe('verifyAuth', () => {
  it('should return true for valid auth cookie', async () => {
    const hash = await MD5MD5(UA + KEY + PASSWORD);
    const cookies = `other=val; auth=${hash}; foo=bar`;
    expect(await verifyAuth(cookies, UA, KEY, PASSWORD)).toBe(true);
  });

  it('should return false for invalid auth cookie', async () => {
    const cookies = 'auth=invalidhash';
    expect(await verifyAuth(cookies, UA, KEY, PASSWORD)).toBe(false);
  });

  it('should return false when no auth cookie exists', async () => {
    expect(await verifyAuth('foo=bar', UA, KEY, PASSWORD)).toBe(false);
  });

  it('should return false for empty cookie string', async () => {
    expect(await verifyAuth('', UA, KEY, PASSWORD)).toBe(false);
  });
});

describe('createAuthCookie', () => {
  it('should return a valid Set-Cookie header', async () => {
    const cookie = await createAuthCookie(UA, KEY, PASSWORD);
    expect(cookie).toContain('auth=');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=Strict');
    expect(cookie).toContain('Max-Age=86400');
  });

  it('should contain the correct hash value', async () => {
    const expectedHash = await MD5MD5(UA + KEY + PASSWORD);
    const cookie = await createAuthCookie(UA, KEY, PASSWORD);
    expect(cookie).toContain(`auth=${expectedHash}`);
  });
});

describe('clearAuthCookie', () => {
  it('should return a cookie with Max-Age=0', () => {
    const cookie = clearAuthCookie();
    expect(cookie).toContain('Max-Age=0');
    expect(cookie).toContain('auth=');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=Strict');
  });
});
