import { describe, it, expect } from 'vitest';
import { MD5MD5, sha224 } from '../crypto.js';

describe('MD5MD5', () => {
  it('should return a 32-char lowercase hex string', async () => {
    const result = await MD5MD5('test');
    expect(result).toMatch(/^[0-9a-f]{32}$/);
  });

  it('should be deterministic', async () => {
    const a = await MD5MD5('hello');
    const b = await MD5MD5('hello');
    expect(a).toBe(b);
  });

  it('should produce different output for different input', async () => {
    const a = await MD5MD5('foo');
    const b = await MD5MD5('bar');
    expect(a).not.toBe(b);
  });
});

describe('sha224', () => {
  // Known SHA-224 test vectors from NIST
  it('should hash empty string correctly', () => {
    expect(sha224('')).toBe('d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f');
  });

  it('should hash "abc" correctly', () => {
    expect(sha224('abc')).toBe('23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7');
  });

  it('should return a 56-char hex string', () => {
    const result = sha224('anything');
    expect(result).toMatch(/^[0-9a-f]{56}$/);
  });
});
