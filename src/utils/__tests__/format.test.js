import { describe, it, expect } from 'vitest';
import { 掩码敏感信息, 整理成数组, 批量替换域名 } from '../format.js';

describe('掩码敏感信息', () => {
  it('should mask middle characters', () => {
    expect(掩码敏感信息('abcdefgh')).toBe('abc***gh');
  });

  it('should return short strings as-is', () => {
    expect(掩码敏感信息('abc')).toBe('abc');
  });

  it('should return non-string input as-is', () => {
    expect(掩码敏感信息(null)).toBe(null);
    expect(掩码敏感信息(undefined)).toBe(undefined);
    expect(掩码敏感信息('')).toBe('');
  });

  it('should support custom prefix/suffix lengths', () => {
    expect(掩码敏感信息('abcdefghij', 2, 3)).toBe('ab*****hij');
  });
});

describe('整理成数组', () => {
  it('should split comma-separated values', async () => {
    expect(await 整理成数组('a,b,c')).toEqual(['a', 'b', 'c']);
  });

  it('should handle newlines and tabs', async () => {
    expect(await 整理成数组('a\nb\tc')).toEqual(['a', 'b', 'c']);
  });

  it('should strip quotes', async () => {
    expect(await 整理成数组('"a","b"')).toEqual(['a', 'b']);
  });

  it('should remove leading/trailing commas', async () => {
    expect(await 整理成数组(',a,b,')).toEqual(['a', 'b']);
  });
});

describe('批量替换域名', () => {
  it('should replace example.com with provided hosts', () => {
    const result = 批量替换域名('host: example.com', ['test.com']);
    expect(result).toBe('host: test.com');
  });

  it('should not modify content without example.com', () => {
    const result = 批量替换域名('host: other.com', ['test.com']);
    expect(result).toBe('host: other.com');
  });

  it('should replace multiple occurrences', () => {
    const result = 批量替换域名('example.com example.com example.com', ['a.com', 'b.com'], 1);
    expect(result).not.toContain('example.com');
  });
});
