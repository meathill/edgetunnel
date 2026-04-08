import { describe, it, expect } from 'vitest';
import { 随机路径 } from '../path.js';

describe('随机路径', () => {
  it('should start with /', () => {
    expect(随机路径()).toMatch(/^\//);
  });

  it('should contain 1-3 path segments', () => {
    const result = 随机路径();
    const segments = result.slice(1).split('/');
    expect(segments.length).toBeGreaterThanOrEqual(1);
    expect(segments.length).toBeLessThanOrEqual(3);
  });

  it('should preserve query string from input path', () => {
    const result = 随机路径('/?key=value');
    expect(result).toContain('?key=value');
  });

  it('should produce different results on repeated calls', () => {
    const results = new Set(Array.from({ length: 20 }, () => 随机路径()));
    expect(results.size).toBeGreaterThan(1);
  });
});
