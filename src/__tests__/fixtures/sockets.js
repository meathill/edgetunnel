import { vi } from 'vitest';

export const connect = vi.fn(() => {
  throw new Error('测试未配置 TCP socket');
});
