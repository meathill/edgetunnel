import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: {
    alias: {
      'cloudflare:sockets': fileURLToPath(new URL('./src/__tests__/fixtures/sockets.js', import.meta.url)),
    },
  },
  test: {
    setupFiles: ['./vitest.setup.js'],
  },
});
