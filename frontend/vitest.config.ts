import { defineConfig } from 'vitest/config';

// Unit tests for browser-free logic (fetch wrapper, form rules). Browser globals the code under test
// touches (document.cookie, window events, fetch) are stubbed per test, so no DOM library is needed.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
    restoreMocks: true,
    unstubGlobals: true,
  },
});
