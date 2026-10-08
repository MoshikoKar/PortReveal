import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';

// Reads BACKEND_PORT / FRONTEND_PORT from the repository-root .env
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '..', '');
  const backend = `http://${env.BACKEND_HOST || '127.0.0.1'}:${env.BACKEND_PORT || '8000'}`;
  return {
    plugins: [react()],
    server: {
      port: Number(env.FRONTEND_PORT || 5173),
      strictPort: true,
      proxy: { '/api': { target: backend, changeOrigin: false } },
    },
    build: { outDir: 'dist', sourcemap: false, chunkSizeWarningLimit: 900 },
  };
});
