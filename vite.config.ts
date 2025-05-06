import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    exclude: ['lucide-react'],
    esbuildOptions: {
      define: {
        global: 'globalThis'
      }
    }
  },
  resolve: {
    // Remove any alias settings that could conflict
  },
  publicDir: 'public',
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        secure: false,
      }
    },
    headers: {
      'Cross-Origin-Embedder-Policy': 'credentialless',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Access-Control-Allow-Origin': '*'
    },
    host: 'localhost',
    port: 3001,
    open: true,
    strictPort: true,
    cors: true
  },
  preview: {
    port: 3001,
    strictPort: true,
  },
});
