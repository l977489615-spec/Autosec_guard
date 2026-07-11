import path from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(() => {
    return {
      server: {
        port: 3000,
        host: '127.0.0.1',
        proxy: {
          '/api': {
            target: 'http://127.0.0.1:5002',
            configure: (proxy) => {
              proxy.on('proxyReq', (proxyReq, req) => {
                const host = req.headers.host;
                if (host) {
                  proxyReq.setHeader('X-Forwarded-Host', host);
                  proxyReq.setHeader('X-Forwarded-Proto', 'http');
                }
              });
            },
          },
          '/health': {
            target: 'http://127.0.0.1:5002',
            configure: (proxy) => {
              proxy.on('proxyReq', (proxyReq, req) => {
                const host = req.headers.host;
                if (host) {
                  proxyReq.setHeader('X-Forwarded-Host', host);
                  proxyReq.setHeader('X-Forwarded-Proto', 'http');
                }
              });
            },
          },
        },
      },
      plugins: [react()],
      build: {
        // Three.js is route-lazy and remains 134.76 kB gzip; its uncompressed
        // module is intentionally larger than Vite's generic 500 kB warning.
        chunkSizeWarningLimit: 600,
      },
      resolve: {
        alias: {
          '@': path.resolve(__dirname, '.'),
        }
      }
    };
});
