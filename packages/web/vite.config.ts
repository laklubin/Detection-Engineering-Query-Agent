import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

/**
 * GitHub Pages serves the site from /<repository>/, so the production build
 * needs a matching base path. Override with VITE_BASE_PATH when deploying to a
 * custom domain or to the user/organisation root site.
 */
export default defineConfig(({ command }) => ({
  base: command === 'build' ? (process.env['VITE_BASE_PATH'] ?? '/Detection-Engineering-Query-Agent/') : '/',
  plugins: [react(), tailwindcss()],
  build: {
    outDir: 'dist',
    sourcemap: false,
    target: 'es2022',
  },
  test: {
    environment: 'jsdom',
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
    globals: true,
  },
}));
