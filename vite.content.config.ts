import { defineConfig } from 'vite';
import { resolve } from 'node:path';

// Manifest content scripts run as classic scripts and cannot import ESM chunks.
export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: false,
    lib: {
      entry: resolve(__dirname, 'src/content/index.ts'),
      name: 'BrowserDefenseContent',
      formats: ['iife'],
      fileName: () => 'content.js',
    },
    target: 'chrome133',
    minify: false,
  },
});
