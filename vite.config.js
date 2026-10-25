/*
 * Anne's Test — Vite build (web platform target)
 * Part of the Anne's Office suite. Builds the static web app: the landing page, the
 * command shell and the AI setup wizard. The pages are self-contained (inline
 * CSS and inline module scripts), so Vite minifies and fingerprints them
 * without any framework runtime. publicDir is disabled because our source
 * pages already live under public/ as build inputs, not as passthrough assets.
 */
import { resolve } from 'node:path';
import { defineConfig } from 'vite';

export default defineConfig({
  root: '.',
  publicDir: false,
  base: './', // relative asset URLs, so the build works from file://, a subpath, or an Electron bundle
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        index: resolve(import.meta.dirname, 'index.html'),
        shell: resolve(import.meta.dirname, 'public/shell.html'),
        wizard: resolve(import.meta.dirname, 'public/ai-wizard.html'),
      },
    },
  },
  server: { host: '127.0.0.1', port: 5173 },
});
