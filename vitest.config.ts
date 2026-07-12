import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
  },
  resolve: {
    alias: {
      '#config': resolve(__dirname, './src/config'),
      '#controllers': resolve(__dirname, './src/controllers'),
      '#middleware': resolve(__dirname, './src/middleware'),
      '#models': resolve(__dirname, './src/models'),
      '#routes': resolve(__dirname, './src/routes'),
      '#services': resolve(__dirname, './src/services'),
      '#utils': resolve(__dirname, './src/utils'),
      '#validations': resolve(__dirname, './src/validations'),
    },
  },
});
