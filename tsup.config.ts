import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/cli/index.ts'],
  format: ['esm'],
  target: 'node20',
  sourcemap: true,
  clean: true,
  dts: true,
  splitting: false,
  banner: {
    js: '#!/usr/bin/env node'
  }
});
