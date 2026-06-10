import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    grovedb: 'src/grovedb/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  // Emit shared code (the grovedb module is reachable from both entries) as a
  // single chunk both bundles import, so classes like GroveDBVerificationError
  // are identity-equal across the root `grovedb` namespace and the `./grovedb`
  // subpath. With splitting off each entry inlines its own copy and instanceof
  // checks fail across the two.
  splitting: true,
  sourcemap: false,
  clean: true,
  minify: false,
});
