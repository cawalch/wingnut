#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
// Package build (not the `wingnut build` CLI). Emits:
//   dist/index.js          runtime-AJV entry
//   dist/codegen/index.js  thin codegen entry (AJV aliased to fail-fast stubs)
//   dist/cli.js            `wingnut build` CLI (AJV bundled, shebang)
//   dist/*.d.ts            via tsc (tsconfig.build.json)
// `__WINGNUT_*` are injected with esbuild `define`.
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import esbuild from 'esbuild'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'))
const ajvVersion = JSON.parse(
  await readFile(join(root, 'node_modules/ajv/package.json'), 'utf8'),
).version
const defines = {
  __WINGNUT_VERSION__: JSON.stringify(pkg.version),
  __WINGNUT_AJV_VERSION__: JSON.stringify(ajvVersion),
}

const base = {
  bundle: true,
  platform: 'node',
  target: 'node22',
  minify: true,
  treeShaking: true,
}

// 1) runtime-AJV entry — flags identical to the pre-codegen build.
await esbuild.build({
  ...base,
  entryPoints: [join(root, 'src/index.ts')],
  outdir: join(root, 'dist'),
  external: ['express', 'ajv', 'ajv-formats'],
})

// 2) thin codegen entry — AJV aliased to fail-fast stubs; the bundle must
//    contain zero AJV code. Uses outfile (not {in,out}+outdir) so esbuild
//    writes dist/codegen/index.js instead of overwriting dist/index.js.
await esbuild.build({
  ...base,
  entryPoints: [join(root, 'src/codegen/index.ts')],
  outfile: join(root, 'dist/codegen/index.js'),
  external: ['express'],
  define: defines,
  alias: {
    'ajv/dist/2020': join(root, 'src/codegen/stubs/ajv-2020.ts'),
    ajv: join(root, 'src/codegen/stubs/ajv.ts'),
    'ajv-formats': join(root, 'src/codegen/stubs/ajv-formats.ts'),
  },
})

// 3) `wingnut build` CLI — AJV + ajv-formats BUNDLED (dev-time tool; must
//    run on a machine that has not installed AJV), node builtins external.
await esbuild.build({
  ...base,
  entryPoints: [join(root, 'src/cli/index.ts')],
  outfile: join(root, 'dist/cli.js'),
  banner: { js: '#!/usr/bin/env node' },
  define: defines,
})

// 4) type declarations.
const tsc = spawnSync(
  'pnpm',
  ['exec', 'tsc', '--project', 'tsconfig.build.json'],
  {
    cwd: root,
    stdio: 'inherit',
  },
)
if (tsc.status !== 0) process.exit(tsc.status ?? 1)

console.log(
  `built dist/ (index, codegen, cli) — wingnut@${pkg.version}, ajv@${ajvVersion}`,
)
