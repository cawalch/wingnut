/**
 * `wingnut build` — codegen build step.
 *
 * Runs the app's route wiring once with a recording AjvLike backed by real
 * AJV (canonical options + `code:{source:true}`), captures every unique
 * schema, re-emits each as standalone code, and writes the artifacts:
 *
 *   <out>/validators.cjs   Record<schemaJson, validateFn>
 *   <out>/meta.json        generator identity + options hash (drift gate)
 *
 * Emits are byte-for-byte AJV's own compiler output, so semantics match the
 * runtime path by construction.
 *
 *   wingnut build --entry app.mjs --out generated [--dialect 3.0|3.1]
 *   wingnut build --entry app.mjs --out generated --check
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

// AJV is bundled into this CLI (not externalized in scripts/build.mjs), so
// `wingnut build` works on a dev machine with only wingnut installed.
import Ajv from 'ajv'
import Ajv2020 from 'ajv/dist/2020'
import standalone from 'ajv/dist/standalone'
import ajvPkg from 'ajv/package.json'
import addFormats from 'ajv-formats'
import ajvFormatsPkg from 'ajv-formats/package.json'
import type { CodegenDialect, CodegenMeta } from '../lib/codegen'
import {
  CODEGEN_CANONICAL_OPTIONS,
  codegenOptionsHash,
  codegenSchemaKey,
  WingnutCodegenError,
} from '../lib/codegen'
import type { AjvLike, AjvLikeValidateFunction } from '../types/common'

// `--define` targets (scripts/build.mjs).
declare const __WINGNUT_VERSION__: string
declare const __WINGNUT_AJV_VERSION__: string

export interface BuildArgs {
  command: 'build'
  entry: string
  out: string
  dialect: CodegenDialect
  check: boolean
  quiet: boolean
}

/** Minimal dependency-free arg parser for the documented surface. */
export const parseArgs = (argv: string[]): BuildArgs | { error: string } => {
  const [command, ...rest] = argv
  const out: {
    command: string
    entry?: string
    out?: string
    dialect?: CodegenDialect
    check?: boolean
    quiet?: boolean
  } = { command: command ?? '' }
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]
    if (a === '--entry' || a === '--out' || a === '--dialect') {
      const v = rest[++i]
      if (v === undefined) return { error: `missing value for ${a}` }
      if (a === '--entry') out.entry = v
      else if (a === '--out') out.out = v
      else {
        if (v !== '3.0' && v !== '3.1') {
          return { error: `--dialect must be 3.0 or 3.1 (got ${v})` }
        }
        out.dialect = v
      }
    } else if (a === '--check') out.check = true
    else if (a === '--quiet') out.quiet = true
    else return { error: `unknown argument: ${a} (see: wingnut build)` }
  }
  if (out.command !== 'build') {
    return {
      error:
        out.command === ''
          ? 'usage: wingnut build --entry <file> --out <dir> [--dialect 3.0|3.1] [--check] [--quiet]'
          : `unknown command: ${out.command} (expected "build")`,
    }
  }
  if (!out.entry) return { error: 'missing required --entry <file>' }
  if (!out.out) return { error: 'missing required --out <dir>' }
  return {
    command: 'build',
    entry: out.entry,
    out: out.out,
    dialect: out.dialect ?? '3.0',
    check: out.check ?? false,
    quiet: out.quiet ?? false,
  }
}

/** Canonical wingnut options plus `code:{source:true}` for standalone emit. */
const createGeneratorAjv = (dialect: CodegenDialect) => {
  // `formats` is applied via the plugin below, not the constructor: AJV's
  // `Options.formats` field is for custom format definitions.
  const instance =
    dialect === '3.1'
      ? new Ajv2020({
          coerceTypes: CODEGEN_CANONICAL_OPTIONS.coerceTypes,
          allErrors: CODEGEN_CANONICAL_OPTIONS.allErrors,
          code: { source: true },
        })
      : new Ajv({
          coerceTypes: CODEGEN_CANONICAL_OPTIONS.coerceTypes,
          allErrors: CODEGEN_CANONICAL_OPTIONS.allErrors,
          code: { source: true },
        })
  if (CODEGEN_CANONICAL_OPTIONS.formats) addFormats(instance)
  return instance
}

/** Wraps a live AjvLike; records each unique schema exactly once. */
const recordingAjvLike = (
  ajv: AjvLike,
): AjvLike & { _unique: Map<string, AjvLikeValidateFunction> } => {
  const unique = new Map<string, AjvLikeValidateFunction>()
  return {
    compile(schema: Record<string, unknown>) {
      const key = codegenSchemaKey(schema)
      let v = unique.get(key)
      if (!v) {
        v = ajv.compile(schema)
        unique.set(key, v)
      }
      return v
    },
    _unique: unique,
  }
}

/**
 * One standalone validator wrapped in an IIFE. AJV emits the `module.exports`
 * lines first but the `const` initializers after them, so the `return` must
 * be appended last or the consts are in the TDZ on first run.
 */
const standaloneEmit = (
  genAjv: InstanceType<typeof Ajv> | InstanceType<typeof Ajv2020>,
  schema: Record<string, unknown>,
): string => {
  const code = standalone(genAjv, genAjv.compile(schema))
  const m = code.match(
    /^"use strict";module\.exports = (\w+);module\.exports\.default = \1;/,
  )
  if (!m) {
    throw new WingnutCodegenError(
      `unexpected standalone output shape — AJV version drift? ` +
        `head: ${code.slice(0, 120)}`,
    )
  }
  const name = m[1]
  const body = code.slice(m[0].length)
  return `(()=>{${body}\nreturn ${name}})()`
}

/** The shape a build entry must export. */
export type BuildEntry = {
  build: (ajvLike: AjvLike) => unknown
}

/** Load the user's build entry: ESM/CJS, or `.ts` (re-spawned with
 * `--experimental-strip-types` on Node < 23.6). */
const loadBuildEntry = async (entryPath: string): Promise<BuildEntry> => {
  const abs = resolve(entryPath)
  if (!existsSync(abs)) {
    throw new WingnutCodegenError(`entry not found: ${abs}`)
  }
  const mod = await import(abs)
  const fn =
    (mod as { build?: unknown }).build ?? (mod as { default?: unknown }).default
  if (typeof fn !== 'function') {
    throw new WingnutCodegenError(
      `entry ${abs} must export a \`build(ajvLike)\` function (named ` +
        `\`build\` or default export) that wires the app routes with the ` +
        `injected AjvLike`,
    )
  }
  return { build: fn as BuildEntry['build'] }
}

export interface BuildResult {
  keys: string[]
  bytes: number
  meta: CodegenMeta
}

const generatorId = (): string => `wingnut@${__WINGNUT_VERSION__}`

/** Capture → emit. `write=false` runs the capture only (`--check`). */
export const runBuild = async ({
  entryPath,
  outDir,
  dialect,
  write = true,
}: {
  entryPath: string
  outDir: string
  dialect: CodegenDialect
  write?: boolean
}): Promise<BuildResult> => {
  const gen = createGeneratorAjv(dialect)
  const recorder = recordingAjvLike(gen as unknown as AjvLike)
  const entry = await loadBuildEntry(entryPath)
  await entry.build(recorder)

  const keys = [...recorder._unique.keys()]
  const meta: CodegenMeta = {
    generator: generatorId(),
    ajv: ajvPkg.version,
    ajvFormats: ajvFormatsPkg.version,
    dialect,
    optionsHash: codegenOptionsHash(dialect),
    count: keys.length,
    keys,
  }

  let bytes = 0
  if (write) {
    const lines = keys.map((key) => {
      const schema = JSON.parse(key) as Record<string, unknown>
      return `  ${JSON.stringify(key)}: ${standaloneEmit(gen, schema)},`
    })
    const code =
      `"use strict";\n` +
      `/* generated by ${meta.generator} — do not edit */\n` +
      `const validators = {\n${lines.join('\n')}\n};\n` +
      `module.exports = validators;\n`
    bytes = Buffer.byteLength(code)
    mkdirSync(outDir, { recursive: true })
    writeFileSync(join(outDir, 'validators.cjs'), code)
    writeFileSync(
      join(outDir, 'meta.json'),
      JSON.stringify(meta, null, 2) + '\n',
    )
  }
  return { keys, bytes, meta }
}

/** `--check`: compare the on-disk artifact against a fresh capture. */
const checkArtifact = (
  fresh: BuildResult,
  outDir: string,
): { ok: boolean; problems: string[] } => {
  const metaPath = join(outDir, 'meta.json')
  const valPath = join(outDir, 'validators.cjs')
  if (!existsSync(metaPath) || !existsSync(valPath)) {
    return {
      ok: false,
      problems: [
        'no artifact found — run: wingnut build --entry <file> --out ' + outDir,
      ],
    }
  }
  const onDisk = JSON.parse(readFileSync(metaPath, 'utf8')) as CodegenMeta
  const problems: string[] = []
  if (onDisk.generator !== fresh.meta.generator) {
    problems.push(
      `generator drift (artifact=${onDisk.generator}, current=${fresh.meta.generator})`,
    )
  }
  if (onDisk.ajv !== fresh.meta.ajv) {
    problems.push(
      `AJV version drift (artifact=${onDisk.ajv}, current=${fresh.meta.ajv})`,
    )
  }
  if (onDisk.optionsHash !== fresh.meta.optionsHash) {
    problems.push(
      `options hash drift (artifact=${onDisk.optionsHash}, current=${fresh.meta.optionsHash})`,
    )
  }
  const diskSet = new Set(onDisk.keys)
  const freshSet = new Set(fresh.meta.keys)
  const removed = onDisk.keys.filter((k) => !freshSet.has(k))
  const added = fresh.meta.keys.filter((k) => !diskSet.has(k))
  if (removed.length > 0 || added.length > 0) {
    problems.push(
      `schema drift: ${added.length} added, ${removed.length} removed vs artifact ` +
        `(schemas changed since the last build)`,
    )
  }
  return { ok: problems.length === 0, problems }
}

const tsReSpawnIfNeeded = (args: string[]): boolean => {
  const entryIdx = args.indexOf('--entry')
  const entry = entryIdx >= 0 ? args[entryIdx + 1] : undefined
  if (!entry || !entry.endsWith('.ts')) return false
  const [major, minor] = process.versions.node.split('.').map(Number)
  const strippingDefault = major > 23 || (major === 23 && minor >= 6)
  if (strippingDefault) return false
  if (process.env.__WINGNUT_TS_SPAWNED === '1') return false
  const { spawnSync } =
    require('node:child_process') as typeof import('node:child_process')
  const self = process.argv[1]
  const r = spawnSync(
    process.execPath,
    ['--experimental-strip-types', self, ...args],
    {
      stdio: 'inherit',
      env: { ...process.env, __WINGNUT_TS_SPAWNED: '1' },
    },
  )
  process.exit(r.status ?? 1)
  return true
}

export const main = async (argv: string[]): Promise<void> => {
  if (tsReSpawnIfNeeded(argv)) return
  const parsed = parseArgs(argv)
  if ('error' in parsed) {
    console.error(`wingnut: ${parsed.error}`)
    process.exit(1)
  }
  try {
    if (parsed.check) {
      const fresh = await runBuild({
        entryPath: parsed.entry,
        outDir: parsed.out,
        dialect: parsed.dialect,
        write: false,
      })
      const { ok, problems } = checkArtifact(fresh, parsed.out)
      if (ok) {
        if (!parsed.quiet) {
          console.log(
            `OK — artifact matches current routes (${fresh.keys.length} schemas)`,
          )
        }
        process.exit(0)
      }
      console.error(
        `DRIFT — ${problems.join('; ')}. Re-run: wingnut build --entry ${parsed.entry} --out ${parsed.out}`,
      )
      process.exit(3)
    }
    const { keys, bytes } = await runBuild({
      entryPath: parsed.entry,
      outDir: parsed.out,
      dialect: parsed.dialect,
    })
    console.log(
      `wrote ${keys.length} validators, ${(bytes / 1024).toFixed(1)} kB ` +
        `→ ${resolve(parsed.out)}/validators.cjs (+meta.json)`,
    )
    process.exit(0)
  } catch (e) {
    console.error(
      `wingnut build failed: ${e instanceof Error ? e.message : String(e)}`,
    )
    process.exit(1)
  }
}

// Entry point when run as a script (dist/cli.js).
if (typeof require !== 'undefined' && require.main === module) {
  main(process.argv.slice(2))
}
