/**
 * `wingnut build` CLI end-to-end: spawn the real dist/cli.js against a temp
 * entry, run the artifact through dist/codegen, compare vs the live facade.
 * Requires a prior `pnpm build`.
 */

import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'

const repoRoot = resolve(__dirname, '..', '..')
const dist = join(repoRoot, 'dist')
const requireCjs = createRequire(__filename)

const distExists = existsSync(join(dist, 'cli.js'))
const describeIf = distExists ? describe : describe.skipIf(true)

let workDir: string
let outDir: string
let entryPath: string

const entrySource = (schema: Record<string, unknown>) => `
import { createRequire } from 'node:module'
const requireHere = createRequire(import.meta.url)
const express = requireHere(${JSON.stringify(join(repoRoot, 'node_modules', 'express'))})
const wn = requireHere(${JSON.stringify(join(dist, 'index.js'))})

export const build = (ajvLike) => {
  const { route, paths, controller } = wn.wingnut(ajvLike)
  const app = express()
  paths(
    app,
    controller({
      prefix: '',
      route: (router) =>
        route(
          router,
          wn.path(
            '/items',
            wn.getMethod({
              parameters: [
                wn.queryParam({
                  name: 'limit',
                  required: true,
                  schema: ${JSON.stringify(schema)},
                }),
              ],
              middleware: [(req, res) => res.json({ ok: true })],
            }),
          ),
        ),
    }),
  )
  return app
}
`

describeIf('wingnut build CLI (e2e, requires pnpm build)', () => {
  beforeAll(() => {
    workDir = mkdtempSync(join(tmpdir(), 'wn-codegen-e2e-'))
    outDir = join(workDir, 'generated')
    entryPath = join(workDir, 'entry.mjs')
  })

  it('builds validators.cjs + meta.json from a real app entry', () => {
    writeFileSync(entryPath, entrySource({ type: 'integer', minimum: 1 }))
    const r = spawnSync(
      process.execPath,
      [join(dist, 'cli.js'), 'build', '--entry', entryPath, '--out', outDir],
      { encoding: 'utf8' },
    )
    expect(r.status, r.stderr).toBe(0)
    expect(r.stdout).toMatch(/wrote 1 validators/)
    expect(existsSync(join(outDir, 'validators.cjs'))).toBe(true)
    const meta = JSON.parse(readFileSync(join(outDir, 'meta.json'), 'utf8'))
    expect(meta.generator).toMatch(/^wingnut@/)
    expect(meta.ajv).toMatch(/^8\./)
    expect(meta.count).toBe(1)
    expect(meta.keys).toHaveLength(1)
  })

  it('generated artifact is byte-parity with the live facade', () => {
    const validators = requireCjs(join(outDir, 'validators.cjs'))
    const meta = JSON.parse(readFileSync(join(outDir, 'meta.json'), 'utf8'))
    const codegen = requireCjs(join(dist, 'codegen', 'index.js'))
    const live = requireCjs(join(dist, 'index.js'))

    const liveAjv = live.createWingnutAjv()
    const genAjv = codegen.codegenAjvLikeVerified(validators, meta)

    // meta.keys[0] is the exact facade-shaped schema the middleware compiles
    const schema = JSON.parse(meta.keys[0])
    for (const value of [{ limit: '5' }, { limit: 0 }, { limit: 'x' }, {}]) {
      const lv = liveAjv.compile(schema)
      const gv = genAjv.compile(schema)
      const a = structuredClone(value)
      const b = structuredClone(value)
      expect(gv(b)).toBe(lv(a))
      expect(JSON.stringify(gv.errors ?? null)).toBe(
        JSON.stringify(lv.errors ?? null),
      )
    }
  })

  it('fails closed on a stale artifact (schema not in map)', () => {
    const validators = requireCjs(join(outDir, 'validators.cjs'))
    const codegen = requireCjs(join(dist, 'codegen', 'index.js'))
    const genAjv = codegen.codegenAjvLike(validators)
    expect(() =>
      genAjv.compile({ type: 'object', properties: { other: {} } }),
    ).toThrow(/artifact is stale/)
  })

  it('thin bundle contains no AJV requires; createWingnutAjv throws', () => {
    const bundle = readFileSync(join(dist, 'codegen', 'index.js'), 'utf8')
    expect(bundle).not.toMatch(/require\((["'])ajv\1\)/)
    expect(bundle).not.toMatch(/require\((["'])ajv-formats\1\)/)
    const codegen = requireCjs(join(dist, 'codegen', 'index.js'))
    expect(() => codegen.createWingnutAjv()).toThrow(/codegen mode/)
  })

  it('--check passes on a matching artifact and exits 3 on drift', () => {
    const ok = spawnSync(
      process.execPath,
      [
        join(dist, 'cli.js'),
        'build',
        '--entry',
        entryPath,
        '--out',
        outDir,
        '--check',
      ],
      { encoding: 'utf8' },
    )
    expect(ok.status, ok.stderr).toBe(0)

    writeFileSync(entryPath, entrySource({ type: 'integer', minimum: 2 }))
    const drift = spawnSync(
      process.execPath,
      [
        join(dist, 'cli.js'),
        'build',
        '--entry',
        entryPath,
        '--out',
        outDir,
        '--check',
      ],
      { encoding: 'utf8' },
    )
    expect(drift.status).toBe(3)
    expect(drift.stderr).toMatch(/schema drift/)
  })

  it('rejects unknown args and missing required flags', () => {
    const r = spawnSync(
      process.execPath,
      [join(dist, 'cli.js'), 'build', '--bogus'],
      { encoding: 'utf8' },
    )
    expect(r.status).toBe(1)
    expect(r.stderr).toMatch(/unknown argument/)
    const r2 = spawnSync(
      process.execPath,
      [join(dist, 'cli.js'), 'frobnicate'],
      { encoding: 'utf8' },
    )
    expect(r2.status).toBe(1)
    expect(r2.stderr).toMatch(/unknown command/)
  })
})
