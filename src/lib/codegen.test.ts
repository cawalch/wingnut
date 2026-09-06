import { describe, expect, it } from 'vitest'
import type { AjvLikeValidateFunction } from '../types/common'
import type { CodegenMeta } from './codegen'
import {
  CODEGEN_CANONICAL_OPTIONS,
  codegenAjvLike,
  codegenOptionsHash,
  codegenSchemaKey,
  verifyCodegenMeta,
  WingnutCodegenError,
} from './codegen'

const schema = {
  type: 'object',
  properties: { limit: { type: 'integer', minimum: 1 } },
  required: ['limit'],
}

const fakeValidator = Object.assign(
  ((_d: unknown) => true) as unknown as AjvLikeValidateFunction,
  { errors: null },
)

const metaFor = (over: Partial<CodegenMeta> = {}): CodegenMeta => ({
  generator: 'wingnut@0.5.0',
  ajv: '8.20.0',
  ajvFormats: '3.0.1',
  dialect: '3.0',
  optionsHash: codegenOptionsHash('3.0'),
  count: 1,
  keys: [codegenSchemaKey(schema)],
  ...over,
})

describe('codegenOptionsHash', () => {
  it('is stable and dialect-sensitive', () => {
    expect(codegenOptionsHash('3.0')).toBe(codegenOptionsHash('3.0'))
    expect(codegenOptionsHash('3.0')).not.toBe(codegenOptionsHash('3.1'))
    expect(codegenOptionsHash('3.0')).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('codegenAjvLike', () => {
  it('returns the precompiled validator for a known schema', () => {
    const key = codegenSchemaKey(schema)
    const ajv = codegenAjvLike({ [key]: fakeValidator })
    expect(ajv.compile(schema)).toBe(fakeValidator)
  })

  it('fails closed on a schema with no precompiled entry', () => {
    const ajv = codegenAjvLike({})
    expect(() => ajv.compile(schema)).toThrowError(WingnutCodegenError)
    expect(() => ajv.compile(schema)).toThrow(/artifact is stale/)
  })

  it('verifies meta when provided', () => {
    const key = codegenSchemaKey(schema)
    const meta = metaFor()
    expect(() =>
      codegenAjvLike({ [key]: fakeValidator }, meta, {
        generator: 'wingnut@0.5.0',
        ajv: '8.20.0',
      }),
    ).not.toThrow()
  })

  it('rejects an incomplete artifact (recorded key missing)', () => {
    const meta = metaFor()
    expect(() =>
      codegenAjvLike({}, meta, {
        generator: 'wingnut@0.5.0',
        ajv: '8.20.0',
      }),
    ).toThrow(/incomplete/)
  })
})

describe('verifyCodegenMeta', () => {
  const expected = { generator: 'wingnut@0.5.0', ajv: '8.20.0' }

  it('accepts a matching meta', () => {
    expect(() => verifyCodegenMeta(metaFor(), expected)).not.toThrow()
  })

  it('rejects generator drift', () => {
    expect(() =>
      verifyCodegenMeta(metaFor({ generator: 'wingnut@0.6.0' }), expected),
    ).toThrow(/generator mismatch/)
  })

  it('rejects AJV major drift (but not minor)', () => {
    expect(() =>
      verifyCodegenMeta(metaFor({ ajv: '9.0.0' }), expected),
    ).toThrow(/AJV major mismatch/)
    expect(() =>
      verifyCodegenMeta(metaFor({ ajv: '8.21.4' }), expected),
    ).not.toThrow()
  })

  it('rejects options-hash drift', () => {
    expect(() =>
      verifyCodegenMeta(metaFor({ optionsHash: 'deadbeef' }), expected),
    ).toThrow(/options hash mismatch/)
  })
})

describe('canonical options constant', () => {
  it('matches createWingnutAjv defaults', () => {
    expect(CODEGEN_CANONICAL_OPTIONS).toEqual({
      formats: true,
      coerceTypes: true,
      allErrors: true,
    })
  })
})
