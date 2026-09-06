/**
 * Differential parity: for every corpus schema, the live `createWingnutAjv`
 * validator and the standalone-generated one must agree on verdict AND on
 * the JSON-serialized AJV error array. Regression net for byte-identical
 * artifacts across AJV/option/facade changes.
 */

import { createRequire } from 'node:module'
import Ajv from 'ajv'
import Ajv2020 from 'ajv/dist/2020'
import standalone from 'ajv/dist/standalone'
import addFormats from 'ajv-formats'
import { describe, expect, it } from 'vitest'
import { createWingnutAjv } from '../index'

const requireCjs = createRequire(__filename)

type Case = { name: string; schema: Record<string, unknown>; values: unknown[] }

/** Compact edge-case corpus (full 354-schema fuzz lives in spike E1). */
const corpus: Case[] = [
  {
    name: 'query integer + coercion + range',
    schema: {
      type: 'object',
      properties: {
        limit: { type: 'integer', minimum: 1, maximum: 100 },
        kind: { type: 'string', enum: ['a', 'b', 'c'] },
      },
      required: ['limit'],
    },
    values: [
      { limit: '42', kind: 'a' },
      { limit: 0 },
      { kind: 'a' },
      { limit: '101' },
      { limit: '4.5' },
      { limit: null, kind: 'x' },
    ],
  },
  {
    name: 'body object, additionalProperties:false, formats',
    schema: {
      type: 'object',
      properties: {
        log: {
          type: 'object',
          properties: {
            message: { type: 'string', minLength: 1, maxLength: 200 },
            level: { type: 'string', enum: ['info', 'warn', 'error'] },
            ts: { type: 'string', format: 'date-time' },
          },
          required: ['message'],
          additionalProperties: false,
        },
        tags: { type: 'array', items: { type: 'string', format: 'hostname' } },
      },
      required: ['log'],
      additionalProperties: false,
    },
    values: [
      { log: { message: 'hi', level: 'info', ts: '2026-09-06T09:00:00Z' } },
      { log: { level: 'info' } },
      { log: { message: 'x', other: 1 } },
      { log: { message: 'x', ts: 'not-a-date' } },
      { log: { message: 'x' }, tags: [9] },
      { tags: ['ok.example'] },
    ],
  },
  {
    name: 'path param pattern',
    schema: {
      type: 'object',
      properties: { id: { type: 'string', pattern: '^[a-z]{4}$' } },
      required: ['id'],
    },
    values: [{ id: 'abcd' }, { id: 'ABC' }, { id: 'abc' }, { id: 1 }],
  },
  {
    name: 'header integer coercion',
    schema: {
      type: 'object',
      properties: { 'x-page': { type: 'integer', minimum: 1 } },
      required: ['x-page'],
    },
    values: [{ 'x-page': '3' }, { 'x-page': '0' }, { 'x-page': 'x' }, {}],
  },
  {
    name: 'combinators + nullable (o3.0 shorthand)',
    schema: {
      type: 'object',
      properties: {
        state: { type: 'string', enum: ['open', 'closed'], nullable: true },
        note: {
          if: { properties: { state: { const: 'closed' } } },
          then: {
            properties: { reason: { type: 'string', minLength: 3 } },
            required: ['reason'],
          },
        },
      },
      required: ['state'],
    },
    values: [
      { state: 'closed', note: { reason: 'done it' } },
      { state: 'closed', note: { reason: 'no' } },
      { state: null, note: { reason: 'x' } },
      { state: 'open' },
      { state: 'weird' },
    ],
  },
  {
    name: 'nested + multipleOf + exclusiveMinimum',
    schema: {
      type: 'object',
      properties: {
        cfg: {
          type: 'object',
          properties: {
            ratio: { type: 'number', multipleOf: 0.5 },
            temp: { type: 'number', exclusiveMinimum: 0 },
          },
          required: ['ratio', 'temp'],
        },
      },
      required: ['cfg'],
    },
    values: [
      { cfg: { ratio: 1.5, temp: 21 } },
      { cfg: { ratio: 1.2, temp: 21 } },
      { cfg: { ratio: 1.5, temp: 0 } },
      { cfg: { ratio: '2', temp: '-3' } },
      { cfg: {} },
    ],
  },
]

const run = (
  compile: (
    s: Record<string, unknown>,
  ) => ((d: unknown) => boolean) & { errors?: unknown },
  schema: Record<string, unknown>,
  value: unknown,
): { verdict: boolean; errors: string } => {
  const v = compile(schema)
  const data = structuredClone(value)
  const verdict = v(data)
  return { verdict, errors: JSON.stringify(v.errors ?? null) }
}

/** standaloneEmit — same IIFE wrap as the shipped CLI (return appended
 * after the const initializers). */
const emit = (
  genAjv: InstanceType<typeof Ajv> | InstanceType<typeof Ajv2020>,
  schema: Record<string, unknown>,
): ((data: unknown) => boolean) & { errors?: unknown } => {
  const code = standalone(genAjv, genAjv.compile(schema))
  const m = code.match(
    /^"use strict";module\.exports = (\w+);module\.exports\.default = \1;/,
  )
  if (!m) throw new Error('unexpected standalone output: ' + code.slice(0, 120))
  const fn = new Function(
    'require',
    `"use strict";return (()=>{${code.slice(m[0].length)}\nreturn ${m[1]}})()`,
  )
  return fn(requireCjs) as unknown as ((data: unknown) => boolean) & {
    errors?: unknown
  }
}

const makeGenAjv = (dialect: '3.0' | '3.1') => {
  const instance =
    dialect === '3.1'
      ? new Ajv2020({
          coerceTypes: true,
          allErrors: true,
          code: { source: true },
        })
      : new Ajv({ coerceTypes: true, allErrors: true, code: { source: true } })
  addFormats(instance)
  return instance
}

for (const dialect of ['3.0', '3.1'] as const) {
  describe(`parity (dialect ${dialect})`, () => {
    it('live AJV and standalone agree on verdict + error bytes', () => {
      const live = createWingnutAjv({ openapi: dialect })
      const gen = makeGenAjv(dialect)
      const total = corpus.reduce((n, c) => n + c.values.length, 0)
      let checked = 0
      for (const c of corpus) {
        for (const value of c.values) {
          const a = run((s) => live.compile(s), c.schema, value)
          const genValidator = emit(gen, c.schema)
          const data = structuredClone(value)
          const verdict = genValidator(data)
          const b = {
            verdict,
            errors: JSON.stringify(genValidator.errors ?? null),
          }
          expect(
            b,
            `mismatch on ${c.name} with ${JSON.stringify(value)}`,
          ).toEqual(a)
          checked++
        }
      }
      expect(checked).toBe(total)
    })
  })
}
