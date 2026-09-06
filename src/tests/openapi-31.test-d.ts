import type { Request } from 'express'
import type {
  WnDataType as PublicWnDataType,
  WnParamDef as PublicWnParamDef,
} from '../index'
import { createWingnutAjv } from '../index'
import type { AjvLike } from '../types/common'
import type { ContentItem, ParamSchema } from '../types/open-api-3'
import type { WnDataType } from '../types/wn-data'

// Bidirectional assignability: true when A and B are mutually assignable.
type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false

// --- ParamSchema accepts OpenAPI 3.1 / JSON Schema 2020-12 keywords ---

/** Representative 3.1 body schema: $defs, $ref, const, type arrays, rich
 * enum, not, if/then/else, numeric exclusiveMinimum, schema-valued
 * additionalProperties. */
export const _ref31: ParamSchema = {
  $defs: {
    Geo: {
      type: 'object',
      properties: { lat: { type: 'number' }, lng: { type: 'number' } },
      required: ['lat', 'lng'],
    },
  },
  type: 'object',
  properties: {
    status: { const: 'pending' },
    amount: { type: ['number', 'null'] },
    tags: { type: 'array', items: { enum: ['a', 'b', null] } },
    code: { not: { const: 0 } },
    label: {
      if: { type: 'string' },
      then: { maxLength: 4 },
      else: { type: 'null' },
    },
    ratio: { type: 'number', exclusiveMinimum: 0 },
    meta: { additionalProperties: { type: 'string' } },
    geo: { $ref: '#/$defs/Geo' },
  },
}

/** OpenAPI 3.0 schemas keep type-checking (regression guard). */
export const _legacy30: ParamSchema = {
  type: 'string',
  nullable: true,
  enum: ['a', 'b'],
  minLength: 1,
}

export const _content31: ContentItem = {
  'application/json': { schema: _ref31 },
}

// --- WnDataType resolves 3.1 constructs ---

/** $refs are resolved by Ajv at runtime; the TS-level type is `unknown`. */
export const _refUnknown: Equals<WnDataType<{ $ref: string }>, unknown> = true
/** Negation has no TS equivalent; falls back to `unknown`. */
export const _notUnknown: Equals<
  WnDataType<{ not: { const: 0 } }>,
  unknown
> = true
/** 2020-12 enum values may be any JSON value. */
export const _enumMixed: Equals<
  WnDataType<{ enum: readonly ['a', 'b', null] }>,
  'a' | 'b' | null
> = true
/** 3.1 type arrays resolve to the union (including null). */
export const _typeArrNumberNull: Equals<
  WnDataType<{ type: readonly ['number', 'null'] }>,
  number | null
> = true
export const _constNumber: Equals<WnDataType<{ const: 7 }>, 7> = true

// --- public entry surface (README imports) ---

const ListQueryParams = {
  properties: {
    limit: { description: 'max', schema: { type: 'integer', minimum: 1 } },
  },
} satisfies PublicWnParamDef

type ListQuery = PublicWnDataType<typeof ListQueryParams>
export const _publicEntry: Equals<ListQuery, { limit?: number }> = true
export type _publicRequest = Request<unknown, unknown, unknown, ListQuery>

// --- the 3.1 factory output is an injectable AjvLike ---

export const _ajv31IsAjvLike: AjvLike = createWingnutAjv({ openapi: '3.1' })
export const _ajv30IsAjvLike: AjvLike = createWingnutAjv()
