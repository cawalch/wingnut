/**
 * Type-level tests for WnDataType. These are compile-time assertions: each
 * `export const _x: Equals<Actual, Expected> = true` fails to compile if the
 * inferred type drifts from the expected shape. Run via `pnpm typecheck`.
 *
 * Covers the gaps the previous WnDataType silently dropped to `unknown`:
 * nullable, enum, const, anyOf/oneOf/allOf, type arrays, required vs optional,
 * array items, additionalProperties, and the param-shaped WnParamDef wrappers.
 */
import type { Request } from 'express'
import type { WnDataType, WnParamDef } from '../types/wn-data'

// Bidirectional assignability (semantically equal, not type-identity strict).
// Identity-strict Equals falsely rejects equivalent intersection/merged forms.
type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false

// --- primitives & numeric formats ------------------------------------------
export const _int: Equals<WnDataType<{ type: 'integer' }>, number> = true
export const _int64: Equals<WnDataType<{ type: 'int64' }>, number> = true
export const _str: Equals<WnDataType<{ type: 'string' }>, string> = true
export const _bool: Equals<WnDataType<{ type: 'boolean' }>, boolean> = true

// --- const & enum (the old enum branch only matched type:'string') ---------
export const _const: Equals<WnDataType<{ const: 'pending' }>, 'pending'> = true
export const _enumNum: Equals<
  WnDataType<{ type: 'integer'; enum: readonly [1, 2, 3] }>,
  1 | 2 | 3
> = true
export const _enumStr: Equals<
  WnDataType<{ type: 'string'; enum: readonly ['a', 'b'] }>,
  'a' | 'b'
> = true

// --- nullable (was dropped: old code returned bare string) -----------------
export const _nullableStr: Equals<
  WnDataType<{ type: 'string'; nullable: true }>,
  string | null
> = true
export const _nullableEnum: Equals<
  WnDataType<{ enum: readonly ['x', 'y']; nullable: true }>,
  'x' | 'y' | null
> = true
export const _typeArrNull: Equals<
  WnDataType<{ type: readonly ['string', 'null'] }>,
  string | null
> = true

// --- composition (previously `unknown`) ------------------------------------
export const _anyOf: Equals<
  WnDataType<{ anyOf: readonly [{ type: 'string' }, { type: 'integer' }] }>,
  string | number
> = true
export const _oneOf: Equals<
  WnDataType<{ oneOf: readonly [{ type: 'boolean' }, { type: 'null' }] }>,
  boolean | null
> = true
export const _allOf: Equals<
  WnDataType<{
    allOf: readonly [
      { properties: { a: { type: 'string' } } },
      { properties: { b: { type: 'integer' } }; required: readonly ['b'] },
    ]
  }>,
  { a?: string } & { b: number }
> = true

// --- arrays of objects ------------------------------------------------------
export const _arrOfObj: Equals<
  WnDataType<{
    type: 'array'
    items: { type: 'object'; properties: { id: { type: 'integer' } } }
  }>,
  { id?: number }[]
> = true

// --- objects: required vs optional, additionalProperties -------------------
export const _objMixed: Equals<
  WnDataType<{
    type: 'object'
    properties: {
      name: { type: 'string' }
      age: { type: 'integer' }
    }
    required: readonly ['name']
  }>,
  { name?: string; age?: number } & { name: string }
> = true
export const _objAdditional: Equals<
  WnDataType<{
    type: 'object'
    properties: { k: { type: 'string' } }
    additionalProperties: true
  }>,
  { k?: string } & { [key: string]: unknown }
> = true

// --- WnParamDef wrapper (README pattern) -----------------------------------
const ListQueryParams = {
  properties: {
    limit: { description: 'max', schema: { type: 'integer', minimum: 1 } },
    filter: {
      description: 'q',
      schema: { type: 'string', nullable: true },
    },
  },
} satisfies WnParamDef

type ListQuery = WnDataType<typeof ListQueryParams>
export const _paramDef: Equals<
  ListQuery,
  { limit?: number; filter?: string | null }
> = true

// Wiring into express Request<...> compiles (no value assertion).
export type _ListRequest = Request<unknown, unknown, unknown, ListQuery>
