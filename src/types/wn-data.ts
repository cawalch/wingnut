import type { Parameter } from './open-api-3'

/** Numeric JSON-Schema / OpenAPI-3 formats that resolve to TS `number`. */
export type WnNumberType =
  | 'integer'
  | 'number'
  | 'int'
  | 'int8'
  | 'int16'
  | 'int32'
  | 'int64'
  | 'uint8'
  | 'uint16'
  | 'uint32'
  | 'uint64'
  | 'short'
  | 'long'
  | 'float'
  | 'double'

/**
 * Map a JSON-Schema `type` string to its TS primitive.
 */
export type WnTypeOf<T extends string> = T extends WnNumberType
  ? number
  : T extends 'string'
    ? string
    : T extends 'boolean'
      ? boolean
      : T extends 'null'
        ? null
        : T extends 'array'
          ? unknown[]
          : T extends 'object'
            ? Record<string, unknown>
            : unknown

type WnUnionOf<A extends ReadonlyArray<unknown>> = A extends readonly [
  infer Head,
  ...infer Rest,
]
  ? WnDataType<Head> | WnUnionOf<Rest>
  : never

type WnIntersectOf<A extends ReadonlyArray<unknown>> = A extends readonly [
  infer Head,
  ...infer Rest,
]
  ? WnDataType<Head> & WnIntersectOf<Rest>
  : unknown

type WnRequiredKeys<S> = S extends {
  properties: infer P
  required: infer R
}
  ? P extends Record<string, unknown>
    ? R extends ReadonlyArray<string>
      ? {
          [K in R[number] & keyof P]: WnDataType<P[K]>
        }
      : unknown
    : unknown
  : unknown

type WnOptionalKeys<S> = S extends { properties: infer P }
  ? P extends Record<string, unknown>
    ? { [K in keyof P]?: WnDataType<P[K]> }
    : unknown
  : unknown

type WnAdditionalProps<S> = S extends { additionalProperties: infer A }
  ? A extends true
    ? { [key: string]: unknown }
    : A extends Record<string, unknown>
      ? { [key: string]: WnDataType<A> }
      : unknown
  : unknown

type WnCore<S> = S extends { const: infer C }
  ? C
  : S extends { enum: infer E }
    ? E extends ReadonlyArray<infer V>
      ? V
      : never
    : S extends { anyOf: infer A }
      ? A extends ReadonlyArray<unknown>
        ? WnUnionOf<A>
        : never
      : S extends { oneOf: infer O }
        ? O extends ReadonlyArray<unknown>
          ? WnUnionOf<O>
          : never
        : S extends { allOf: infer L }
          ? L extends ReadonlyArray<unknown>
            ? WnIntersectOf<L>
            : never
          : S extends { schema: infer Sch; description: string }
            ? WnDataType<Sch>
            : S extends { schema: infer Sch; name: string }
              ? WnDataType<Sch>
              : S extends { items: infer I }
                ? WnDataType<I>[]
                : S extends { properties: Record<string, unknown> }
                  ? WnOptionalKeys<S> & WnRequiredKeys<S> & WnAdditionalProps<S>
                  : S extends { type: infer T }
                    ? T extends string
                      ? WnTypeOf<T>
                      : T extends ReadonlyArray<infer Elem extends string>
                        ? WnTypeOf<Elem>
                        : unknown
                    : unknown

/**
 * WnDataType
 *
 * Resolve a Wingnut / OpenAPI-3 schema to the TS request type.
 * Applied to `req.body`, `req.query`, or `req.params` via `WnParamDef`.
 *
 * `nullable: true` (OpenAPI 3.0) and `type` arrays including `'null'`
 * (JSON Schema / OpenAPI 3.1) both resolve to `T | null`.
 *
 * ```typescript
 * const Params = {
 *   properties: {
 *     limit: { description: 'max', schema: { type: 'integer', minimum: 1 } },
 *     filter: { description: 'q', schema: { type: 'string', nullable: true } },
 *   },
 * } satisfies WnParamDef
 *
 * type Req = Request<unknown, unknown, unknown, WnDataType<typeof Params>>
 * //   ^? { limit?: number; filter?: string | null }
 * ```
 */
export type WnDataType<S> = S extends { nullable: true }
  ? WnCore<S> | null
  : WnCore<S>

/**
 * WnParamDef
 *
 * Map of named request parameters for `WnDataType` input.
 * Use `satisfies` (not `:`) so literals are preserved for inference.
 *
 * ```typescript
 * const Params = {
 *   properties: {
 *     limit: { description: 'max', schema: { type: 'integer', minimum: 1 } },
 *   },
 * } satisfies WnParamDef
 *
 * type Req = Request<unknown, unknown, unknown, WnDataType<typeof Params>>
 * ```
 */
export type WnParamDef = Record<
  string,
  Record<string, Omit<Parameter, 'in' | 'name'>>
>
