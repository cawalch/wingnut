/**
 * WnDataType<S> — zero-dependency, compile-time inference of a TypeScript
 * request type from a Wingnut / OpenAPI 3 / JSON Schema object literal.
 *
 * Why this exists instead of pulling in a schema library:
 *  - Pure type-level: no runtime emit, no third-party types. Wingnut ships
 *    against `ajv` + `express` only; request typing must not add a runtime dep.
 *  - Standards-native: the source of truth is a plain JSON Schema / OpenAPI
 *    object (portable to gateways, mock servers, contract tests), not a
 *    library-private runtime object (zod/typebox).
 *
 * Uses only type features stable since TS 5.0 (template literals, distributive
 * conditionals, `infer` with constraints, mapped types, `const`/`satisfies`).
 * TS 6.0 adds no schema-relevant primitives (it is a TS 7.0 Go-port transition
 * release), so this targets the broadest compatible toolchain.
 *
 * Literal preservation: declare schemas with `satisfies WnParamDef` (not `:`
 * annotation) so `type`/`enum`/`const` literals survive for inference. For
 * `enum` unions, add `as const` to the array.
 */
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
 * Map a single JSON-Schema `type` string to its TS primitive.
 * `array`/`object` defaults are only reached when no `items`/`properties` are
 * present; the structural branches in {@link WnCore} take precedence.
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

/** Reduce a readonly schema tuple to a union (used by `anyOf` / `oneOf`). */
type WnUnionOf<A extends ReadonlyArray<unknown>> = A extends readonly [
  infer Head,
  ...infer Rest,
]
  ? WnDataType<Head> | WnUnionOf<Rest>
  : never

/** Reduce a readonly schema tuple to an intersection (used by `allOf`). */
type WnIntersectOf<A extends ReadonlyArray<unknown>> = A extends readonly [
  infer Head,
  ...infer Rest,
]
  ? WnDataType<Head> & WnIntersectOf<Rest>
  : unknown

/** Required-key members of an object schema (`unknown` is the &-identity). */
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

/** Optional-key members of an object schema. */
type WnOptionalKeys<S> = S extends { properties: infer P }
  ? P extends Record<string, unknown>
    ? { [K in keyof P]?: WnDataType<P[K]> }
    : unknown
  : unknown

/** Index signature from `additionalProperties` (true, or a sub-schema). */
type WnAdditionalProps<S> = S extends { additionalProperties: infer A }
  ? A extends true
    ? { [key: string]: unknown }
    : A extends Record<string, unknown>
      ? { [key: string]: WnDataType<A> }
      : unknown
  : unknown

/**
 * Core resolution, pre-nullable. Branch order runs most-specific to
 * least-specific. `nullable` is applied by {@link WnDataType} as an *outer*
 * wrapper so it composes with every branch (e.g. a nullable enum → `E | null`,
 * not bare `E`).
 */
type WnCore<S> =
  // 1. const — a literal value wins outright.
  S extends { const: infer C }
    ? C
    : // 2. enum — union of members (use `as const` for literal unions).
      S extends { enum: infer E }
      ? E extends ReadonlyArray<infer V>
        ? V
        : never
      : // 3. composition keywords.
        S extends { anyOf: infer A }
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
            : // 4. param-shaped wrappers used by WnParamDef entries.
              S extends { schema: infer Sch; description: string }
              ? WnDataType<Sch>
              : S extends { schema: infer Sch; name: string }
                ? WnDataType<Sch>
                : // 5. array via explicit items.
                  S extends { items: infer I }
                  ? WnDataType<I>[]
                  : // 6. object via properties (+ required + additionalProperties).
                    S extends { properties: Record<string, unknown> }
                    ? WnOptionalKeys<S> &
                        WnRequiredKeys<S> &
                        WnAdditionalProps<S>
                    : // 7. bare `type` field (string, or array → union).
                      S extends { type: infer T }
                      ? T extends string
                        ? WnTypeOf<T>
                        : T extends ReadonlyArray<infer Elem extends string>
                          ? WnTypeOf<Elem>
                          : unknown
                      : // 8. fallback.
                        unknown

/**
 * Public entry point. Resolves a Wingnut/OpenAPI schema to the TypeScript type
 * a handler will see in `req.body` / `req.query` / `req.params`.
 *
 * `nullable: true` (OpenAPI 3.0) and `type` arrays including `'null'`
 * (JSON Schema / OpenAPI 3.1) both produce `| null`.
 *
 * @example
 * const P = {
 *   properties: {
 *     limit: { description: 'max', schema: { type: 'integer', minimum: 1 } },
 *     filter: { description: 'q', schema: { type: 'string', nullable: true } },
 *   },
 * } satisfies WnParamDef
 *
 * type Req = Request<unknown, unknown, unknown, WnDataType<typeof P>>
 * //   ^? { limit?: number; filter?: string | null }
 */
export type WnDataType<S> = S extends { nullable: true }
  ? WnCore<S> | null
  : WnCore<S>

/**
 * Map of named request parameters for `WnDataType` input. Each entry is a
 * `Parameter` minus its `in`/`name`. Use `satisfies WnParamDef` (not `:`) so
 * literals are preserved for inference.
 */
export type WnParamDef = Record<
  string,
  Record<string, Omit<Parameter, 'in' | 'name'>>
>
