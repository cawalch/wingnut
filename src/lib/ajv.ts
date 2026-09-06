import Ajv from 'ajv'
import Ajv2020 from 'ajv/dist/2020'

export interface WingnutAjvOptions {
  /**
   * Schema dialect evaluated at runtime.
   *
   * - `'3.0'` (default): the draft-07 Ajv. Evaluates OpenAPI 3.0 schemas;
   *   Ajv also accepts and correctly validates the common 3.1 shorthands
   *   (`nullable: true`, `type` arrays like `['string', 'null']`, `const`,
   *   same-document `$ref`).
   * - `'3.1'`: Ajv 2020 (JSON Schema 2020-12) for full OpenAPI 3.1
   *   semantics, e.g. cross-schema `$ref` resolution via `addSchema`.
   */
  openapi?: '3.0' | '3.1'
  /** Install ajv-formats so `format` (uuid, email, date-time, ...) validates. Default true. */
  formats?: boolean
  /** Coerce strings to numbers/booleans (Express hands query/path params as strings). Default true. */
  coerceTypes?: boolean
  /** Collect all validation errors, not just the first. Default true. */
  allErrors?: boolean
}

export const createWingnutAjv = (
  options: WingnutAjvOptions = {},
): Ajv | Ajv2020 => {
  const {
    formats = true,
    coerceTypes = true,
    allErrors = true,
    openapi = '3.0',
  } = options
  const instance =
    openapi === '3.1'
      ? new Ajv2020({ coerceTypes, allErrors })
      : new Ajv({ coerceTypes, allErrors })
  if (formats) {
    const { default: addFormats } = require('ajv-formats')
    addFormats(instance)
  }
  return instance
}
