import Ajv from 'ajv'

export interface WingnutAjvOptions {
  /** Install ajv-formats so `format` (uuid, email, date-time, ...) validates. Default true. */
  formats?: boolean
  /** Coerce strings to numbers/booleans (Express hands query/path params as strings). Default true. */
  coerceTypes?: boolean
  /** Collect all validation errors, not just the first. Default true. */
  allErrors?: boolean
}

export const createWingnutAjv = (options: WingnutAjvOptions = {}): Ajv => {
  const { formats = true, coerceTypes = true, allErrors = true } = options
  const instance = new Ajv({ coerceTypes, allErrors })
  if (formats) {
    const { default: addFormats } = require('ajv-formats')
    addFormats(instance)
  }
  return instance
}
