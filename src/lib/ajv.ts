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
    let addFormats: (ajv: Ajv) => Ajv
    try {
      ;({ default: addFormats } = require('ajv-formats'))
    } catch {
      throw new Error(
        "wingnut: createWingnutAjv({ formats: true }) needs the 'ajv-formats' package. Install it, or pass { formats: false }.",
      )
    }
    addFormats(instance)
  }
  return instance
}
