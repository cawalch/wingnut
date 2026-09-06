export class WingnutError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'WingnutError'
  }
}

export class ValidationError extends WingnutError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'ValidationError'
  }

  get context() {
    return this.cause
  }
}

/**
 * Thrown via `next()` when a request's `Content-Type` does not match any
 * media type declared for the operation's request body (and no
 * `application/json` / `application/x-www-form-urlencoded` fallback is
 * declared). Error handlers should map `status` to an HTTP 415 response.
 */
export class UnsupportedMediaTypeError extends WingnutError {
  readonly status = 415

  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'UnsupportedMediaTypeError'
  }
}
