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
