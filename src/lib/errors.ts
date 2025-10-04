export class WingnutError extends Error {
  private _stack?: string

  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'WingnutError'
    // Capture the initial stack trace from Error constructor
    const initialStack = (this as any).stack
    // Delete the stack property set by Error constructor to allow our getter/setter to work
    delete (this as any).stack
    // Store the initial stack for lazy access
    this._stack = initialStack
  }

  // Lazy stack trace capture
  get stack(): string | undefined {
    if (!this._stack && Error.captureStackTrace) {
      // Temporarily allow direct property assignment
      const tempStack: any = {}
      Error.captureStackTrace(tempStack, this.constructor)
      this._stack = tempStack.stack
    }
    return this._stack
  }

  set stack(value: string | undefined) {
    this._stack = value
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
