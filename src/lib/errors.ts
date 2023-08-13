export class WingnutError extends Error {
  constructor(message: string) {
    super(message);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = "WingnutError";
  }
}

export class ValidationError extends WingnutError {
  constructor(
    message: string,
    public context: unknown,
  ) {
    super(message);
    this.name = "ValidationError";
    this.context = context;
  }
}
