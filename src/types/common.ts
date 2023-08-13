export type RequestLikeHandler = (
  req: any,
  res: any,
  next: () => void,
) => Promise<void> | void;

export type Route = (path: string, ...handler: RequestLikeHandler[]) => void;

export type Router = {
  get?: Route;
  post?: Route;
  put?: Route;
  delete?: Route;
  patch?: Route;
  stack: any;
};

export type ConnectLike = {
  use: (path: string, router: any) => void;
  _router: {
    stack: any;
  };
};

export type AjvErrorLikeObject = {
  propertyName?: string;
  message?: string;
  data?: unknown;
};

export interface AjvLikeValidateFunction<T = unknown> {
  (this: AjvLike | any, schema: any): schema is T;
  errors?: null | AjvErrorLikeObject[];
}

export type AjvLike = {
  compile: (schema: Record<string, unknown>) => AjvLikeValidateFunction;
};

export type AjvLikeSchemaObject = any;
