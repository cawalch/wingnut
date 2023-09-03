import { RequestHandler } from "express";
// open api 3 typings

export type NamedHandler<S> = Record<
  S extends string ? S : string,
  ScopeHandler
>;

export interface AppObject {
  openapi: string;
  info: {
    title: string;
    version: string;
    description: string;
  };
  wrapper?: (cb: RequestHandler) => RequestHandler;
  paths: PathItem;
  components?: Components;
}

interface Components {
  securitySchemas: SecuritySchemesObject;
}

interface SecuritySchemesObject {
  [y: string]: {
    type: string;
    [z: string]: unknown;
  };
}

export interface PathItem {
  [path: string]: PathObject;
}

export interface PathObject {
  get?: PathOperation;
  post?: PathOperation;
  put?: PathOperation;
  delete?: PathOperation;
}

export type SecurityObject = {
  [auth: string]: string[];
}[];

export interface ScopeHandler {
  (req: unknown, res: unknown, next?: () => void): boolean;
}

export type ScopeObject<S = string> = {
  auth: string;
  scopes: (keyof NamedHandler<S>)[];
  middleware: RequestHandler[];
  responses?: MediaSchemaItem;
};

export type ParamType =
  | "integer"
  | "number"
  | "string"
  | "array"
  | "object"
  | "boolean";

export interface ParamSchema extends Record<string, unknown> {
  type?: ParamType;
  description?: string;
  format?: string;
  minimum?: number;
  maximum?: number;
  example?: unknown;
  default?: unknown;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  maxItems?: number;
  maxProperties?: number;
  minProperties?: number;
  nullable?: boolean;
  required?: readonly string[];
  enum?: Readonly<number[] | string[]>;
  properties?: {
    [key: string]: ParamSchema;
  };
  additionalProperties?: boolean;
  items?: ParamSchema;
  pattern?: string;
  uniqueItems?: boolean;
  oneOf?: ParamSchema[];
  anyOf?: ParamSchema[];
  allOf?: ParamSchema[];
}

export interface Parameter {
  in: ParamIn;
  name: string;
  description?: string;
  required?: boolean;
  schema?: ParamSchema;
  deprecated?: boolean;
  examples?: {
    [ex: string]: {
      value: unknown;
      summary?: string;
    };
  };
}

export interface PathOperation {
  tags?: string[];
  operationId?: string;
  summary?: string;
  description?: string;
  requestBody?: MediaSchema;
  responses?: MediaSchemaItem;
  scope?: ScopeObject[];
  security?: SecurityObject;
  parameters?: Parameter[];
  wrapper?: (cb: RequestHandler) => RequestHandler;
  middleware: RequestHandler[];
}

export interface MediaSchemaItem {
  [code: string]: MediaSchema;
}

export interface MediaSchema {
  description?: string;
  required?: true;
  content?: ContentItem;
}

export interface ContentItem {
  [content: string]: {
    schema: ParamSchema;
  };
}

export const inMap = {
  path: "params",
  query: "query",
  body: "body",
};

export type ParamIn = "query" | "path" | "body";
// export type ParamIn = "query" | "path" | "header" | "body" | "cookie";
