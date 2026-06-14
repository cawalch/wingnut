import { ErrorRequestHandler, Request, RequestHandler, Response } from 'express'
// open api 3 typings

export type NamedHandler<S = string, User = unknown> = Record<
  S extends string ? S : string,
  ScopeHandler<User>
>

/**
 * A request carrying an optional auth context — the shape scope handlers and
 * `verify` see. `User` defaults to `unknown`, so `req.user` typing is opt-in
 * (Layer 3). Populate it via `Security<User>` / the scheme builders.
 */
export type AuthedRequest<User = unknown> = Request & { user?: User }

/**
 * Authorization scope predicate. Returns `true` when the request satisfies the
 * scope. `req.user` is typed when the owning `Security<User>` carries `User`.
 */
export interface ScopeHandler<User = unknown> {
  (req: AuthedRequest<User>, res: Response, next?: () => void): boolean
}

export interface AppObject {
  openapi: string
  info: {
    title: string
    version: string
    description: string
  }
  wrapper?: (cb: RequestHandler) => RequestHandler
  paths: PathItem
  components?: Components
}

/**
 * OpenAPI 3.0 Security Scheme Object.
 * @see https://spec.openapis.org/oas/v3.0.3#security-scheme-object
 */
export type SecuritySchemeType = 'apiKey' | 'http' | 'oauth2' | 'openIdConnect'

/**
 * OpenAPI 3.0 OAuth Flows Object.
 * @see https://spec.openapis.org/oas/v3.0.3#oauth-flows-object
 */
export interface OAuthFlowsObject {
  implicit?: {
    authorizationUrl: string
    refreshUrl?: string
    scopes: Record<string, string>
  }
  password?: {
    tokenUrl: string
    refreshUrl?: string
    scopes: Record<string, string>
  }
  clientCredentials?: {
    tokenUrl: string
    refreshUrl?: string
    scopes: Record<string, string>
  }
  authorizationCode?: {
    authorizationUrl: string
    tokenUrl: string
    refreshUrl?: string
    scopes: Record<string, string>
  }
}

/**
 * OpenAPI 3.0 Security Scheme Object. Required fields depend on `type`
 * (e.g. `name`/`in` for apiKey, `scheme` for http, `flows` for oauth2).
 * @see https://spec.openapis.org/oas/v3.0.3#security-scheme-object
 */
export interface SecuritySchemeObject {
  type: SecuritySchemeType
  description?: string
  /** Required when type === 'apiKey'. */
  name?: string
  /** Required when type === 'apiKey'. */
  in?: 'query' | 'header' | 'cookie'
  /** Required when type === 'http'. */
  scheme?: string
  /** Used together with http scheme 'bearer'. */
  bearerFormat?: string
  /** Required when type === 'oauth2'. */
  flows?: OAuthFlowsObject
  /** Required when type === 'openIdConnect'. */
  openIdConnectUrl?: string
}

/**
 * OpenAPI 3.0 `components.securitySchemes` map, keyed by scheme name.
 * Per-operation `security` references must resolve to a key here.
 */
export type SecuritySchemesObject = Record<string, SecuritySchemeObject>

interface Components {
  securitySchemes: SecuritySchemesObject
}

export interface PathItem {
  [path: string]: PathObject
}

export interface PathObject {
  get?: PathOperation
  post?: PathOperation
  put?: PathOperation
  delete?: PathOperation
}

export type SecurityObject = {
  [auth: string]: string[]
}[]

export type ScopeObject<S = string> = {
  auth: string
  scopes: (keyof NamedHandler<S>)[]
  middleware: RequestHandler[]
  responses?: MediaSchemaItem
}

export type ParamType =
  | 'integer'
  | 'number'
  | 'string'
  | 'array'
  | 'object'
  | 'boolean'

export interface ParamSchema extends Record<string, unknown> {
  type?: ParamType
  description?: string
  format?: string
  minimum?: number
  maximum?: number
  example?: unknown
  default?: unknown
  minLength?: number
  maxLength?: number
  minItems?: number
  maxItems?: number
  maxProperties?: number
  minProperties?: number
  nullable?: boolean
  required?: readonly string[]
  enum?: Readonly<number[] | string[]>
  properties?: {
    [key: string]: ParamSchema
  }
  additionalProperties?: boolean
  items?: ParamSchema
  pattern?: string
  uniqueItems?: boolean
  oneOf?: ParamSchema[]
  anyOf?: ParamSchema[]
  allOf?: ParamSchema[]
}

export interface Parameter {
  in: ParamIn
  name: string
  description?: string
  required?: boolean
  schema?: ParamSchema
  deprecated?: boolean
  examples?: {
    [ex: string]: {
      value: unknown
      summary?: string
    }
  }
}

export interface PathOperation {
  tags?: string[]
  operationId?: string
  summary?: string
  description?: string
  requestBody?: MediaSchema
  responses?: MediaSchemaItem
  scope?: ScopeObject[]
  security?: SecurityObject
  parameters?: Parameter[]
  wrapper?: (cb: RequestHandler) => RequestHandler
  middleware: Array<RequestHandler | ErrorRequestHandler>
}

export interface MediaSchemaItem {
  [code: string]: MediaSchema
}

export interface MediaSchema {
  description?: string
  required?: true
  content?: ContentItem
}

export interface ContentItem {
  [content: string]: {
    schema: ParamSchema
  }
}

export const inMap = {
  path: 'params',
  query: 'query',
  body: 'body',
  header: 'headers',
} as const

export type ParamIn = keyof typeof inMap
