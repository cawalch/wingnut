/**
 * Layer 1 — Authentication scheme builders.
 *
 * Each builder returns a {@link Security} with credential extraction wired into
 * `before`, the correct OpenAPI {@link SecuritySchemeObject} populated on
 * `scheme`, and a 401 slot in `unauthorized`. Callers supply a `verify`
 * function (bring-your-own crypto — wingnut ships no JWT/OAuth/session library)
 * and the authorization `scopes`; wingnut composes the middleware and emits the
 * documentation. Failed `verify` → 401; failed scope → 403.
 *
 * @see ROADMAP.md "Layer 1 — Authentication scheme builders"
 */
import type { Request, RequestHandler } from 'express'
import type {
  MediaSchemaItem,
  NamedHandler,
  OAuthFlowsObject,
  SecuritySchemeObject,
} from '../types/open-api-3'
import type { Security } from './index'

/**
 * Caller-supplied credential verification. Returning `false` or throwing routes
 * the request to the 401 handler. Populate `req.user` here (bring-your-own
 * crypto).
 */
export type Verify = (
  credential: string,
  req: Request,
) => boolean | Promise<boolean>

const BEARER_PATTERN = /^Bearer\s+(.+)$/i

const extractBearerToken = (req: Request): string | undefined => {
  const match = BEARER_PATTERN.exec(req.headers.authorization ?? '')
  return match?.[1]
}

const readQueryParam = (req: Request, name: string): string | undefined => {
  const value = (req.query as Record<string, unknown>)[name]
  if (typeof value === 'string') return value
  if (Array.isArray(value) && typeof value[0] === 'string') return value[0]
  return undefined
}

const defaultUnauthorized: RequestHandler = (_req, res) => {
  res.set('WWW-Authenticate', 'Bearer').status(401).send('Unauthorized')
}

const defaultForbidden: RequestHandler = (_req, res) => {
  res.status(403).send('Forbidden')
}

const defaultResponses: MediaSchemaItem = {
  '401': { description: 'Unauthenticated' },
  '403': { description: 'Forbidden' },
}

/**
 * Build the `before` extraction/verification handler. Extracts the credential,
 * runs the caller's `verify`, and either fails closed through the unauthorized
 * (401) handler or proceeds to `next()` so the scope layer can authorize.
 */
const buildVerifyBefore =
  (
    extract: (req: Request) => string | undefined,
    verify: Verify,
    unauthorized: RequestHandler,
  ): RequestHandler =>
  async (req, res, next) => {
    const credential = extract(req)
    if (credential === undefined) {
      unauthorized(req, res, next)
      return
    }
    try {
      const ok = await verify(credential, req)
      if (!ok) {
        unauthorized(req, res, next)
        return
      }
    } catch {
      unauthorized(req, res, next)
      return
    }
    next()
  }

/** Fields shared by every scheme-builder config. */
interface SchemeAuthConfig<S extends string> {
  /** components.securitySchemes key + per-operation security reference name. */
  name: string
  description?: string
  /** Caller-supplied verification. `false` or a throw → 401. */
  verify: Verify
  /** Override the default 401 handler. */
  unauthorized?: RequestHandler
  /** Override the default 403 handler. */
  forbidden?: RequestHandler
  /** Authorization scope handlers — the authorization half. */
  scopes?: NamedHandler<S>
  /** Override or extend the default 401/403 response documentation. */
  responses?: MediaSchemaItem
}

const resolveScopes = <S extends string>(
  scopes: NamedHandler<S> | undefined,
): NamedHandler<S> => (scopes ?? {}) as NamedHandler<S>

/**
 * bearerAuth
 *
 * Build a `Security` for HTTP Bearer authentication. Extracts the token from
 * the `Authorization: Bearer <token>` header and emits an
 * `{ type: 'http', scheme: 'bearer' }` securityScheme.
 *
 * ```typescript
 * interface AuthedRequest extends Request {
 *   user?: { role: string }
 * }
 *
 * const jwt = bearerAuth({
 *   name: 'bearerAuth',
 *   description: 'JWT access token',
 *   bearerFormat: 'JWT',
 *   verify: (token, req) => {
 *     try {
 *       ;(req as AuthedRequest).user = verifyJwt(token) // caller's lib
 *       return true
 *     } catch {
 *       return false // → 401
 *     }
 *   },
 *   scopes: {
 *     admin: (req) => (req as AuthedRequest).user?.role === 'admin',
 *   },
 * })
 *
 * // authorization layer — failed scope → 403
 * const editUser = authPathOp(scope(jwt, 'admin'))(putMethod({ ... }))
 * ```
 */
export const bearerAuth = <S extends string = string>(
  config: SchemeAuthConfig<S> & {
    /** `bearerFormat` for the scheme (e.g. 'JWT'). Omitted from the scheme when unset. */
    bearerFormat?: string
  },
): Security<S> => {
  const unauthorized = config.unauthorized ?? defaultUnauthorized
  const scheme: SecuritySchemeObject = { type: 'http', scheme: 'bearer' }
  if (config.bearerFormat) scheme.bearerFormat = config.bearerFormat
  if (config.description) scheme.description = config.description

  return {
    name: config.name,
    scheme,
    before: buildVerifyBefore(extractBearerToken, config.verify, unauthorized),
    unauthorized,
    forbidden: config.forbidden ?? defaultForbidden,
    scopes: resolveScopes(config.scopes),
    responses: { ...defaultResponses, ...config.responses },
  }
}

/**
 * apiKey
 *
 * Build a `Security` for API-key authentication in a header, query parameter,
 * or cookie. Emits an `{ type: 'apiKey', in, name }` securityScheme. Cookie
 * extraction reads `req.cookies` — supply `cookie-parser` yourself when using
 * `in: 'cookie'`.
 *
 * ```typescript
 * const key = apiKey({
 *   name: 'apiKey',
 *   in: 'header',
 *   fieldName: 'X-API-Key',
 *   verify: (value, req) => {
 *     ;(req as AuthedRequest).user = lookupKey(value)
 *     return !!req.user
 *   },
 * })
 * ```
 */
export const apiKey = <S extends string = string>(
  config: SchemeAuthConfig<S> & {
    /** Location of the credential. */
    in: 'query' | 'header' | 'cookie'
    /** Header name, query parameter, or cookie name (the OpenAPI `name` field). */
    fieldName: string
  },
): Security<S> => {
  const unauthorized = config.unauthorized ?? defaultUnauthorized
  const extract = (req: Request): string | undefined => {
    if (config.in === 'header') {
      const value = req.headers[config.fieldName.toLowerCase()]
      if (typeof value === 'string') return value
      if (Array.isArray(value) && typeof value[0] === 'string') {
        return value[0]
      }
      return undefined
    }
    if (config.in === 'query') return readQueryParam(req, config.fieldName)
    return req.cookies?.[config.fieldName]
  }
  const scheme: SecuritySchemeObject = {
    type: 'apiKey',
    in: config.in,
    name: config.fieldName,
  }
  if (config.description) scheme.description = config.description

  return {
    name: config.name,
    scheme,
    before: buildVerifyBefore(extract, config.verify, unauthorized),
    unauthorized,
    forbidden: config.forbidden ?? defaultForbidden,
    scopes: resolveScopes(config.scopes),
    responses: { ...defaultResponses, ...config.responses },
  }
}

/**
 * oauth2
 *
 * Build a `Security` for OAuth 2.0. Access tokens are extracted from the
 * `Authorization: Bearer <token>` header (same as {@link bearerAuth}); the
 * `flows` field documents the configured OAuth 2.0 flows on the emitted
 * `{ type: 'oauth2' }` securityScheme.
 *
 * ```typescript
 * const auth = oauth2({
 *   name: 'oauth2',
 *   flows: {
 *     authorizationCode: {
 *       authorizationUrl: 'https://example.com/oauth/authorize',
 *       tokenUrl: 'https://example.com/oauth/token',
 *       scopes: { read: 'read access', write: 'write access' },
 *     },
 *   },
 *   verify: (token, req) => {
 *     ;(req as AuthedRequest).user = verifyAccessToken(token)
 *     return !!req.user
 *   },
 * })
 * ```
 */
export const oauth2 = <S extends string = string>(
  config: SchemeAuthConfig<S> & {
    /** OpenAPI OAuth Flows Object — required for an oauth2 scheme. */
    flows: OAuthFlowsObject
  },
): Security<S> => {
  const unauthorized = config.unauthorized ?? defaultUnauthorized
  const scheme: SecuritySchemeObject = { type: 'oauth2', flows: config.flows }
  if (config.description) scheme.description = config.description

  return {
    name: config.name,
    scheme,
    before: buildVerifyBefore(extractBearerToken, config.verify, unauthorized),
    unauthorized,
    forbidden: config.forbidden ?? defaultForbidden,
    scopes: resolveScopes(config.scopes),
    responses: { ...defaultResponses, ...config.responses },
  }
}
