import {
  ErrorRequestHandler,
  NextFunction,
  Request,
  RequestHandler,
  Response,
  Router,
} from 'express'
import {
  AjvLike,
  AjvLikeSchemaObject,
  AjvLikeValidateFunction,
} from '../types/common'
import {
  AppObject,
  AuthedRequest,
  inMap,
  MediaSchemaItem,
  NamedHandler,
  Parameter,
  ParamIn,
  ParamSchema,
  PathItem,
  PathObject,
  PathOperation,
  ScopeHandler,
  ScopeObject,
  SecuritySchemeObject,
  SecuritySchemesObject,
} from '../types/open-api-3'
import { ValidationError } from './errors'

// Layer 1 scheme builders (bearerAuth / apiKey / oauth2). Type-only import of
// `Security` is erased, so there is no runtime cycle between the two modules.
export * from './security'

export type AppRoute = { paths: PathItem[]; router: Router }

export type ValidateByParam = Record<
  ParamIn,
  AjvLikeValidateFunction | undefined
>

export interface Security<S = string, User = unknown> {
  name: string
  /**
   * OpenAPI Security Scheme documentation for this definition. Emitted into
   * `components.securitySchemes` by `securitySchemes()` so per-operation
   * `security` references resolve in Swagger UI / Redoc / Schemathesis.
   */
  scheme?: SecuritySchemeObject
  /**
   * Credential-extraction / pre-authorization hook (e.g. parse + verify a
   * token and populate `req.user`). Runs before scope evaluation.
   */
  before?: RequestHandler
  /**
   * Unauthenticated (401) handler. Invoked when credential extraction
   * reports a missing or invalid credential — e.g. a Layer 1 `bearerAuth`
   * `verify` returning `false`. Optional at Layer 0: when omitted, `before`
   * owns its own failure response.
   */
  unauthorized?: RequestHandler
  /**
   * Forbidden (403) handler. Invoked when the caller is authenticated but
   * lacks every required scope. Replaces the legacy `handler` field so the
   * 401/403 distinction is explicit on the definition.
   */
  forbidden: RequestHandler
  /**
   * Authorization scope handlers. Each receives a typed `req.user` when
   * `User` is supplied, evaluated with OR semantics by `scope()`.
   */
  scopes: NamedHandler<S, User>
  responses?: MediaSchemaItem
}

/**
 * Derive the authed-request shape from a `Security` definition — the typed
 * `req` a handler sees once authentication has populated `req.user`. Pure
 * type-level, zero runtime cost; parallels `WnDataType` for schemas.
 *
 * ```typescript
 * const auth = bearerAuth<'admin', { id: string; role: string }>({ ... })
 * type Authed = WnAuthType<typeof auth> // Request & { user?: { id, role } }
 *
 * const handler = (req: Authed, res: Response) => {
 *   req.user?.id // string | undefined — no manual casts
 * }
 * ```
 */
export type WnAuthType<Sec extends Security<any, any>> =
  Sec extends Security<any, infer User> ? AuthedRequest<User> : never

export const app = (a: AppObject): AppObject => a

export const groupByParamIn = (
  params: Parameter[],
): Partial<Record<ParamIn, Parameter[]>> => {
  return params.reduce<Partial<Record<ParamIn, Parameter[]>>>((group, p) => {
    const key = p.in
    ;(group[key] ??= []).push(p)
    return group
  }, {})
}

export const validateParams = (
  params: (Partial<Parameter> & { name: string })[],
): AjvLikeSchemaObject => {
  const schema: AjvLikeSchemaObject = {
    type: 'object',
    properties: {},
    required: [],
  }
  const required = new Set<string>()

  for (const param of params) {
    if (!param.schema || !schema.properties) {
      continue
    }

    // Copy the param schema so AJV cannot mutate a shared Parameter object
    // across routes during compilation.
    schema.properties[param.name] = { ...param.schema }

    if (param.required) {
      required.add(param.name)
    }
  }

  if (required.size > 0) {
    schema.required = [...required]
  }

  return schema
}

export const validateBuilder =
  (v: AjvLike) =>
  (
    parameters: Parameter[],
  ): {
    handlers: RequestHandler[]
    schema: Partial<Record<ParamIn, AjvLikeSchemaObject>>
  } => {
    const pIns = groupByParamIn(parameters)
    const schema: Partial<Record<ParamIn, AjvLikeSchemaObject>> = {}

    const handlers = Object.values(pIns).flatMap((params) => {
      // Defensive check: groupByParamIn only creates non-empty arrays,
      // but this guards against potential future changes or edge cases
      if (!params?.length) {
        return []
      }

      const paramIn = params[0].in
      const builtSchema = validateParams(params)
      schema[paramIn] = builtSchema
      const validator = v.compile(builtSchema)

      return [validateHandler(validator, paramIn)]
    })

    return { handlers, schema }
  }

// Reuse error message string to reduce allocations
const VALIDATION_ERROR_MESSAGE = 'WingnutValidationError'

export const validateHandler =
  (valid: AjvLikeValidateFunction, whereIn: ParamIn): RequestHandler =>
  (req, _res, next) => {
    const dataSource = req[inMap[whereIn]]
    if (!valid(dataSource)) {
      return next(
        new ValidationError(VALIDATION_ERROR_MESSAGE, { cause: valid.errors }),
      )
    }
    return next()
  }

/**
 * Schema cache for compiled validators
 * Uses a Map to cache compiled schemas by their stringified representation
 */
export const createSchemaCache = () => {
  const cache = new Map<string, AjvLikeValidateFunction>()
  let hits = 0
  let misses = 0

  const generateCacheKey = (schema: AjvLikeSchemaObject): string => {
    return JSON.stringify(schema)
  }

  const get = (
    schema: AjvLikeSchemaObject,
  ): AjvLikeValidateFunction | undefined => {
    const key = generateCacheKey(schema)
    const cached = cache.get(key)
    if (cached) {
      hits++
      return cached
    }
    misses++
    return undefined
  }

  const set = (
    schema: AjvLikeSchemaObject,
    validator: AjvLikeValidateFunction,
  ): void => {
    const key = generateCacheKey(schema)
    cache.set(key, validator)
  }

  const getStats = () => ({
    size: cache.size,
    hits,
    misses,
    hitRate: hits + misses > 0 ? (hits / (hits + misses)) * 100 : 0,
  })

  const clear = () => {
    cache.clear()
    hits = 0
    misses = 0
  }

  return { get, set, getStats, clear }
}

/**
 * Wraps AJV compile method with caching
 */
const createCachedAjv = (ajv: AjvLike) => {
  const schemaCache = createSchemaCache()
  const originalCompile = ajv.compile.bind(ajv)

  const cachedCompile = (
    schema: AjvLikeSchemaObject,
  ): AjvLikeValidateFunction => {
    // Check cache first
    const cached = schemaCache.get(schema)
    if (cached) {
      return cached
    }

    // Compile and cache
    const validator = originalCompile(schema)
    schemaCache.set(schema, validator)
    return validator
  }

  return {
    ...ajv,
    compile: cachedCompile,
    _schemaCache: schemaCache, // Expose cache for testing/monitoring
  }
}

export const wingnut = (ajv: AjvLike) => {
  // Wrap AJV with caching
  const cachedAjv = createCachedAjv(ajv)
  const validate = validateBuilder(cachedAjv)

  const mapRouter = (
    urtr: Router,
    {
      pathOp,
      path,
      method,
    }: { pathOp: PathOperation; path: string; method: string },
  ) => {
    const wrapper = pathOp.wrapper ?? ((cb) => cb)

    const requestBodyContent =
      pathOp.requestBody?.content?.['application/json'] ??
      pathOp.requestBody?.content?.['application/x-www-form-urlencoded']

    const middle = [
      ...(pathOp.scope ? handleScopes(pathOp.scope, wrapper) : []),
      ...(requestBodyContent?.schema
        ? [
            wrapper(
              validateHandler(
                cachedAjv.compile(requestBodyContent.schema),
                'body',
              ),
            ),
          ]
        : []),
      ...(pathOp.parameters
        ? validate(pathOp.parameters).handlers.map(wrapper)
        : []),
      ...(pathOp.middleware?.map((m) => wrapper(m as RequestHandler)) ?? []),
    ]

    // Type assertion for router method access
    if (middle.length > 0) {
      ;(urtr as unknown as Record<string, (...args: any[]) => void>)[method](
        path,
        ...middle,
      )
    }
  }

  const handleScopes = (
    scopes: ScopeObject[],
    wrapper: (cb: RequestHandler) => RequestHandler,
  ) => {
    return scopes.flatMap((s) =>
      s.middleware.map((m) => wrapper(m as RequestHandler)),
    )
  }

  /**
   * route
   *
   * Map an Express route to one or more Paths
   *
   * ```typescript
   * // returns router and PathItems for swagger docs
   * const { router, pathItems } = route(
   *  express.Router(),
   *  path(
   *    '/users',
   *    getMethod({
   *       middleware: [
   *        // express HTTP handler
   *       ]
   *    })
   *    )
   *  )
   * ```
   */
  const route = (rtr: Router, ...pitems: PathItem[]): AppRoute => ({
    paths: pitems,
    router: pitems.reduce((urtr, pitem) => {
      Object.entries(pitem).forEach(([path, pathObj]) => {
        Object.entries(pathObj).forEach(([method, pathOp]) => {
          mapRouter(urtr, { pathOp, path, method })
        })
      })
      return urtr
    }, rtr),
  })
  /**
   * controller
   *
   * Creates a new controller with a path prefix
   *
   * ```typescript
   *
   * import logsController from './logs'
   *
   * // map controller and path prefix
   * controller({
   *   prefix: '/api/logs',
   *   route: logsController
   * })
   * ```
   */
  const controller =
    (controllerDefinition: { prefix: string; route: typeof route }) =>
    (router: Router): PathItem[] => {
      const { paths: pathItems, router: controllerRouter } =
        controllerDefinition.route(Router())
      router.use(controllerDefinition.prefix, controllerRouter)
      if (!Array.isArray(pathItems)) {
        throw new Error('WingnutError: "paths" must be an array')
      }
      return pathItems.map((pathItem) => {
        return Object.entries(pathItem).reduce<PathItem>(
          (acc, [originalPath, pathObject]) => {
            const newPathKey = `${controllerDefinition.prefix}${originalPath}`
              .replaceAll(/\([^()]*\)/g, '')
              .replaceAll(/:(\w+)/g, '{$1}')
            acc[newPathKey] = pathObject
            return acc
          },
          {},
        )
      })
    }

  /**
   * paths
   *
   * Define path endpoints with Express
   * app context
   *
   * ```typescript
   * paths(
   *  // express app
   *  app,
   *  controller({
   *    prefix: '/api/logs',
   *    route: logsController
   *  })
   * )
   * ```
   */
  const paths = (
    router: Router,
    ...ctrls: ReturnType<typeof controller>[]
  ): PathItem => {
    const acc = { out: {} as PathItem, track: new Set<string>() }

    ctrls.forEach((c) => {
      const p = c(router)
      p.forEach((item) => {
        const path = Object.keys(item)[0]
        const methods = Object.keys(item[path])
        for (const method of methods) {
          const full = `${method} ${path}`
          if (acc.track.has(full)) {
            throw new Error(`WingnutError: ${full} already exists`)
          }
          acc.track.add(full)
        }
        // Merge methods under the same path key; the duplicate check above
        // guarantees the method sets are disjoint, so none are overwritten.
        acc.out[path] = Object.assign(acc.out[path] ?? {}, item[path])
      })
    })

    return acc.out
  }

  return {
    validate,
    route,
    paths,
    controller,
  }
}

export const path = (path: string, ...pathObjects: PathObject[]): PathItem => ({
  [path]: Object.assign({}, ...pathObjects),
})

export const asyncMethod =
  (
    m: string,
    wrapper: (cb: AsyncRequestHandler) => ErrorRequestHandler | RequestHandler,
  ) =>
  (pop: PathOperation): PathObject => ({
    [m]: { wrapper, ...pop },
  })

type AsyncRequestHandler =
  | ((req: Request, res: Response, next: NextFunction) => Promise<void>)
  | ((
      err: Error,
      req: Request,
      res: Response,
      next: NextFunction,
    ) => Promise<void>)

export const asyncWrapper = (
  cb: AsyncRequestHandler,
): RequestHandler | ErrorRequestHandler => {
  if (cb.length === 4) {
    const errHandler = cb as (
      err: Error,
      req: Request,
      res: Response,
      next: NextFunction,
    ) => Promise<void>
    return async (
      err: Error,
      req: Request,
      res: Response,
      next: NextFunction,
    ) => {
      try {
        await errHandler(err, req, res, next)
      } catch (e) {
        next(e)
      }
    }
  }

  const reqHandler = cb as (
    req: Request,
    res: Response,
    next: NextFunction,
  ) => Promise<void>
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      await reqHandler(req, res, next)
    } catch (e) {
      next(e)
    }
  }
}

export const method =
  (m: string) =>
  (pop: PathOperation): PathObject => ({
    [m]: pop,
  })

/**
 * Build a fail-closed authorization gate from scope predicates. `combine`
 * decides the strategy: OR (any scope passes — `scope()`) or AND (every
 * scope passes — `allScopes()`). On success the gate calls `next()`; on
 * failure it delegates to the Security's `forbidden` (403) handler.
 */
const scopeGate =
  <User = unknown>(
    cb: RequestHandler,
    scopes: ScopeHandler<User>[],
    combine: (results: boolean[]) => boolean,
  ): RequestHandler =>
  (req, res, next) => {
    // `req.user` is populated at runtime by the Security `before` hook; the
    // cast narrows to AuthedRequest<User> for typed scope handlers.
    const isAuthorized = combine(
      scopes.map((handler) => handler(req as AuthedRequest<User>, res)),
    )
    if (isAuthorized) {
      next()
    } else {
      cb(req, res, next)
    }
  }

/**
 * scopeWrapper
 *
 * OR-semantics gate: authorize when ANY scope predicate passes. Backs
 * `scope()`. Kept as a named export for callers composing custom middleware.
 */
export const scopeWrapper = <User = unknown>(
  cb: RequestHandler,
  scopes: ScopeHandler<User>[],
): RequestHandler =>
  scopeGate<User>(cb, scopes, (results) => results.some(Boolean))

/**
 * allScopesWrapper
 *
 * AND-semantics gate: authorize only when EVERY scope predicate passes.
 * Backs `allScopes()`.
 */
export const allScopesWrapper = <User = unknown>(
  cb: RequestHandler,
  scopes: ScopeHandler<User>[],
): RequestHandler =>
  scopeGate<User>(cb, scopes, (results) => results.every(Boolean))

/** Resolve scope names to their handler predicates, throwing on a missing name. */
const resolveScopeHandlers = <T, User>(
  security: Security<T, User>,
  scopes: (keyof NamedHandler<T, User>)[],
): ScopeHandler<User>[] =>
  scopes.map((s) => {
    const handler = security.scopes[s]
    if (!handler) {
      throw new Error(
        `WingnutError: Scope '${String(s)}' not found in security.scopes`,
      )
    }
    return handler
  })

/** Build a ScopeObject that runs `before` then a gate combining the scopes. */
const buildScope = <T, User>(
  security: Security<T, User>,
  scopes: (keyof NamedHandler<T, User>)[],
  wrap: (cb: RequestHandler, handlers: ScopeHandler<User>[]) => RequestHandler,
): ScopeObject => ({
  auth: security.name,
  scopes,
  middleware: [
    ...(security.before ? [security.before] : []),
    wrap(security.forbidden, resolveScopeHandlers(security, scopes)),
  ],
  responses: security.responses,
})

/**
 * scope
 *
 * Create a user security scope with OR semantics — the request is
 * authorized when ANY listed scope predicate passes. Emits a single-scheme
 * `security` entry.
 *
 * ```typescript
 * import { Request, Response } from 'express'
 *
 * // The user shape is carried by Security<string, User> — no manual
 * // `extends Request` interface needed.
 * const userLevel = (minLevel: number): ScopeHandler<{ level: number }> =>
 *   (req) => (req.user?.level ?? 0) > minLevel
 *
 * const auth: Security<string, { level: number }> = {
 *  name: 'auth',
 *  scheme: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
 *  forbidden: (_req, res) => res.status(403).send('Forbidden'),
 *  scopes: {
 *    admin: userLevel(100),
 *    moderator: userLevel(50)
 *  },
 *  responses: { '403': { description: 'Forbidden' } }
 * }
 *
 * const adminAuth = authPathOp(scope(auth, 'admin'))
 * ```
 */
export const scope = <T = string, User = unknown>(
  security: Security<T, User>,
  ...scopes: (keyof NamedHandler<T, User>)[]
): ScopeObject => buildScope(security, scopes, scopeWrapper<User>)

/**
 * allScopes
 *
 * AND-require multiple scopes from one Security. Unlike `scope()` — which
 * authorizes when ANY listed scope passes (OR) — `allScopes()` requires
 * EVERY listed scope to pass; a request missing any scope is forbidden
 * (403). The emitted `security` entry is identical to `scope()`'s (a single
 * scheme carrying all the named scopes); only the runtime combination
 * differs.
 *
 * ```typescript
 * // Require BOTH 'read' AND 'paid' — a free-tier user with only 'read' is denied.
 * const paidReader = authPathOp(allScopes(auth, 'read', 'paid'))
 * ```
 */
export const allScopes = <T = string, User = unknown>(
  security: Security<T, User>,
  ...scopes: (keyof NamedHandler<T, User>)[]
): ScopeObject => buildScope(security, scopes, allScopesWrapper<User>)

/**
 * authPathOp
 *
 * Authorization middleware builder. Accepts one or more scope requirements:
 * a single `ScopeObject` (from `scope()` / `allScopes()`) for one scheme, or
 * several — / the result of `both(...)` — to AND-combine multiple schemes.
 * Each requirement's middleware runs in order, and every requirement must
 * pass; the first failing requirement rejects the request via its own 401
 * (unauthenticated) or 403 (forbidden) handler. The emitted `security`
 * array mirrors the OpenAPI rule that entries are AND'd, so docs and
 * enforcement agree.
 *
 * ```typescript
 * // create admin authorization middleware guard
 * const adminAuth = authPathOp(scope(auth, 'admin'))
 *
 * // secure route with admin authorization
 * adminAuth(
 *  getMethod({
 *    middleware: [
 *      // express HTTP handler
 *    ]
 *  })
 * )
 *
 * // AND-combine two schemes — both bearerAuth AND apiKey are required
 * authPathOp(both(scope(jwt, 'admin'), scope(key, 'admin')))(
 *  getMethod({ middleware: [] }),
 * )
 * ```
 */
export const authPathOp =
  (first: ScopeObject | ScopeObject[], ...rest: ScopeObject[]) =>
  (pathObject: PathObject): PathObject => {
    const scopes = Array.isArray(first) ? [...first, ...rest] : [first, ...rest]
    const result: PathObject = {}
    for (const [method, operation] of Object.entries(pathObject)) {
      ;(result as Record<string, PathOperation>)[method] = {
        ...operation,
        security: scopes.map((s) => ({ [s.auth]: s.scopes })),
        scope: scopes,
        responses: scopes.reduce<MediaSchemaItem>(
          (acc, s) => ({ ...acc, ...s.responses }),
          { ...operation.responses },
        ),
      }
    }
    return result
  }

/**
 * both
 *
 * AND-combine multiple schemes (e.g. `bearerAuth` AND `apiKey`). Returns
 * the requirements for `authPathOp`, which runs each scheme's middleware in
 * order and emits a multi-entry `security` array. OpenAPI AND's array
 * entries, so the served docs and the runtime enforcement agree: every
 * scheme must be satisfied. For within-scheme OR/AND use `scope()` /
 * `allScopes()`.
 *
 * ```typescript
 * // Require a valid JWT AND a valid API key.
 * authPathOp(both(scope(jwt, 'admin'), scope(key, 'admin')))(putMethod({ ... }))
 * ```
 */
export const both = (...scopes: ScopeObject[]): ScopeObject[] => scopes

/**
 * securitySchemes
 *
 * Build the OpenAPI `components.securitySchemes` map from one or more
 * `Security` definitions, keyed by `security.name`. Securities without a
 * `scheme` are skipped, so per-operation `security` references resolve to a
 * real scheme definition in the served spec (Swagger UI, Redoc, Schemathesis).
 *
 * ```typescript
 * const auth: Security = {
 *   name: 'bearerAuth',
 *   scheme: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
 *   forbidden: (_req, res) => res.status(403).send('Forbidden'),
 *   scopes: { admin: (req) => (req.user?.level ?? 0) >= 100 },
 *   responses: { '403': { description: 'Forbidden' } },
 * }
 *
 * const spec = {
 *   openapi: '3.0.0',
 *   info: { version: '1.0.0', title: 'API' },
 *   paths,
 *   components: { securitySchemes: securitySchemes(auth) },
 * }
 * ```
 */
export const securitySchemes = (
  ...securities: Security[]
): SecuritySchemesObject => {
  const schemes: SecuritySchemesObject = {}
  for (const security of securities) {
    if (security.scheme) {
      schemes[security.name] = security.scheme
    }
  }
  return schemes
}

/**
 * Create a parameter schema with the given `in` location.
 */
export const param =
  (pin: ParamIn) =>
  (param: Omit<Parameter, 'in'>): Parameter => ({
    ...param,
    in: pin,
  })

export const integer = (sch: Partial<ParamSchema>): ParamSchema => ({
  type: 'integer',
  ...sch,
})

/**
 * queryParam
 *
 * OpenAPI3 QueryParam Schema builder
 *
 * ```typescript
 * getMethod({
 *   parameters: [
 *     // accept `/path?limit=<number>`
 *     queryParam({
 *        name: 'limit',
 *        description: 'max number',
 *        schema: {
 *          type: 'integer',
 *          minimum: 1,
 *        },
 *     })
 *   ]
 * })
 * ```
 */
export const queryParam = param('query')

/**
 * pathParam
 *
 * OpenAPI3 PathParam Schema builder
 *
 * ```typescript
 * putMethod({
 *  parameters: [
 *    // accept `/path/:id` where `:id` is in uuidv4 format
 *    pathParam({
 *      name: 'id',
 *      description: 'user id',
 *      schema: {
 *        type: 'string',
 *        format: 'uuidv4'
 *      }
 *    })
 *  ]
 * })
 * ```
 */
export const pathParam = param('path')

export const headerParam = param('header')

export const getMethod = method('get')
export const postMethod = method('post')
export const putMethod = method('put')
export const patchMethod = method('patch')
export const deleteMethod = method('delete')
export const asyncGetMethod = asyncMethod('get', asyncWrapper)

export const asyncPostMethod = asyncMethod('post', asyncWrapper)
export const asyncPatchMethod = asyncMethod('patch', asyncWrapper)
export const asyncPutMethod = asyncMethod('put', asyncWrapper)

export const asyncDeleteMethod = asyncMethod('delete', asyncWrapper)

export type { AuthedRequest } from '../types/open-api-3'
export type {
  WnDataType,
  WnNumberType,
  WnParamDef,
  WnTypeOf,
} from '../types/wn-data'
