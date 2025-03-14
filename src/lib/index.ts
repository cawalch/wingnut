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
  MediaSchemaItem,
  NamedHandler,
  ParamIn,
  ParamSchema,
  Parameter,
  PathItem,
  PathObject,
  PathOperation,
  ScopeHandler,
  ScopeObject,
  inMap,
} from '../types/open-api-3'
import { ValidationError } from './errors'

export type AppRoute = { paths: PathItem[]; router: Router }

type ValidateByParam = Record<ParamIn, AjvLikeValidateFunction | undefined>

export interface Security<S = string> {
  name: string
  before?: RequestHandler
  handler: RequestHandler
  scopes: NamedHandler<S>
  responses?: MediaSchemaItem
}

export const app = (a: AppObject): AppObject => a

export const groupByParamIn = (
  params: Parameter[],
): { [key in ParamIn]?: Parameter[] } => {
  return params.reduce(
    (group, p) => {
      const key = inMap[p.in]
      if (!group[key]) {
        group[key] = []
      }
      group[key].push(p)
      return group
    },
    {} as { [key in ParamIn]: Parameter[] },
  )
}

export const validateParams = (
  params: (Partial<Parameter> & { name: string })[],
): AjvLikeSchemaObject => {
  const schema: AjvLikeSchemaObject = {
    type: 'object',
    properties: {},
    required: [],
  }

  for (const param of params) {
    if (!param.schema) {
      continue
    }

    schema.properties[param.name] = { ...param.schema }

    if (param.required) {
      if (!schema.required.includes(param.name)) {
        schema.required.push(param.name)
      }
    }
  }

  return schema
}

export const validateBuilder =
  (v: AjvLike) =>
  (
    s: Parameter[],
  ): {
    handlers: RequestHandler[]
    schema: { [key in ParamIn]?: AjvLikeSchemaObject }
  } => {
    const pIns = groupByParamIn(s)
    const ret: { [key in ParamIn]?: AjvLikeSchemaObject } = {}
    const handlers: RequestHandler[] = []
    const validators: ValidateByParam = {
      path: undefined,
      query: undefined,
      body: undefined,
      header: undefined,
    }

    for (const k of Object.keys(pIns)) {
      const schema = validateParams(pIns[k])
      const validator = v.compile(schema)
      validators[k as ParamIn] = validator
      ret[k as ParamIn] = schema
      handlers.push(validateHandler(validator, k as ParamIn))
    }
    return { handlers, schema: ret }
  }

export const validateHandler =
  (valid: AjvLikeValidateFunction, whereIn: ParamIn) =>
  (req: Request, _res: Response, next: NextFunction) => {
    if (!valid(req[whereIn])) {
      next(new ValidationError('WingnutValidationError', valid.errors))
    }
    next()
  }

export const wingnut = (ajv: AjvLike) => {
  const validate = validateBuilder(ajv)

  const mapRouter = (
    urtr: Router,
    {
      pathOp,
      path,
      method,
    }: { pathOp: PathOperation; path: string; method: string },
  ) => {
    let wrapper: (
      cb: RequestHandler | ErrorRequestHandler,
    ) => RequestHandler | ErrorRequestHandler = (cb) => cb
    if (pathOp.wrapper) {
      wrapper = pathOp.wrapper
    }

    const middle: Array<RequestHandler | ErrorRequestHandler> = []

    // security handler
    if (pathOp.scope) {
      middle.push(...handleScopes(pathOp.scope, wrapper))
    }

    if (pathOp.requestBody?.content !== undefined) {
      const content =
        pathOp.requestBody.content['application/json'] ||
        pathOp.requestBody.content['application/x-www-form-urlencoded']
      if (content) {
        const handler = validateHandler(ajv.compile(content.schema), 'body')
        middle.push(wrapper(handler))
      }
    }

    if (pathOp.parameters) {
      const { handlers } = validate(pathOp.parameters)
      handlers.forEach((h) => middle.push(wrapper(h)))
    }

    pathOp.middleware?.forEach((m) => middle.push(wrapper(m)))

    urtr[method](path, ...middle)
  }

  const handleScopes = (scopes: ScopeObject[], wrapper: any) => {
    const middleware: (RequestHandler | ErrorRequestHandler)[] = []
    for (const s of scopes) {
      middleware.push(...s.middleware.map((m) => wrapper(m)))
    }
    return middleware
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
    (ctrl: { prefix: string; route: typeof route }) =>
    (router: Router): PathItem[] => {
      const paths = ctrl.route(Router())
      router.use(ctrl.prefix, paths.router)
      if (!Array.isArray(paths.paths)) {
        throw new Error('WingnutError: "paths" must be an array')
      }
      paths.paths.forEach((p) => {
        Object.keys(p).forEach((k) => {
          const pathKey = `${ctrl.prefix}${k}`
            .replace(/\([^()]*\)/g, '')
            .replace(/:(\w+)/g, '{$1}')
          p[pathKey] = p[k]
          delete p[k]
        })
      })
      return paths.paths
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
    const acc = { out: {}, track: new Map<string, boolean>() }

    ctrls.forEach((c) => {
      const p = c(router)
      p.forEach((item) => {
        const path = Object.keys(item)[0]
        const method = Object.keys(item[path])[0]
        const full = `${method} ${path}`
        if (acc.track.has(full)) {
          console.warn(`WingnutWarning: ${full} already exists`)
        } else {
          acc.track.set(full, true)
        }
        Object.assign(acc.out, item)
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

export const path = (path: string, ...po: PathObject[]): PathItem => ({
  [path]: po.reduce((acc, p) => ({ ...acc, ...p }), {}),
})

export const asyncMethod =
  (
    m: string,
    wrapper: (cb: AsyncRequestHandler) => ErrorRequestHandler | RequestHandler,
  ) =>
  (pop: PathOperation): PathObject => ({
    [m]: { wrapper, ...pop },
  })

type AsyncRequestHandler = (...args: unknown[]) => Promise<void>

export const asyncWrapper = (cb: AsyncRequestHandler) => {
  if (cb.length === 2) {
    return async (req: Request, res: Response) => {
      await cb(req, res)
    }
  }
  if (cb.length === 3)
    return async (
      req: Request,
      res: Response,
      next: NextFunction,
    ): Promise<void> => {
      try {
        await cb(req, res, next)
      } catch (e) {
        next(e)
      }
    }
  return async (
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      await cb(err, req, res, next)
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
 * scopeWrapper
 *
 * Wraps Express RequestHandler's inside scoped middleware.
 * Used to create middleware that maps to Security scopes.
 */
export const scopeWrapper =
  (cb: RequestHandler, scopes: ScopeHandler[]) =>
  (req: Request, res: Response, next: NextFunction) => {
    const isAuthorized = scopes.some((v) => v(req, res, next))
    if (isAuthorized) {
      next()
    } else {
      cb(req, res, next)
    }
  }

/**
 * scope
 *
 * Create a user security scope
 *
 * ```typescript
 * import { Request, Response } from 'express'
 *
 * // user session interface
 * interface UserAuth extends Request {
 *    user?: {
 *      level: number
 *    }
 * }
 *
 * // authorization middleware based on user level
 * const userLevel = (minLevel: number): ScopeHandler => (
 *    req: UserAuth
 * ): boolean => req.user.level > minLevel
 *
 * const auth: Security = {
 *  name: 'auth',
 *  handler: (_req: Request, res: Response) => {
 *    // unauthorized handler
 *    res.status(400).send('Not Auth')
 *  },
 *  scopes: {
 *    admin: userLevel(100),
 *    moderator: userLevel(50)
 *  },
 *  responses: {
 *  '400': {
 *    description: 'Not Auth'
 *   }
 *  }
 * }
 *
 * // build admin authorization middleware
 * const adminAuth = authPathOp(scope(auth, 'admin'))
 * ```
 */
export const scope = <T = string>(
  security: Security<T>,
  ...scopes: (keyof NamedHandler<T>)[]
): ScopeObject => {
  const middleware: RequestHandler[] = []
  if (security.before) {
    middleware.push(security.before)
  }
  const scopeMiddlewares = scopes.map((s) => {
    const handler = security.scopes[s]
    if (!handler) {
      console.error(`WingnutError: Scope '${s}' not found in security.scopes`)
      throw new Error(`Scope '${s}' not found`)
    }
    return handler
  })
  middleware.push(scopeWrapper(security.handler, scopeMiddlewares))
  return {
    auth: security.name,
    scopes,
    middleware,
    responses: security.responses,
  }
}

/**
 * authPathOp
 *
 * Authorization middleware builder.
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
 * ```
 */
export const authPathOp =
  (scope: ScopeObject) =>
  (pop: PathObject): PathObject => {
    const method = Object.keys(pop)[0]
    const operation: PathOperation = pop[method as keyof PathObject]
    operation.security = [{ [scope.auth]: scope.scopes }]
    operation.scope = [scope]
    operation.responses = { ...operation.responses, ...scope.responses }
    return { [method]: operation }
  }

/**
 * Create a parameter schema with the given `in` location.
 */
export const param =
  (pin: ParamIn) =>
  (param: Omit<Parameter, 'in'>): Parameter => ({
    in: pin,
    ...param,
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

type WnNumberType = 'integer' | 'int32' | 'int8' | 'number'

type WnTDataDef<S, D extends Record<string, unknown>> = S extends {
  type: WnNumberType
}
  ? number
  : S extends { type: 'boolean' }
    ? boolean
    : S extends { type: 'timestamp' }
      ? string | Date
      : S extends { type: 'array'; items: { type: string } }
        ? WnTDataDef<S['items'], D>[]
        : S extends { type: 'string'; enum: readonly (infer E)[] }
          ? string extends E
            ? never
            : [E] extends [string]
              ? E
              : never
          : S extends { elements: infer E }
            ? WnTDataDef<E, D>[]
            : S extends { type: 'string' }
              ? string
              : S extends {
                    properties: Record<string, unknown>
                    required?: readonly string[]
                    additionalProperties?: boolean
                  }
                ? {
                    -readonly [K in keyof S['properties']]?: WnTDataDef<
                      S['properties'][K],
                      D
                    >
                  } & {
                    -readonly [K in S['required'][number]]: WnTDataDef<
                      S['properties'][K],
                      D
                    >
                  } & ([S['additionalProperties']] extends [true]
                      ? Record<string, unknown>
                      : unknown)
                : S extends { name: string; schema: Record<string, unknown> }
                  ? {
                      -readonly [K in S['name']]: WnTDataDef<S['schema'], D>
                    }
                  : S extends {
                        description: string
                        schema: Record<string, unknown>
                      }
                    ? WnDataType<S['schema']>
                    : S extends { type: 'object' }
                      ? Record<string, unknown>
                      : null

export type WnDataType<S> = WnTDataDef<S, Record<string, never>>

export type WnParamDef = Record<
  string,
  Record<string, Omit<Parameter, 'in' | 'name'>>
>
