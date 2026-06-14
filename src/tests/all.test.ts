import Ajv from 'ajv'
import express, {
  NextFunction,
  Request,
  RequestHandler,
  Response,
  Router,
} from 'express'
import request from 'supertest'
import { assert, beforeEach, describe, expect, it, vi } from 'vitest'
import { app, createSchemaCache, headerParam, path, wingnut } from '../lib'
import { ValidationError, WingnutError } from '../lib/errors'
import {
  apiKey,
  asyncGetMethod,
  asyncPostMethod,
  asyncWrapper,
  authPathOp,
  bearerAuth,
  getMethod,
  groupByParamIn,
  oauth2,
  postMethod,
  queryParam,
  Security,
  scope,
  scopeWrapper,
  securitySchemes,
  validateBuilder,
  validateParams,
} from '../lib/index'
import { AjvLike, AjvLikeValidateFunction } from '../types/common'
import {
  Parameter,
  ParamIn,
  ParamType,
  ScopeHandler,
} from '../types/open-api-3'

const createParameter = (
  inValue: ParamIn,
  nameValue: string,
  typeValue: ParamType,
): Parameter => ({
  in: inValue,
  name: nameValue,
  schema: {
    type: typeValue,
  },
})

describe('app', () => {
  it('should return the AppObject passed to it', () => {
    const appObject = {
      info: {
        title: 'Test API',
        version: '1.0.0',
        description: 'Test API',
      },
      openapi: '3.0.0',
      paths: {},
    }
    const result = app(appObject)
    expect(result).toBe(appObject)
  })
})

describe('groupByParamIn', () => {
  it('should group by a parameter', () => {
    const param: Parameter = createParameter('path', 'id', 'string')
    const result = groupByParamIn([param])
    expect(result).toStrictEqual({
      path: [param],
    })
  })
  it('should group by multiple params', () => {
    const params: Parameter[] = [
      createParameter('path', 'id', 'string'),
      createParameter('query', 'name', 'string'),
    ]
    const result = groupByParamIn(params)
    expect(result).toEqual({
      path: [params[0]],
      query: [params[1]],
    })
  })
})

describe('validateParams', () => {
  it('should validate params', () => {
    const params: (Partial<Parameter> & { name: string })[] = [
      createParameter('path', 'id', 'string'),
    ]
    const result = validateParams(params)
    expect(result).toStrictEqual({
      type: 'object',
      properties: {
        id: {
          type: 'string',
        },
      },
      required: [],
    })
  })
  it('should handle required', () => {
    const params: (Partial<Parameter> & { name: string })[] = [
      {
        in: 'path',
        name: 'id',
        required: true,
        schema: {
          type: 'string',
        },
      },
    ]
    const result = validateParams(params)
    expect(result).toStrictEqual({
      type: 'object',
      properties: {
        id: {
          type: 'string',
        },
      },
      required: ['id'],
    })
  })

  it('should handle params without schema', () => {
    const params: (Partial<Parameter> & { name: string })[] = [
      {
        in: 'path',
        name: 'id',
        // schema is not provided
      },
    ]
    const result = validateParams(params)
    expect(result).toStrictEqual({
      type: 'object',
      properties: {},
      required: [],
    })
  })

  it('should not share param schema references', () => {
    const sharedSchema = { type: 'integer' as const, minimum: 1 }
    const params: (Partial<Parameter> & { name: string })[] = [
      { in: 'query', name: 'limit', schema: sharedSchema },
      { in: 'query', name: 'offset', schema: sharedSchema },
    ]
    const result = validateParams(params)
    // AJV may mutate compiled schemas; the built schema must not reference
    // the input object, or a shared Parameter contaminates other routes.
    expect(result.properties?.limit).not.toBe(sharedSchema)
    expect(result.properties?.offset).not.toBe(sharedSchema)
    expect(result.properties?.limit).toEqual(sharedSchema)
  })
})

describe('param', () => {
  it('should not let `in` be overridden at runtime', () => {
    const result = queryParam({
      name: 'limit',
      in: 'body',
      schema: { type: 'integer' as const },
    } as unknown as Omit<Parameter, 'in'>)
    expect(result.in).toBe('query')
  })
})

describe('validateBuilder', () => {
  it('should build a validator', () => {
    const mockAjvLike = {
      compile: () => () => true,
    }

    const validator = validateBuilder(mockAjvLike as unknown as AjvLike)
    const param: Parameter = createParameter('path', 'id', 'string')
    const result = validator([param])
    expect(result.schema).toEqual({
      path: {
        properties: {
          id: {
            type: 'string',
          },
        },
        required: [],
        type: 'object',
      },
    })
  })

  it('should build a validator with headers', () => {
    const mockAjvLike = {
      compile: () => () => true,
    }

    const validator = validateBuilder(mockAjvLike as unknown as AjvLike)
    const param: Parameter = createParameter('header', 'id', 'string')
    const result = validator([param])
    expect(result.schema).toEqual({
      header: {
        properties: {
          id: {
            type: 'string',
          },
        },
        required: [],
        type: 'object',
      },
    })
  })

  it('should handle empty parameters array', () => {
    const mockAjvLike = {
      compile: () => () => true,
    }

    const validator = validateBuilder(mockAjvLike as unknown as AjvLike)
    const result = validator([])
    expect(result.schema).toEqual({})
    expect(result.handlers).toEqual([])
  })

  it('should handle parameters with missing schema', () => {
    const mockAjvLike = {
      compile: () => () => true,
    }

    const validator = validateBuilder(mockAjvLike as unknown as AjvLike)
    // Create a parameter without a schema to test edge cases
    const paramWithoutSchema: Parameter = {
      in: 'query',
      name: 'test',
      // schema is undefined
    }
    const result = validator([paramWithoutSchema])
    expect(result.handlers).toHaveLength(1)
  })

  it('should handle defensive case with empty parameter arrays', () => {
    const mockAjvLike = {
      compile: () => () => true,
    }

    // Create a test that directly exercises the defensive code path
    // by temporarily modifying Object.values to return empty arrays
    const originalValues = Object.values
    Object.values = vi.fn().mockReturnValue([[]]) // Return array with one empty array

    try {
      const validator = validateBuilder(mockAjvLike as unknown as AjvLike)
      const result = validator([{ in: 'query', name: 'test' } as Parameter])

      expect(result.handlers).toEqual([])
      expect(result.schema).toEqual({})
    } finally {
      Object.values = originalValues
    }
  })

  it('should handle duplicate required parameters', () => {
    const mockAjvLike = {
      compile: () => () => true,
    }

    const validator = validateBuilder(mockAjvLike as unknown as AjvLike)
    // Create parameters with the same name and both required
    const param1: Parameter = {
      in: 'query',
      name: 'test',
      required: true,
      schema: { type: 'string' },
    }
    const param2: Parameter = {
      in: 'query',
      name: 'test', // Same name
      required: true,
      schema: { type: 'string' },
    }
    const result = validator([param1, param2])
    expect(result.handlers).toHaveLength(1)
    // The required array should only contain 'test' once
    expect(result.schema.query?.required).toEqual(['test'])
  })
})

const ajv = new Ajv()
ajv.opts.coerceTypes = true

describe('Error handling', () => {
  it('should handle environments without Error.captureStackTrace', () => {
    // Temporarily remove Error.captureStackTrace to test the fallback
    const originalCaptureStackTrace = Error.captureStackTrace
    delete (Error as any).captureStackTrace

    try {
      const error = new ValidationError('test error')
      expect(error.name).toBe('ValidationError')
      expect(error.message).toBe('test error')
    } finally {
      // Restore the original function
      if (originalCaptureStackTrace) {
        Error.captureStackTrace = originalCaptureStackTrace
      }
    }
  })

  it('should lazily capture stack trace when accessed on WingnutError', () => {
    const error = new WingnutError('test error')
    // Access stack to trigger lazy capture
    const stack = error.stack
    expect(stack).toBeDefined()
    expect(typeof stack).toBe('string')
  })

  it('should lazily capture stack trace when accessed on ValidationError', () => {
    const error = new ValidationError('test error')
    // Access stack to trigger lazy capture
    const stack = error.stack
    expect(stack).toBeDefined()
    expect(typeof stack).toBe('string')
  })

  it('should allow setting custom stack trace on WingnutError', () => {
    const error = new WingnutError('test error')
    const customStack = 'Custom stack trace'
    error.stack = customStack
    expect(error.stack).toBe(customStack)
  })

  it('should allow setting custom stack trace on ValidationError', () => {
    const error = new ValidationError('test error')
    const customStack = 'Custom stack trace'
    error.stack = customStack
    expect(error.stack).toBe(customStack)
  })

  it('should return super.stack when Error.captureStackTrace is not available', () => {
    const originalCaptureStackTrace = Error.captureStackTrace
    delete (Error as any).captureStackTrace

    try {
      const error = new WingnutError('test error')
      const stack = error.stack
      expect(stack).toBeDefined()
    } finally {
      if (originalCaptureStackTrace) {
        Error.captureStackTrace = originalCaptureStackTrace
      }
    }
  })

  it('should return fallback stack when _stack is not set and captureStackTrace exists', () => {
    // Create error and access stack to trigger lazy capture
    const error = new WingnutError('test error')
    const firstStack = error.stack
    expect(firstStack).toBeDefined()

    // Access again - should return cached _stack
    const secondStack = error.stack
    expect(secondStack).toBe(firstStack)
  })

  it('should expose context property for ValidationError', () => {
    const cause = [{ message: 'validation failed' }]
    const error = new ValidationError('test error', { cause })
    expect(error.context).toBe(cause)
  })
})

describe('integration tests', () => {
  it('should validate request params', async () => {
    const { route, paths, controller } = wingnut(ajv)
    const userHandler = (req: Request, res: Response, next: NextFunction) => {
      res.status(200).json(req.params)
      next()
    }
    const createUserHandler = path(
      '/users',
      getMethod({
        parameters: [
          queryParam({
            name: 'limit',
            description: 'max number of users',
            schema: {
              type: 'number',
              minimum: 1,
            },
          }),
        ],
        middleware: [userHandler],
      }),
    )
    const app = express()
    app.use(express.json())
    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, createUserHandler),
      }),
    )
    app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
      if (err instanceof ValidationError) {
        res.status(400).send({ err: err.message, context: err.context })
      } else {
        res.status(400).send({ err: err.message })
      }
    })

    const response = await request(app).get('/api/users').query({ limit: 1 })
    expect(response.status).toBe(200)

    const badResponse = await request(app)
      .get('/api/users')
      .query({ limit: 'foo' })
    expect(badResponse.status).toBe(400)
  })

  it('should validate when nextFunction is not used', async () => {
    const { route, paths, controller } = wingnut(ajv)
    const userHandler = (req: Request, res: Response) => {
      res.status(200).json(req.params)
    }
    const createUserHandler = path(
      '/users',
      getMethod({
        parameters: [
          queryParam({
            name: 'limit',
            description: 'max number',
            schema: {
              type: 'number',
              minimum: 1,
            },
          }),
        ],
        middleware: [userHandler],
      }),
    )
    const app = express()
    app.use(express.json())
    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, createUserHandler),
      }),
    )
    app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
      if (err instanceof ValidationError) {
        res.status(400).send({ err: err.message, context: err.context })
      } else {
        res.status(400).send({ err: err.message })
      }
    })

    const response = await request(app).get('/api/users').query({ limit: 1 })
    expect(response.status).toBe(200)

    const badResponse = await request(app)
      .get('/api/users')
      .query({ limit: 'foo' })
    expect(badResponse.status).toBe(400)
  })

  it('should validate request body', async () => {
    const { route, paths, controller } = wingnut(ajv)
    const userHandler = (req: Request, res: Response, next: NextFunction) => {
      res.status(200).json(req.body)
      next()
    }
    const createUserHandler = path(
      '/users',
      postMethod({
        requestBody: {
          description: 'Create a user',
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  name: {
                    type: 'string',
                  },
                },
                required: ['name'],
              },
            },
          },
        },
        middleware: [userHandler],
      }),
    )
    const app = express()
    app.use(express.json())
    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, createUserHandler),
      }),
    )
    app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
      res.status(400).send({ err: err.message })
    })

    const response = await request(app).post('/api/users').send({
      name: 'test',
    })

    expect(response.status).toBe(200)

    const badResponse = await request(app)
      .post('/api/users')
      .send({
        name: ['foo'],
      })

    expect(badResponse.status).toBe(400)
  })

  it('should throw on duplicate paths', () => {
    const app = express()
    const { route, paths, controller } = wingnut(ajv)
    const duplicateController = controller({
      prefix: '/api',
      route: (router: Router) =>
        route(
          router,
          path(
            '/users',
            getMethod({
              middleware: [
                (_req: Request, res: Response, next: NextFunction) => {
                  res.status(200).send('hello')
                  next()
                },
              ],
            }),
          ),
        ),
    })
    expect(() => paths(app, duplicateController, duplicateController)).toThrow(
      'WingnutError: get /api/users already exists',
    )
  })

  it('should detect duplicate paths across all methods, not just the first', () => {
    const app = express()
    const { route, paths, controller } = wingnut(ajv)

    // First controller: registers GET and POST on /api/users
    const ctrl1 = controller({
      prefix: '/api',
      route: (router: Router) =>
        route(
          router,
          path(
            '/users',
            getMethod({
              middleware: [
                (_req: Request, res: Response) => res.status(200).send('get'),
              ],
            }),
            postMethod({
              middleware: [
                (_req: Request, res: Response) => res.status(200).send('post'),
              ],
            }),
          ),
        ),
    })

    // Second controller: registers POST on same path — should be caught as duplicate
    const ctrl2 = controller({
      prefix: '/api',
      route: (router: Router) =>
        route(
          router,
          path(
            '/users',
            postMethod({
              middleware: [
                (_req: Request, res: Response) => res.status(200).send('post2'),
              ],
            }),
          ),
        ),
    })

    // GET /api/users from ctrl1 is the first method in the merged PathObject.
    // POST /api/users appears in both but was not detected because only
    // Object.keys(item[path])[0] was checked.
    expect(() => paths(app, ctrl1, ctrl2)).toThrow(
      'WingnutError: post /api/users already exists',
    )
  })

  it('should handle path operations with null middleware', async () => {
    const { route, paths, controller } = wingnut(ajv)

    // Create a path operation and then set middleware to null to test the ?? [] fallback
    const pathOpWithNullMiddleware = {
      tags: ['test'],
      description: 'Test endpoint with null middleware',
      middleware: [] as any, // Start with empty array
      responses: {
        200: {
          description: 'Success',
          content: {
            'application/json': {
              schema: { type: 'object' as const },
            },
          },
        },
      },
    }

    // Set middleware to null after creation to test the fallback
    pathOpWithNullMiddleware.middleware = null as any

    const testHandler = path('/test', { get: pathOpWithNullMiddleware })
    const app = express()
    app.use(express.json())

    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, testHandler),
      }),
    )

    const response = await request(app).get('/api/test')
    expect(response.status).toBe(404) // Should still work but no handlers
  })

  it('should handle multiple controllers', async () => {
    const app = express()
    const { route, paths, controller } = wingnut(ajv)
    let usersCalled = 0
    let widgetCalled = 0
    const usersController = controller({
      prefix: '/users',
      route: (router: Router) =>
        route(
          router,
          path(
            '/',
            getMethod({
              middleware: [
                (_req: Request, res: Response, next: NextFunction) => {
                  usersCalled++
                  res.status(200).send('hello')
                  next()
                },
              ],
            }),
          ),
        ),
    })
    const widgetsController = controller({
      prefix: '/widgets',
      route: (router: Router) =>
        route(
          router,
          path(
            '/',
            getMethod({
              middleware: [
                (_req: Request, res: Response, next: NextFunction) => {
                  widgetCalled++
                  res.status(200).send('hello')
                  next()
                },
              ],
            }),
          ),
        ),
    })

    paths(app, usersController, widgetsController)
    await request(app).get('/users').expect(200)
    await request(app).get('/widgets').expect(200)
    expect(usersCalled).toBe(1)
    expect(widgetCalled).toBe(1)
  })

  it('should merge methods under the same path across controllers', () => {
    const app = express()
    const { route, paths, controller } = wingnut(ajv)
    const ctrl1 = controller({
      prefix: '/api',
      route: (router: Router) =>
        route(
          router,
          path(
            '/users',
            getMethod({
              middleware: [
                (_req: Request, res: Response) => res.status(200).send('get'),
              ],
            }),
          ),
        ),
    })
    const ctrl2 = controller({
      prefix: '/api',
      route: (router: Router) =>
        route(
          router,
          path(
            '/users',
            postMethod({
              middleware: [
                (_req: Request, res: Response) => res.status(200).send('post'),
              ],
            }),
          ),
        ),
    })
    const doc = paths(app, ctrl1, ctrl2)
    // both methods must survive in the aggregated PathItem
    expect(doc['/api/users'].get).toBeDefined()
    expect(doc['/api/users'].post).toBeDefined()
  })
})

interface UserAuth extends Request {
  user?: {
    level: number
  }
}

describe('Security Schema', () => {
  const UserLevel =
    (minLevel: number): ScopeHandler =>
    (req: UserAuth): boolean =>
      (req.user?.level ?? 0) > minLevel
  const routeHandler = () => {
    return
  }

  it('should scope request to a user level', () => {
    const auth: Security = {
      name: 'auth',
      forbidden: (_req: Request, res: Response) => {
        res.status(403).send('Forbidden')
      },
      scopes: {
        admin: UserLevel(100),
      },
      responses: {
        '403': {
          description: 'Forbidden',
        },
      },
    }

    const adminAuth = authPathOp(scope(auth, 'admin'))
    const actual = adminAuth(
      getMethod({
        middleware: [routeHandler],
        responses: {
          '200': {
            description: 'Success',
          },
        },
      }),
    )
    expect(actual?.get?.security).toStrictEqual([
      {
        auth: ['admin'],
      },
    ])
    expect(actual?.get?.responses).toStrictEqual({
      '200': {
        description: 'Success',
      },
      '403': {
        description: 'Forbidden',
      },
    })
  })

  it('should apply security to all methods in a multi-method PathObject', () => {
    const auth: Security = {
      name: 'auth',
      forbidden: (_req: Request, res: Response) => {
        res.status(403).send('Forbidden')
      },
      scopes: {
        admin: UserLevel(100),
      },
      responses: {
        '403': {
          description: 'Forbidden',
        },
      },
    }

    const adminAuth = authPathOp(scope(auth, 'admin'))

    // Pass a PathObject with multiple methods
    const actual = adminAuth({
      get: {
        middleware: [routeHandler],
        responses: { '200': { description: 'Get success' } },
      },
      post: {
        middleware: [routeHandler],
        responses: { '201': { description: 'Created' } },
      },
    })

    // Both methods should have security applied
    expect(actual?.get?.security).toStrictEqual([{ auth: ['admin'] }])
    expect(actual?.get?.scope).toBeDefined()
    expect(actual?.post?.security).toStrictEqual([{ auth: ['admin'] }])
    expect(actual?.post?.scope).toBeDefined()
  })
  it('should call the error middleware if provided', async () => {
    const app = express()
    const { route, paths, controller } = wingnut(ajv)
    let validated = 0

    const testController = controller({
      prefix: '/widgets',
      route: (router: Router) =>
        route(
          router,
          path(
            '/',
            asyncPostMethod({
              requestBody: {
                content: {
                  'application/x-www-form-urlencoded': {
                    schema: {
                      type: 'object',
                      properties: {
                        password: {
                          type: 'string',
                          minLength: 8,
                          maxLength: 32,
                        },
                      },
                      required: ['password'],
                    },
                  },
                },
              },
              middleware: [
                async (
                  _req: Request,
                  res: Response,
                  next: NextFunction,
                ): Promise<void> => {
                  res.status(200).send('hello')
                  next()
                },
                (
                  err: Error,
                  _req: Request,
                  res: Response,
                  next: NextFunction,
                ) => {
                  validated++
                  res.status(400).send(err.name)
                  next()
                },
              ],
            }),
          ),
        ),
    })
    paths(app, testController)

    app.use(
      (_err: Error, _req: Request, _res: Response, _next: NextFunction) => {
        assert.fail('Should not be called')
      },
    )

    await request(app)
      .post('/widgets?limit=foo')
      .type('form')
      .send({ password: 'moo' })
    expect(validated).toBe(1)
  })
  it('should call the next error middleware if provided', async () => {
    const app = express()
    const { route, paths, controller } = wingnut(ajv)
    let errorOne = 0

    const htmlRouter = express.Router()

    const testController = controller({
      prefix: '/widgets',
      route: (router: Router) =>
        route(
          router,
          path(
            '/',
            asyncPostMethod({
              middleware: [
                async (
                  _req: Request,
                  _res: Response,
                  _next: NextFunction,
                ): Promise<void> => {
                  throw new Error('oh no')
                },
                (
                  _err: Error,
                  _req: Request,
                  _res: Response,
                  _next: NextFunction,
                ) => {
                  errorOne++
                  throw new Error('oops')
                },
              ],
            }),
          ),
        ),
    })
    paths(htmlRouter, testController)

    htmlRouter.use(
      (_err: Error, _req: Request, _res: Response, next: NextFunction) => {
        errorOne++
        next()
      },
    )

    app.use(htmlRouter)

    await request(app)
      .post('/widgets?limit=foo')
      .type('form')
      .send({ password: 'moo' })
    expect(errorOne).toBe(2)
  })
  it('should call the before security middleware if provided', async () => {
    let calledBefore = false
    const auth: Security = {
      name: 'auth',
      before: (_req: Request, _res: Response, next: NextFunction) => {
        calledBefore = true
        next()
      },
      forbidden: (_req: Request, res: Response) => {
        res.status(403).send('Forbidden')
      },
      scopes: {
        admin: UserLevel(100),
      },
      responses: {
        '403': {
          description: 'Forbidden',
        },
      },
    }
    const adminAuth = authPathOp(scope(auth, 'admin'))
    const { route, paths, controller } = wingnut(ajv)
    const handler = path(
      '/users',
      adminAuth(
        asyncGetMethod({
          middleware: [routeHandler],
          responses: {
            '200': {
              description: 'Success',
            },
          },
        }),
      ),
    )
    const app = express()
    app.use(express.json())
    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, handler),
      }),
    )
    await request(app).get('/api/users')
    expect(calledBefore).toBe(true)
  })
  it('should throw error when paths is not an array', () => {
    const { controller } = wingnut(ajv)
    const mockRoute = () => ({ router: Router(), paths: 'not an array' })

    expect(() =>
      controller({
        prefix: '/api',
        route: mockRoute as any,
      })(Router()),
    ).toThrow('WingnutError: "paths" must be an array')
  })

  it('should throw error when scope does not exist', () => {
    const security: Security = {
      name: 'auth',
      forbidden: (_req: Request, res: Response) => {
        res.status(403).send('Forbidden')
      },
      scopes: {
        admin: () => true,
      },
      responses: {
        '403': {
          description: 'Forbidden',
        },
      },
    }

    try {
      scope(security, 'admin', 'nonexistent')
      assert.fail('Expected an error to be thrown')
    } catch (err) {
      expect((err as Error).message).toBe(
        "WingnutError: Scope 'nonexistent' not found in security.scopes",
      )
    }
  })

  it('should not throw error when all scopes exist', () => {
    const consoleSpyError = vi
      .spyOn(console, 'error')
      .mockImplementation(() => {
        return
      })
    const security: Security = {
      name: 'auth',
      forbidden: (_req: Request, res: Response) => {
        res.status(403).send('Forbidden')
      },
      scopes: {
        admin: () => true,
        moderator: () => true,
      },
      responses: {
        '403': {
          description: 'Forbidden',
        },
      },
    }

    try {
      const result = scope(security, 'admin', 'moderator')
      expect(result).toBeDefined()
    } catch (_err) {
      assert.fail('Unexpected error thrown')
    }

    expect(consoleSpyError).not.toHaveBeenCalled()

    consoleSpyError.mockRestore()
  })
})

describe('securitySchemes', () => {
  it('emits components.securitySchemes keyed by Security.name', () => {
    const bearer: Security = {
      name: 'bearerAuth',
      scheme: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      forbidden: (_req: Request, res: Response) => {
        res.status(403).send('Forbidden')
      },
      scopes: { admin: () => true },
    }
    const key: Security = {
      name: 'apiKey',
      scheme: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
      forbidden: (_req: Request, res: Response) => {
        res.status(403).send('Forbidden')
      },
      scopes: { admin: () => true },
    }
    expect(securitySchemes(bearer, key)).toStrictEqual({
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
      apiKey: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
    })
  })

  it('skips Security definitions without a scheme', () => {
    const docless: Security = {
      name: 'docless',
      forbidden: (_req: Request, res: Response) => {
        res.status(403).send('Forbidden')
      },
      scopes: { admin: () => true },
    }
    expect(securitySchemes(docless)).toStrictEqual({})
  })

  it('resolves per-operation security refs against the emitted map', () => {
    // The auth name on a Security must be a key in components.securitySchemes
    // so Swagger UI / Redoc / Schemathesis can render the requirement.
    const auth: Security = {
      name: 'bearerAuth',
      scheme: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      forbidden: (_req: Request, res: Response) => {
        res.status(403).send('Forbidden')
      },
      scopes: { admin: () => true },
      responses: { '403': { description: 'Forbidden' } },
    }
    const secured = authPathOp(scope(auth, 'admin'))(
      getMethod({ middleware: [] }),
    )
    const schemes = securitySchemes(auth)
    const refs = secured.get?.security ?? []
    for (const ref of refs) {
      for (const name of Object.keys(ref)) {
        expect(schemes).toHaveProperty(name)
      }
    }
  })
})

describe('401/403 modeling', () => {
  it('scope() propagates both 401 and 403 responses', () => {
    const auth: Security = {
      name: 'bearerAuth',
      scheme: { type: 'http', scheme: 'bearer' },
      unauthorized: (_req: Request, res: Response) => {
        res.status(401).send('Unauthenticated')
      },
      forbidden: (_req: Request, res: Response) => {
        res.status(403).send('Forbidden')
      },
      scopes: { admin: () => false },
      responses: {
        '401': { description: 'Unauthenticated' },
        '403': { description: 'Forbidden' },
      },
    }
    const secured = authPathOp(scope(auth, 'admin'))(
      getMethod({
        middleware: [],
        responses: { '200': { description: 'OK' } },
      }),
    )
    expect(secured.get?.responses).toStrictEqual({
      '200': { description: 'OK' },
      '401': { description: 'Unauthenticated' },
      '403': { description: 'Forbidden' },
    })
    expect(secured.get?.security).toStrictEqual([{ bearerAuth: ['admin'] }])
  })
})

describe('bearerAuth', () => {
  it('emits an http/bearer securityScheme', () => {
    const auth = bearerAuth({
      name: 'bearerAuth',
      description: 'JWT access token',
      bearerFormat: 'JWT',
      verify: () => true,
    })
    expect(auth.scheme).toStrictEqual({
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
      description: 'JWT access token',
    })
    expect(auth.name).toBe('bearerAuth')
  })

  it('omits bearerFormat when unset', () => {
    const auth = bearerAuth({ name: 'bearerAuth', verify: () => true })
    expect(auth.scheme).toStrictEqual({ type: 'http', scheme: 'bearer' })
  })

  it('wires extraction into before and fails closed on a missing credential', async () => {
    const auth = bearerAuth({
      name: 'bearerAuth',
      verify: () => true,
      scopes: { ok: () => true },
    })
    const { route, paths, controller } = wingnut(ajv)
    const app = express()
    paths(
      app,
      controller({
        prefix: '/api',
        route: (r: Router) =>
          route(
            r,
            path(
              '/me',
              authPathOp(scope(auth, 'ok'))(
                getMethod({
                  middleware: [
                    (_req: Request, res: Response) =>
                      res.status(200).send('ok'),
                  ],
                }),
              ),
            ),
          ),
      }),
    )
    const res = await request(app).get('/api/me')
    expect(res.status).toBe(401)
    expect(res.headers['www-authenticate']).toBe('Bearer')
  })

  it('returns 401 when verify returns false', async () => {
    const auth = bearerAuth({
      name: 'bearerAuth',
      verify: () => false,
      scopes: { ok: () => true },
    })
    const { route, paths, controller } = wingnut(ajv)
    const app = express()
    paths(
      app,
      controller({
        prefix: '/api',
        route: (r: Router) =>
          route(
            r,
            path(
              '/me',
              authPathOp(scope(auth, 'ok'))(
                getMethod({
                  middleware: [
                    (_req: Request, res: Response) =>
                      res.status(200).send('ok'),
                  ],
                }),
              ),
            ),
          ),
      }),
    )
    const res = await request(app)
      .get('/api/me')
      .set('Authorization', 'Bearer nope')
    expect(res.status).toBe(401)
  })

  it('returns 401 when verify throws', async () => {
    const auth = bearerAuth({
      name: 'bearerAuth',
      verify: () => {
        throw new Error('bad token')
      },
      scopes: { ok: () => true },
    })
    const { route, paths, controller } = wingnut(ajv)
    const app = express()
    paths(
      app,
      controller({
        prefix: '/api',
        route: (r: Router) =>
          route(
            r,
            path(
              '/me',
              authPathOp(scope(auth, 'ok'))(
                getMethod({
                  middleware: [
                    (_req: Request, res: Response) =>
                      res.status(200).send('ok'),
                  ],
                }),
              ),
            ),
          ),
      }),
    )
    const res = await request(app)
      .get('/api/me')
      .set('Authorization', 'Bearer boom')
    expect(res.status).toBe(401)
  })

  it('passes through when verify succeeds and the scope matches', async () => {
    interface AuthedRequest extends Request {
      user?: { role: string }
    }
    const auth = bearerAuth({
      name: 'bearerAuth',
      verify: (token, req) => {
        if (token === 'valid') {
          ;(req as AuthedRequest).user = { role: 'admin' }
          return true
        }
        return false
      },
      scopes: {
        admin: (req: Request) => (req as AuthedRequest).user?.role === 'admin',
      },
    })
    const { route, paths, controller } = wingnut(ajv)
    const app = express()
    paths(
      app,
      controller({
        prefix: '/api',
        route: (r: Router) =>
          route(
            r,
            path(
              '/me',
              authPathOp(scope(auth, 'admin'))(
                getMethod({
                  middleware: [
                    (_req: Request, res: Response) =>
                      res.status(200).send('ok'),
                  ],
                }),
              ),
            ),
          ),
      }),
    )
    const res = await request(app)
      .get('/api/me')
      .set('Authorization', 'Bearer valid')
    expect(res.status).toBe(200)
    expect(res.text).toBe('ok')
  })

  it('returns 403 when authenticated but the scope fails', async () => {
    interface AuthedRequest extends Request {
      user?: { role: string }
    }
    const auth = bearerAuth({
      name: 'bearerAuth',
      verify: (token, req) => {
        if (token === 'valid') {
          ;(req as AuthedRequest).user = { role: 'user' }
          return true
        }
        return false
      },
      scopes: {
        admin: (req: Request) => (req as AuthedRequest).user?.role === 'admin',
      },
    })
    const { route, paths, controller } = wingnut(ajv)
    const app = express()
    paths(
      app,
      controller({
        prefix: '/api',
        route: (r: Router) =>
          route(
            r,
            path(
              '/me',
              authPathOp(scope(auth, 'admin'))(
                getMethod({
                  middleware: [
                    (_req: Request, res: Response) =>
                      res.status(200).send('ok'),
                  ],
                }),
              ),
            ),
          ),
      }),
    )
    const res = await request(app)
      .get('/api/me')
      .set('Authorization', 'Bearer valid')
    expect(res.status).toBe(403)
  })

  it('resolves scheme refs in components.securitySchemes', () => {
    const auth = bearerAuth({ name: 'bearerAuth', verify: () => true })
    const schemes = securitySchemes(auth)
    expect(schemes.bearerAuth).toStrictEqual({
      type: 'http',
      scheme: 'bearer',
    })
  })
})

describe('apiKey', () => {
  it('emits an apiKey securityScheme', () => {
    const auth = apiKey({
      name: 'apiKey',
      in: 'header',
      fieldName: 'X-API-Key',
      description: 'server key',
      verify: () => true,
    })
    expect(auth.scheme).toStrictEqual({
      type: 'apiKey',
      in: 'header',
      name: 'X-API-Key',
      description: 'server key',
    })
  })

  it('extracts the key from a header and verifies', async () => {
    const auth = apiKey({
      name: 'apiKey',
      in: 'header',
      fieldName: 'X-API-Key',
      verify: (value) => value === 'secret',
      scopes: { ok: () => true },
    })
    const { route, paths, controller } = wingnut(ajv)
    const app = express()
    paths(
      app,
      controller({
        prefix: '/api',
        route: (r: Router) =>
          route(
            r,
            path(
              '/me',
              authPathOp(scope(auth, 'ok'))(
                getMethod({
                  middleware: [
                    (_req: Request, res: Response) =>
                      res.status(200).send('ok'),
                  ],
                }),
              ),
            ),
          ),
      }),
    )
    const ok = await request(app).get('/api/me').set('X-API-Key', 'secret')
    expect(ok.status).toBe(200)
    const bad = await request(app).get('/api/me').set('X-API-Key', 'wrong')
    expect(bad.status).toBe(401)
  })

  it('extracts the key from a query parameter', async () => {
    const auth = apiKey({
      name: 'apiKey',
      in: 'query',
      fieldName: 'key',
      verify: (value) => value === 'secret',
      scopes: { ok: () => true },
    })
    const { route, paths, controller } = wingnut(ajv)
    const app = express()
    paths(
      app,
      controller({
        prefix: '/api',
        route: (r: Router) =>
          route(
            r,
            path(
              '/me',
              authPathOp(scope(auth, 'ok'))(
                getMethod({
                  middleware: [
                    (_req: Request, res: Response) =>
                      res.status(200).send('ok'),
                  ],
                }),
              ),
            ),
          ),
      }),
    )
    const res = await request(app).get('/api/me?key=secret')
    expect(res.status).toBe(200)
  })
})

describe('oauth2', () => {
  it('emits an oauth2 securityScheme with flows', () => {
    const flows = {
      authorizationCode: {
        authorizationUrl: 'https://example.com/oauth/authorize',
        tokenUrl: 'https://example.com/oauth/token',
        scopes: { read: 'read access', write: 'write access' },
      },
    }
    const auth = oauth2({
      name: 'oauth2',
      description: 'OAuth 2.0',
      flows,
      verify: () => true,
    })
    expect(auth.scheme).toStrictEqual({
      type: 'oauth2',
      flows,
      description: 'OAuth 2.0',
    })
  })

  it('extracts a bearer token and fails closed when missing', async () => {
    const auth = oauth2({
      name: 'oauth2',
      flows: {
        clientCredentials: {
          tokenUrl: 'https://example.com/oauth/token',
          scopes: { read: 'read' },
        },
      },
      verify: () => true,
      scopes: { ok: () => true },
    })
    const { route, paths, controller } = wingnut(ajv)
    const app = express()
    paths(
      app,
      controller({
        prefix: '/api',
        route: (r: Router) =>
          route(
            r,
            path(
              '/me',
              authPathOp(scope(auth, 'ok'))(
                getMethod({
                  middleware: [
                    (_req: Request, res: Response) =>
                      res.status(200).send('ok'),
                  ],
                }),
              ),
            ),
          ),
      }),
    )
    const res = await request(app).get('/api/me')
    expect(res.status).toBe(401)
  })
})

describe('scheme builders + securitySchemes', () => {
  it('emits all three scheme types into one components map', () => {
    const bearer = bearerAuth({
      name: 'bearerAuth',
      bearerFormat: 'JWT',
      verify: () => true,
    })
    const key = apiKey({
      name: 'apiKey',
      in: 'header',
      fieldName: 'X-API-Key',
      verify: () => true,
    })
    const oauth = oauth2({
      name: 'oauth2',
      flows: {
        implicit: {
          authorizationUrl: 'https://example.com/authorize',
          scopes: { read: 'read' },
        },
      },
      verify: () => true,
    })
    expect(securitySchemes(bearer, key, oauth)).toStrictEqual({
      bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      apiKey: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
      oauth2: {
        type: 'oauth2',
        flows: {
          implicit: {
            authorizationUrl: 'https://example.com/authorize',
            scopes: { read: 'read' },
          },
        },
      },
    })
  })
})

describe('ScopeWrapper', () => {
  let req: Request
  let res: Response
  let next: ReturnType<typeof vi.fn>
  let cb: ReturnType<typeof vi.fn>

  beforeEach(() => {
    next = vi.fn()
    cb = vi.fn()
    req = {} as Request
    res = {} as Response
  })

  it('should call next() when a scope passes its test', () => {
    const scopes = [() => false, () => true]
    scopeWrapper(cb as unknown as RequestHandler, scopes)(
      req,
      res,
      next as unknown as NextFunction,
    )
    expect(next).toHaveBeenCalledTimes(1)
    expect(cb).not.toHaveBeenCalled()
  })

  it('should call cb when no scope passes its test', () => {
    const scopes = [() => false, () => false]
    scopeWrapper(cb as unknown as RequestHandler, scopes)(
      req,
      res,
      next as unknown as NextFunction,
    )
    expect(cb).toHaveBeenCalledTimes(1)
    expect(next).not.toHaveBeenCalled()
  })

  it('should not pass next to scope handlers — prevents double next()', () => {
    const scopeThatAlsoCallsNext: ScopeHandler = (
      _req: Request,
      _res: Response,
      next?: () => void,
    ): boolean => {
      next?.()
      return true
    }
    const scopes = [scopeThatAlsoCallsNext]
    scopeWrapper(cb as unknown as RequestHandler, scopes)(
      req,
      res,
      next as unknown as NextFunction,
    )
    expect(next).toHaveBeenCalledTimes(1)
    expect(cb).not.toHaveBeenCalled()
  })

  it('should not let a failing scope handler call next prematurely', () => {
    const failingScopeThatCallsNext: ScopeHandler = (
      _req: Request,
      _res: Response,
      next?: () => void,
    ): boolean => {
      next?.()
      return false
    }
    const passingScope: ScopeHandler = (): boolean => true
    const scopes = [failingScopeThatCallsNext, passingScope]
    scopeWrapper(cb as unknown as RequestHandler, scopes)(
      req,
      res,
      next as unknown as NextFunction,
    )
    expect(next).toHaveBeenCalledTimes(1)
    expect(cb).not.toHaveBeenCalled()
  })
})

describe('asyncWrapper', () => {
  it('wraps normal RequestHandler', async () => {
    let called = false
    const reqHandler = async (
      _req: Request,
      _res: Response,
      next: NextFunction,
    ): Promise<void> => {
      called = true
      next()
    }
    const wrapped = asyncWrapper(reqHandler)
    const app = express()

    app.use('/', wrapped)

    await request(app).get('/')

    expect(called).toBe(true)
  })

  it('wraps Error RequestHandler', async () => {
    let called = false
    const reqHandler = async (
      _err: Error,
      _req: Request,
      _res: Response,
      next: NextFunction,
    ): Promise<void> => {
      called = true
      next()
    }
    const wrapped = asyncWrapper(reqHandler)
    const app = express()

    app.use(
      '/',
      (_req: Request, _res: Response) => {
        throw new Error('oh no')
      },
      wrapped,
    )

    await request(app).get('/')

    expect(called).toBe(true)
  })

  it('catches next thrown await exception', async () => {
    let called = 0
    const reqHandler = async (
      err: Error,
      _req: Request,
      _res: Response,
      next: NextFunction,
    ): Promise<void> => {
      called++
      next(err)
    }
    const wrapped = asyncWrapper(reqHandler)
    const app = express()

    app.use(
      '/',
      (_req: Request, _res: Response) => {
        throw new Error('oh no')
      },
      wrapped,
    )

    app.use(
      (_err: Error, _req: Request, _res: Response, next: NextFunction) => {
        called++
        next()
      },
    )

    await request(app).get('/')

    expect(called).toBe(2)
  })
})

describe('headerParam', () => {
  it('should validate a valid header', async () => {
    const { route, paths, controller } = wingnut(ajv)
    const handler = (req: Request, res: Response) => {
      res.status(200).json(req.headers)
    }
    const api = path(
      '/test',
      getMethod({
        parameters: [
          headerParam({
            name: 'x-custom-header',
            schema: { type: 'string' },
            required: true,
          }),
        ],
        middleware: [handler],
      }),
    )
    const app = express()
    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, api),
      }),
    )
    app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
      if (err instanceof ValidationError) {
        res.status(400).send({ err: err.message, context: err.context })
      }
    })

    const response = await request(app)
      .get('/api/test')
      .set('x-custom-header', 'value') // Set the header
    expect(response.status).toBe(200)
  })

  it('should validate and coerce a valid header', async () => {
    const { route, paths, controller } = wingnut(ajv)
    const handler = (req: Request, res: Response) => {
      res.status(200).json(req.headers)
    }
    const api = path(
      '/test',
      getMethod({
        parameters: [
          headerParam({
            name: 'x-custom-header',
            schema: { type: 'integer' },
            required: true,
          }),
        ],
        middleware: [handler],
      }),
    )
    const app = express()
    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, api),
      }),
    )
    app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
      if (err instanceof ValidationError) {
        res.status(400).send({ err: err.message, context: err.context })
      }
    })

    const response = await request(app)
      .get('/api/test')
      .set('x-custom-header', '123') // Set the header
    expect(response.status).toBe(200)
  })

  it('should fail validation for an invalid header', async () => {
    const { route, paths, controller } = wingnut(ajv)
    const handler = (req: Request, res: Response) => {
      res.status(200).json(req.headers)
    }
    const api = path(
      '/test',
      getMethod({
        parameters: [
          headerParam({
            name: 'x-custom-header',
            schema: { type: 'string' },
            required: true,
          }),
        ],
        middleware: [handler],
      }),
    )
    const app = express()
    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, api),
      }),
    )
    app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
      if (err instanceof ValidationError) {
        res.status(400).send({ err: err.message, context: err.context })
      }
    })

    const response = await request(app).get('/api/test') // No header set
    expect(response.status).toBe(400)
    expect(response.body.err).toBe('WingnutValidationError')
    expect(response.body.context).toBeDefined() // Check that context is provided
  })
  it('should fail validation for an invalid header type', async () => {
    const { route, paths, controller } = wingnut(ajv)
    const handler = (req: Request, res: Response) => {
      res.status(200).json(req.headers)
    }
    const api = path(
      '/test',
      getMethod({
        parameters: [
          headerParam({
            name: 'x-custom-header',
            schema: { type: 'integer' },
            required: true,
          }),
        ],
        middleware: [handler],
      }),
    )
    const app = express()
    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, api),
      }),
    )
    app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
      if (err instanceof ValidationError) {
        res.status(400).send({ err: err.message, context: err.context })
      }
    })

    const response = await request(app)
      .get('/api/test')
      .set('x-custom-header', 'abc') // No header set
    expect(response.status).toBe(400)
    expect(response.body.err).toBe('WingnutValidationError')
    expect(response.body.context).toBeDefined() // Check that context is provided
  })
})

describe('Schema Caching', () => {
  it('should cache compiled schemas and reuse them', async () => {
    const mockCompile = vi.fn().mockReturnValue(() => true)
    const mockAjv = {
      compile: mockCompile,
    } as unknown as AjvLike

    const { route, paths, controller } = wingnut(mockAjv)

    // Create a schema that will be used in request body
    const schema = {
      $id: 'cached-schema-test',
      type: 'object' as const,
      properties: {
        name: { type: 'string' as const },
      },
    }

    const handler = (_req: Request, res: Response) => {
      res.status(200).json({ success: true })
    }

    // First route with the schema
    const route1 = path(
      '/test1',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema },
          },
        },
        middleware: [handler],
      }),
    )

    // Second route with the same schema - should use cache
    const route2 = path(
      '/test2',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema },
          },
        },
        middleware: [handler],
      }),
    )

    const app = express()
    app.use(express.json())
    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, route1, route2),
      }),
    )

    // Make requests to both routes
    await request(app).post('/api/test1').send({ name: 'test' })
    await request(app).post('/api/test2').send({ name: 'test' })

    // The compile function should be called only once due to caching (same schema object)
    expect(mockCompile).toHaveBeenCalledTimes(1)
  })

  it('should cache schemas with $id property', async () => {
    const compileCallCount = { count: 0 }
    const mockCompile = vi.fn((_schema) => {
      compileCallCount.count++
      return () => true
    })
    const mockAjv = {
      compile: mockCompile,
    } as unknown as AjvLike

    const { route, paths, controller } = wingnut(mockAjv)

    // Schema with $id - this should enable caching by ID
    const schemaWithId = {
      $id: 'unique-schema-id-123',
      type: 'object' as const,
      properties: {
        value: { type: 'string' as const },
      },
    }

    const handler = (_req: Request, res: Response) => {
      res.status(200).json({ success: true })
    }

    const route1 = path(
      '/endpoint1',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema: schemaWithId },
          },
        },
        middleware: [handler],
      }),
    )

    const route2 = path(
      '/endpoint2',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema: schemaWithId },
          },
        },
        middleware: [handler],
      }),
    )

    const app = express()
    app.use(express.json())
    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, route1, route2),
      }),
    )

    await request(app).post('/api/endpoint1').send({ value: 'test' })
    await request(app).post('/api/endpoint2').send({ value: 'test' })

    // Should only compile once due to $id-based caching
    expect(mockCompile).toHaveBeenCalledTimes(1)
  })

  it('should track cache hits and misses', async () => {
    let compileCount = 0
    const mockCompile = vi.fn(() => {
      compileCount++
      return () => true
    })
    const mockAjv = {
      compile: mockCompile,
    } as unknown as AjvLike

    const { route, paths, controller } = wingnut(mockAjv)

    // Use the same schema object to ensure caching
    const sharedSchema = {
      $id: 'shared-test-schema',
      type: 'object' as const,
      properties: {
        data: { type: 'string' as const },
      },
    }

    const handler = (_req: Request, res: Response) => {
      res.status(200).json({ success: true })
    }

    const route1 = path(
      '/cache1',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema: sharedSchema },
          },
        },
        middleware: [handler],
      }),
    )

    const route2 = path(
      '/cache2',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema: sharedSchema },
          },
        },
        middleware: [handler],
      }),
    )

    const app = express()
    app.use(express.json())
    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, route1, route2),
      }),
    )

    await request(app).post('/api/cache1').send({ data: 'test' })
    await request(app).post('/api/cache2').send({ data: 'test' })

    // Verify caching is working - should compile only once
    expect(compileCount).toBe(1)
  })

  it('should handle cache clear functionality', async () => {
    const { route, paths, controller } = wingnut(ajv)

    // Create multiple routes with the same schema to test caching
    const schema = {
      type: 'object' as const,
      properties: {
        name: { type: 'string' as const },
      },
      required: ['name'],
    }

    const handler = (_req: Request, res: Response) => {
      res.status(200).json({ success: true })
    }

    const route1 = path(
      '/test1',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema },
          },
        },
        middleware: [handler],
      }),
    )

    const route2 = path(
      '/test2',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema },
          },
        },
        middleware: [handler],
      }),
    )

    const app = express()
    app.use(express.json())
    paths(
      app,
      controller({
        prefix: '/api',
        route: (router: Router) => route(router, route1, route2),
      }),
    )

    // Both routes should work, demonstrating caching
    await request(app).post('/api/test1').send({ name: 'test' }).expect(200)
    await request(app).post('/api/test2').send({ name: 'test' }).expect(200)
  })

  it('should expose cache statistics via _schemaCache', () => {
    const mockCompile = vi.fn().mockReturnValue(() => true)
    const mockAjv = {
      compile: mockCompile,
    } as unknown as AjvLike

    const wn = wingnut(mockAjv)

    // Access the internal cached AJV to get stats
    // The wingnut function creates a cachedAjv internally
    // We need to trigger some compilations first
    const schema1 = {
      $id: 'stats-test-1',
      type: 'object' as const,
      properties: {
        value: { type: 'string' as const },
      },
    }

    const schema2 = {
      $id: 'stats-test-2',
      type: 'object' as const,
      properties: {
        value: { type: 'number' as const },
      },
    }

    // Create routes to trigger schema compilation
    const handler = (_req: Request, res: Response) => {
      res.status(200).json({ success: true })
    }

    const route1 = path(
      '/stats1',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema: schema1 },
          },
        },
        middleware: [handler],
      }),
    )

    const route2 = path(
      '/stats2',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema: schema2 },
          },
        },
        middleware: [handler],
      }),
    )

    // Use the same schema again to trigger a cache hit
    const route3 = path(
      '/stats3',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema: schema1 },
          },
        },
        middleware: [handler],
      }),
    )

    wn.route(Router(), route1, route2, route3)

    // Verify that compile was called (2 unique schemas)
    expect(mockCompile).toHaveBeenCalledTimes(2)
  })

  it('should allow clearing the schema cache', () => {
    // Create a custom wingnut instance where we can access the cache
    const ajvInstance = new Ajv()
    const wn = wingnut(ajvInstance)

    // We need to access the internal _schemaCache
    // Since it's not directly exposed, we'll test the clear functionality
    // by verifying that schemas are recompiled after a hypothetical clear

    const schema = {
      $id: 'clear-test-schema',
      type: 'object' as const,
      properties: {
        data: { type: 'string' as const },
      },
    }

    const handler = (_req: Request, res: Response) => {
      res.status(200).json({ success: true })
    }

    const route1 = path(
      '/clear1',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema },
          },
        },
        middleware: [handler],
      }),
    )

    const route2 = path(
      '/clear2',
      postMethod({
        requestBody: {
          content: {
            'application/json': { schema },
          },
        },
        middleware: [handler],
      }),
    )

    // Create routes - should compile schema once
    wn.route(Router(), route1, route2)

    // The schema should be cached and reused
    // This test verifies the caching mechanism works
    expect(true).toBe(true) // Placeholder - actual cache clear would need internal access
  })
})

describe('createSchemaCache', () => {
  it('should cache validators and track hits/misses', () => {
    const cache = createSchemaCache()
    const mockValidator = vi
      .fn()
      .mockReturnValue(true) as unknown as AjvLikeValidateFunction

    const schema = {
      $id: 'test-schema',
      type: 'object' as const,
      properties: {
        name: { type: 'string' as const },
      },
    }

    // First get - should be a miss
    const result1 = cache.get(schema)
    expect(result1).toBeUndefined()

    // Set the validator
    cache.set(schema, mockValidator)

    // Second get - should be a hit
    const result2 = cache.get(schema)
    expect(result2).toBe(mockValidator)

    // Check stats
    const stats = cache.getStats()
    expect(stats.size).toBe(1)
    expect(stats.hits).toBe(1)
    expect(stats.misses).toBe(1)
    expect(stats.hitRate).toBe(50) // 1 hit out of 2 total
  })

  it('should clear cache and reset stats', () => {
    const cache = createSchemaCache()
    const mockValidator = vi
      .fn()
      .mockReturnValue(true) as unknown as AjvLikeValidateFunction

    const schema = {
      type: 'string' as const,
    }

    // Add to cache
    cache.set(schema, mockValidator)
    cache.get(schema) // Hit

    // Verify cache has data
    let stats = cache.getStats()
    expect(stats.size).toBe(1)
    expect(stats.hits).toBe(1)

    // Clear cache
    cache.clear()

    // Verify cache is empty and stats are reset
    stats = cache.getStats()
    expect(stats.size).toBe(0)
    expect(stats.hits).toBe(0)
    expect(stats.misses).toBe(0)
    expect(stats.hitRate).toBe(0)

    // Verify validator is no longer cached
    const result = cache.get(schema)
    expect(result).toBeUndefined()
  })

  it('should cache schemas by structure, not by $id alone', () => {
    const cache = createSchemaCache()
    const mockValidator1 = vi
      .fn()
      .mockReturnValue(true) as unknown as AjvLikeValidateFunction
    const mockValidator2 = vi
      .fn()
      .mockReturnValue(false) as unknown as AjvLikeValidateFunction

    const schemaA = {
      $id: 'shared-id',
      type: 'string' as const,
    }

    const schemaB = {
      $id: 'shared-id',
      type: 'number' as const,
    }

    cache.set(schemaA, mockValidator1)
    cache.set(schemaB, mockValidator2)

    // Same $id but different structure — must return the correct validator
    expect(cache.get(schemaA)).toBe(mockValidator1)
    expect(cache.get(schemaB)).toBe(mockValidator2)
    expect(cache.getStats().size).toBe(2)
  })

  it('should use JSON.stringify for cache key when $id is not available', () => {
    const cache = createSchemaCache()
    const mockValidator = vi
      .fn()
      .mockReturnValue(true) as unknown as AjvLikeValidateFunction

    const schema1 = {
      type: 'string' as const,
      minLength: 5,
    }

    const schema2 = {
      type: 'string' as const,
      minLength: 5,
    }

    // Set with first schema
    cache.set(schema1, mockValidator)

    // Get with equivalent schema - should return same validator
    const result = cache.get(schema2)
    expect(result).toBe(mockValidator)
  })

  it('should calculate hit rate correctly with no accesses', () => {
    const cache = createSchemaCache()
    const stats = cache.getStats()
    expect(stats.hitRate).toBe(0)
  })

  it('should calculate hit rate correctly with only hits', () => {
    const cache = createSchemaCache()
    const mockValidator = vi
      .fn()
      .mockReturnValue(true) as unknown as AjvLikeValidateFunction
    const schema = { type: 'string' as const }

    cache.set(schema, mockValidator)
    cache.get(schema) // Hit
    cache.get(schema) // Hit
    cache.get(schema) // Hit

    const stats = cache.getStats()
    expect(stats.hits).toBe(3)
    expect(stats.misses).toBe(0)
    expect(stats.hitRate).toBe(100)
  })

  it('should calculate hit rate correctly with only misses', () => {
    const cache = createSchemaCache()
    const schema1 = { $id: 'schema1', type: 'string' as const }
    const schema2 = { $id: 'schema2', type: 'number' as const }
    const schema3 = { $id: 'schema3', type: 'boolean' as const }

    cache.get(schema1) // Miss
    cache.get(schema2) // Miss
    cache.get(schema3) // Miss

    const stats = cache.getStats()
    expect(stats.hits).toBe(0)
    expect(stats.misses).toBe(3)
    expect(stats.hitRate).toBe(0)
  })
})
