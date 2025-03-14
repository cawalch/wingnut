import Ajv from 'ajv'
import express, { NextFunction, Response, Router } from 'express'
import { Request } from 'express'
import request from 'supertest'
import { assert, beforeEach, vi } from 'vitest'
import { describe, expect, it } from 'vitest'
import { path, headerParam, wingnut } from '../lib'
import { ValidationError } from '../lib/errors'
import {
  Security,
  asyncGetMethod,
  asyncPostMethod,
  asyncWrapper,
  authPathOp,
  getMethod,
  groupByParamIn,
  postMethod,
  queryParam,
  scope,
  scopeWrapper,
  validateBuilder,
  validateParams,
} from '../lib/index'
import { AjvLike } from '../types/common'
import {
  ParamIn,
  ParamType,
  Parameter,
  ScopeHandler,
} from '../types/open-api-3'

function createParameter(
  inValue: ParamIn,
  nameValue: string,
  typeValue: ParamType,
): Parameter {
  return {
    in: inValue,
    name: nameValue,
    schema: {
      type: typeValue,
    },
  }
}

describe('groupByParamIn', () => {
  it('should group by a parameter', () => {
    const param: Parameter = createParameter('path', 'id', 'string')
    const result = groupByParamIn([param])
    expect(result).toStrictEqual({
      params: [param],
    })
  })
  it('should group by multiple params', () => {
    const params: Parameter[] = [
      createParameter('path', 'id', 'string'),
      createParameter('query', 'name', 'string'),
    ]
    const result = groupByParamIn(params)
    expect(result).toEqual({
      params: [params[0]],
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
      params: {
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
      headers: {
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
})

const ajv = new Ajv()
ajv.opts.coerceTypes = true

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

  it('should warn on duplicate paths', () => {
    const consoleSpyWarn = vi.spyOn(console, 'warn').mockImplementation(() => {
      return
    })
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
    paths(app, duplicateController, duplicateController)
    expect(consoleSpyWarn).toHaveBeenCalledWith(
      'WingnutWarning: get /api/users already exists',
    )
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
      handler: (_req: Request, res: Response) => {
        res.status(400).send('Not Auth')
      },
      scopes: {
        admin: UserLevel(100),
      },
      responses: {
        '400': {
          description: 'Not Auth',
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
    expect(actual.get.security).toStrictEqual([
      {
        auth: ['admin'],
      },
    ])
    expect(actual.get.responses).toStrictEqual({
      '200': {
        description: 'Success',
      },
      '400': {
        description: 'Not Auth',
      },
    })
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
      handler: (_req: Request, res: Response) => {
        res.status(400).send('Not Auth')
      },
      scopes: {
        admin: UserLevel(100),
      },
      responses: {
        '400': {
          description: 'Not Auth',
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
    const consoleSpyError = vi
      .spyOn(console, 'error')
      .mockImplementation(() => {
        return
      })
    const security: Security = {
      name: 'auth',
      handler: (_req: Request, res: Response) => {
        res.status(400).send('Not Auth')
      },
      scopes: {
        admin: () => true,
      },
      responses: {
        '400': {
          description: 'Not Auth',
        },
      },
    }

    try {
      scope(security, 'admin', 'nonexistent')
      assert.fail('Expected an error to be thrown')
    } catch (err) {
      expect(err.message).toBe("Scope 'nonexistent' not found")
    }

    expect(consoleSpyError).toHaveBeenCalledWith(
      "WingnutError: Scope 'nonexistent' not found in security.scopes",
    )

    consoleSpyError.mockRestore()
  })

  it('should not throw error when all scopes exist', () => {
    const consoleSpyError = vi
      .spyOn(console, 'error')
      .mockImplementation(() => {
        return
      })
    const security: Security = {
      name: 'auth',
      handler: (_req: Request, res: Response) => {
        res.status(400).send('Not Auth')
      },
      scopes: {
        admin: () => true,
        moderator: () => true,
      },
      responses: {
        '400': {
          description: 'Not Auth',
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
    scopeWrapper(cb, scopes)(req, res, next)
    expect(next).toHaveBeenCalledTimes(1)
    expect(cb).not.toHaveBeenCalled()
  })

  it('should call cb when no scope passes its test', () => {
    const scopes = [() => false, () => false]
    scopeWrapper(cb, scopes)(req, res, next)
    expect(cb).toHaveBeenCalledTimes(1)
    expect(next).not.toHaveBeenCalled()
  })
})

describe('asyncWrapper', () => {
  it('wraps normal RequestHandler', async () => {
    let called = false
    const reqHandler = (
      _req: Request,
      _res: Response,
      next: NextFunction,
    ): Promise<void> => {
      called = true
      next()
      return
    }
    const wrapped = asyncWrapper(reqHandler)
    const app = express()

    app.use('/', wrapped)

    await request(app).get('/')

    expect(called).toBe(true)
  })

  it('wraps Error RequestHandler', async () => {
    let called = false
    const reqHandler = (
      _err: Error,
      _req: Request,
      _res: Response,
      next: NextFunction,
    ): Promise<void> => {
      called = true
      next()
      return
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
    const reqHandler = (
      err: Error,
      _req: Request,
      _res: Response,
      next: NextFunction,
    ): Promise<void> => {
      called++
      next(err)
      return
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
