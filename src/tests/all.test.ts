/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { assert, beforeEach, vi } from "vitest";
import request from "supertest";
import { describe, it, expect } from "vitest";
import express, { NextFunction, Response, Router } from "express";
import Ajv from "ajv";
import {
  ParamIn,
  ParamType,
  Parameter,
  ScopeHandler,
} from "../types/open-api-3";
import {
  groupByParamIn,
  validateParams,
  validateBuilder,
  postMethod,
  getMethod,
  queryParam,
  authPathOp,
  Security,
  scope,
  scopeWrapper,
  asyncGetMethod,
  asyncPostMethod,
  asyncWrapper,
} from "../lib/index";
import { AjvLike } from "../types/common";
import { Request } from "express";
import { wingnut, path } from "../lib";
import { ValidationError } from "../lib/errors";

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
  };
}

describe("groupByParamIn", () => {
  it("should group by a parameter", () => {
    const param: Parameter = createParameter("path", "id", "string");
    const result = groupByParamIn([param]);
    expect(result).toStrictEqual({
      params: [param],
    });
  });
  it("should group by multiple params", () => {
    const params: Parameter[] = [
      createParameter("path", "id", "string"),
      createParameter("query", "name", "string"),
    ];
    const result = groupByParamIn(params);
    expect(result).toEqual({
      params: [params[0]],
      query: [params[1]],
    });
  });
});

describe("validateParams", () => {
  it("should validate params", () => {
    const params: (Partial<Parameter> & { name: string })[] = [
      createParameter("path", "id", "string"),
    ];
    const result = validateParams(params);
    expect(result).toStrictEqual({
      type: "object",
      properties: {
        id: {
          type: "string",
        },
      },
      required: [],
    });
  });
  it("should handle required", () => {
    const params: (Partial<Parameter> & { name: string })[] = [
      {
        in: "path",
        name: "id",
        required: true,
        schema: {
          type: "string",
        },
      },
    ];
    const result = validateParams(params);
    expect(result).toStrictEqual({
      type: "object",
      properties: {
        id: {
          type: "string",
        },
      },
      required: ["id"],
    });
  });
});

describe("validateBuilder", () => {
  it("should build a validator", () => {
    const mockAjvLike = {
      compile: () => () => true,
    };

    const validator = validateBuilder(mockAjvLike as unknown as AjvLike);
    const param: Parameter = createParameter("path", "id", "string");
    const result = validator([param]);
    expect(result.schema).toEqual({
      params: {
        properties: {
          id: {
            type: "string",
          },
        },
        required: [],
        type: "object",
      },
    });
  });
});

const ajv = new Ajv();
ajv.opts.coerceTypes = true;

describe("integration tests", () => {
  it("should validate request params", async () => {
    const { route, paths, controller } = wingnut(ajv);
    const userHandler = (req: Request, res: Response, next: NextFunction) => {
      res.status(200).json(req.params);
      next();
    };
    const createUserHandler = path(
      "/users",
      getMethod({
        parameters: [
          queryParam({
            name: "limit",
            description: "max number of users",
            schema: {
              type: "number",
              minimum: 1,
            },
          }),
        ],
        middleware: [userHandler],
      }),
    );
    const app = express();
    app.use(express.json());
    paths(
      app,
      controller({
        prefix: "/api",
        route: (router: Router) => route(router, createUserHandler),
      }),
    );
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
      if (err instanceof ValidationError) {
        res.status(400).send({ err: err.message, context: err.context });
      } else {
        res.status(400).send({ err: err.message });
      }
    });

    const response = await request(app).get("/api/users").query({ limit: 1 });
    expect(response.status).toBe(200);

    const badResponse = await request(app)
      .get("/api/users")
      .query({ limit: "foo" });
    expect(badResponse.status).toBe(400);
  });

  it("should validate request body", async () => {
    const { route, paths, controller } = wingnut(ajv);
    const userHandler = (req: Request, res: Response, next: NextFunction) => {
      res.status(200).json(req.body);
      next();
    };
    const createUserHandler = path(
      "/users",
      postMethod({
        requestBody: {
          description: "Create a user",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  name: {
                    type: "string",
                  },
                },
                required: ["name"],
              },
            },
          },
        },
        middleware: [userHandler],
      }),
    );
    const app = express();
    app.use(express.json());
    paths(
      app,
      controller({
        prefix: "/api",
        route: (router: Router) => route(router, createUserHandler),
      }),
    );
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
      res.status(400).send({ err: err.message });
    });

    const response = await request(app).post("/api/users").send({
      name: "test",
    });

    expect(response.status).toBe(200);

    const badResponse = await request(app)
      .post("/api/users")
      .send({
        name: ["foo"],
      });

    expect(badResponse.status).toBe(400);
  });

  it("should warn on duplicate paths", () => {
    const consoleSpyWarn = vi.spyOn(console, "warn").mockImplementation(() => {
      return;
    });
    const app = express();
    const { route, paths, controller } = wingnut(ajv);
    const duplicateController = controller({
      prefix: "/api",
      route: (router: Router) =>
        route(
          router,
          path(
            "/users",
            getMethod({
              middleware: [
                (_req: Request, res: Response, next: NextFunction) => {
                  res.status(200).send("hello");
                  next();
                },
              ],
            }),
          ),
        ),
    });
    paths(app, duplicateController, duplicateController);
    expect(consoleSpyWarn).toHaveBeenCalledWith(
      "WingnutWarning: get /api/users already exists",
    );
  });

  it("should handle multiple controllers", async () => {
    const app = express();
    const { route, paths, controller } = wingnut(ajv);
    let usersCalled = 0;
    let widgetCalled = 0;
    const usersController = controller({
      prefix: "/users",
      route: (router: Router) =>
        route(
          router,
          path(
            "/",
            getMethod({
              middleware: [
                (_req: Request, res: Response, next: NextFunction) => {
                  usersCalled++;
                  res.status(200).send("hello");
                  next();
                },
              ],
            }),
          ),
        ),
    });
    const widgetsController = controller({
      prefix: "/widgets",
      route: (router: Router) =>
        route(
          router,
          path(
            "/",
            getMethod({
              middleware: [
                (_req: Request, res: Response, next: NextFunction) => {
                  widgetCalled++;
                  res.status(200).send("hello");
                  next();
                },
              ],
            }),
          ),
        ),
    });

    paths(app, usersController, widgetsController);
    await request(app).get("/users").expect(200);
    await request(app).get("/widgets").expect(200);
    expect(usersCalled).toBe(1);
    expect(widgetCalled).toBe(1);
  });
});

interface UserAuth extends Request {
  user?: {
    level: number;
  };
}

describe("Security Schema", () => {
  const UserLevel =
    (minLevel: number): ScopeHandler =>
      (req: UserAuth): boolean =>
        (req.user?.level ?? 0) > minLevel;
  const routeHandler = () => {
    return;
  };

  it("should scope request to a user level", () => {
    const auth: Security = {
      name: "auth",
      handler: (_req: Request, res: Response) => {
        res.status(400).send("Not Auth");
      },
      scopes: {
        admin: UserLevel(100),
      },
      responses: {
        "400": {
          description: "Not Auth",
        },
      },
    };

    const adminAuth = authPathOp(scope(auth, "admin"));
    const actual = adminAuth(
      getMethod({
        middleware: [routeHandler],
        responses: {
          "200": {
            description: "Success",
          },
        },
      }),
    );
    expect(actual.get.security).toStrictEqual([
      {
        auth: ["admin"],
      },
    ]);
    expect(actual.get.responses).toStrictEqual({
      "200": {
        description: "Success",
      },
      "400": {
        description: "Not Auth",
      },
    });
  });
  it("should call the error middleware if provided", async () => {
    const app = express();
    const { route, paths, controller } = wingnut(ajv);
    let validated = 0;

    const testController = controller({
      prefix: "/widgets",
      route: (router: Router) =>
        route(
          router,
          path(
            "/",
            asyncPostMethod({
              requestBody: {
                content: {
                  "application/x-www-form-urlencoded": {
                    schema: {
                      type: "object",
                      properties: {
                        password: {
                          type: "string",
                          minLength: 8,
                          maxLength: 32,
                        },
                      },
                      required: ["password"],
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
                  res.status(200).send("hello");
                  next();
                },
                (
                  err: Error,
                  _req: Request,
                  res: Response,
                  next: NextFunction,
                ) => {
                  validated++;
                  res.status(400).send(err.name);
                  next();
                },
              ],
            }),
          ),
        ),
    });
    paths(app, testController);

    app.use(
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      (_err: Error, _req: Request, _res: Response, _next: NextFunction) => {
        assert.fail("Should not be called");
      },
    );

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    await request(app)
      .post("/widgets?limit=foo")
      .type("form")
      .send({ password: "moo" });
    expect(validated).toBe(1);
  });
  it("should call the next error middleware if provided", async () => {
    const app = express();
    const { route, paths, controller } = wingnut(ajv);
    let errorOne = 0;

    const htmlRouter = express.Router();

    const testController = controller({
      prefix: "/widgets",
      route: (router: Router) =>
        route(
          router,
          path(
            "/",
            asyncPostMethod({
              middleware: [
                async (
                  _req: Request,
                  _res: Response,
                  _next: NextFunction,
                ): Promise<void> => {
                  throw new Error("oh no");
                },
                (
                  _err: Error,
                  _req: Request,
                  _res: Response,
                  _next: NextFunction,
                ) => {
                  errorOne++;
                  throw new Error("oops");
                },
              ],
            }),
          ),
        ),
    });
    paths(htmlRouter, testController);

    htmlRouter.use(
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      (_err: Error, _req: Request, _res: Response, next: NextFunction) => {
        errorOne++;
        next();
      },
    );

    app.use(htmlRouter);

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    await request(app)
      .post("/widgets?limit=foo")
      .type("form")
      .send({ password: "moo" });
    expect(errorOne).toBe(2);
  });
  it("should call the before security middleware if provided", async () => {
    let calledBefore = false;
    const auth: Security = {
      name: "auth",
      before: (_req: Request, _res: Response, next: NextFunction) => {
        calledBefore = true;
        next();
      },
      handler: (_req: Request, res: Response) => {
        res.status(400).send("Not Auth");
      },
      scopes: {
        admin: UserLevel(100),
      },
      responses: {
        "400": {
          description: "Not Auth",
        },
      },
    };
    const adminAuth = authPathOp(scope(auth, "admin"));
    const { route, paths, controller } = wingnut(ajv);
    const handler = path(
      "/users",
      adminAuth(
        asyncGetMethod({
          middleware: [routeHandler],
          responses: {
            "200": {
              description: "Success",
            },
          },
        }),
      ),
    );
    const app = express();
    app.use(express.json());
    paths(
      app,
      controller({
        prefix: "/api",
        route: (router: Router) => route(router, handler),
      }),
    );
    await request(app).get("/api/users");
    expect(calledBefore).toBe(true);
  });
});

describe("ScopeWrapper", () => {
  let req: Request;
  let res: Response;
  let next: ReturnType<typeof vi.fn>;
  let cb: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    next = vi.fn();
    cb = vi.fn();
    req = {} as Request;
    res = {} as Response;
  });

  it("should call next() when a scope passes its test", () => {
    const scopes = [() => false, () => true];
    scopeWrapper(cb, scopes)(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(cb).not.toHaveBeenCalled();
  });

  it("should call cb when no scope passes its test", () => {
    const scopes = [() => false, () => false];
    scopeWrapper(cb, scopes)(req, res, next);
    expect(cb).toHaveBeenCalledTimes(1);
    expect(next).not.toHaveBeenCalled();
  });
});

describe("asyncWrapper", () => {
  it("wraps normal RequestHandler", async () => {
    let called = false;
    const reqHandler = (
      _req: Request,
      _res: Response,
      next: NextFunction,
    ): Promise<void> => {
      called = true;
      next();
      return;
    };
    const wrapped = asyncWrapper(reqHandler);
    const app = express();

    app.use("/", wrapped);

    await request(app).get("/");

    expect(called).toBe(true);
  });

  it("wraps Error RequestHandler", async () => {
    let called = false;
    const reqHandler = (
      _err: Error,
      _req: Request,
      _res: Response,
      next: NextFunction,
    ): Promise<void> => {
      called = true;
      next();
      return;
    };
    const wrapped = asyncWrapper(reqHandler);
    const app = express();

    app.use(
      "/",
      (_req: Request, _res: Response) => {
        throw new Error("oh no");
      },
      wrapped,
    );

    await request(app).get("/");

    expect(called).toBe(true);
  });

  it("catches next thrown await exception", async () => {
    let called = 0;
    const reqHandler = (
      err: Error,
      _req: Request,
      _res: Response,
      next: NextFunction,
    ): Promise<void> => {
      called++;
      next(err);
      return;
    };
    const wrapped = asyncWrapper(reqHandler);
    const app = express();

    app.use(
      "/",
      (_req: Request, _res: Response) => {
        throw new Error("oh no");
      },
      wrapped,
    );

    app.use(
      (_err: Error, _req: Request, _res: Response, next: NextFunction) => {
        called++;
        next();
      },
    );

    await request(app).get("/");

    expect(called).toBe(2);
  });
});
