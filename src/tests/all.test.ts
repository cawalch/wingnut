/* eslint-disable @typescript-eslint/no-explicit-any */
import { beforeEach, vi } from "vitest";
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
  Post,
  Get,
  QueryParam,
  AuthPathOp,
  Security,
  Scope,
  ScopeWrapper,
  AsyncGet,
} from "../lib/index";
import { AjvLike } from "../types/common";
import { Request } from "express";
import { wingnut, Path } from "../lib";
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
    const router = express.Router();
    const { Route, Paths, Controller } = wingnut(ajv, router);
    const userHandler = (req: Request, res: Response, next: NextFunction) => {
      res.status(200).json(req.params);
      next();
    };
    const createUserHandler = Path(
      "/users",
      Get({
        parameters: [
          QueryParam({
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
    Paths(
      app,
      Controller({
        prefix: "/api",
        route: (router: Router) => Route(router, createUserHandler),
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
    const router = express.Router();
    const { Route, Paths, Controller } = wingnut(ajv, router);
    const userHandler = (req: Request, res: Response, next: NextFunction) => {
      res.status(200).json(req.body);
      next();
    };
    const createUserHandler = Path(
      "/users",
      Post({
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
    Paths(
      app,
      Controller({
        prefix: "/api",
        route: (router: Router) => Route(router, createUserHandler),
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
    const router = express.Router();
    const { Route, Paths, Controller } = wingnut(ajv, router);
    const duplicateController = Controller({
      prefix: "/api",
      route: (router: Router) =>
        Route(
          router,
          Path(
            "/users",
            Get({
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
    Paths(app, duplicateController, duplicateController);
    expect(consoleSpyWarn).toHaveBeenCalledWith(
      "WingnutWarning: get /api/users already exists",
    );
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

    const AdminAuth = AuthPathOp(Scope(auth, "admin"));
    const actual = AdminAuth(
      Get({
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
  it("should call the before middleware if provided", async () => {
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
    const AdminAuth = AuthPathOp(Scope(auth, "admin"));
    const router = express.Router();
    const { Route, Paths, Controller } = wingnut(ajv, router);
    const handler = Path(
      "/users",
      AdminAuth(
        AsyncGet({
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
    Paths(
      app,
      Controller({
        prefix: "/api",
        route: (router: Router) => Route(router, handler),
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
    ScopeWrapper(cb, scopes)(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(cb).not.toHaveBeenCalled();
  });

  it("should call cb when no scope passes its test", () => {
    const scopes = [() => false, () => false];
    ScopeWrapper(cb, scopes)(req, res, next);
    expect(cb).toHaveBeenCalledTimes(1);
    expect(next).not.toHaveBeenCalled();
  });
});
