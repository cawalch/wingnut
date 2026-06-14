# Wingnut

A node.js library to build express.js APIs using [OpenAPI V3 specs](https://swagger.io/specification/)
for validation and documentation.

[![npm version](https://badge.fury.io/js/wingnut.svg)](https://badge.fury.io/js/wingnut)
[![codecov](https://codecov.io/gh/cawalch/wingnut/graph/badge.svg?token=E7LJCNGZET)](https://codecov.io/gh/cawalch/wingnut)

## Installation

Install wingnut using `npm i wingnut`, or `pnpm i wingnut`, or `yarn i wingnut`.

### Dependencies

1. Express.js - `npm i express`
2. Ajv - `npm i ajv`

## Usage

```typescript
import express, { Express, Router, Request, Response } from "express";
import Ajv from "ajv";

import { wingnut, queryParam, getMethod, path, ParamSchema } from "wingnut";

const ajv = new Ajv();

const { route, paths, controller } = wingnut(ajv);

const app: Express = express();

const logListHandler = (_req: Request, res: Response) => {
  res.status(200).json({
    logs: ["log1", "log2"],
  });
};

const logResponseSchema: ParamSchema = {
  type: "object",
  properties: {
    logs: {
      type: "array",
      items: {
        type: "string",
      },
    },
  },
};

const logListController = getMethod({
  tags: ["logs"],
  description: "List all logs",
  parameters: [
    // query parameter validation
    queryParam({
      name: "limit",
      description: "Number of logs to return",
      schema: {
        type: "integer",
        minimum: 1,
        maximum: 100,
      },
    }),
  ],
  middleware: [logListHandler],
  responses: {
    200: {
      description: "Logs",
      content: {
        "application/json": {
          schema: logResponseSchema,
        },
      },
    },
  },
});

// similar to app.use(apis)
paths(
  app,
  controller({
    // map the above handler to /api/logs
    prefix: "/api/logs",
    route: (router: Router) => route(router, path("/", logListController)),
  }),
);

app.listen(3000, () => {
  console.log("Server started on port 3000");
});
```

## Query Params

```typescript
// Validate `limit` against `req.query`
queryParam({
  name: "limit",
  description: "max number",
  schema: {
    type: "integer",
    minimum: 1,
  },
});
```

## Request Body Validation

```typescript
// Validate `body` against `req.body`
postMethod({
  requestBody: {
    description: "Create a log entry",
    content: {
      "application/json": {
        schema: {
          type: "object",
          properties: {
            log: {
              type: "object",
              properties: {
                message: {
                  type: "string",
                },
              },
              required: ["message"],
            },
          },
          required: ["log"],
        },
      },
    },
  },
});
```

## Path Param Validation

```typescript
// Validate `id` against `req.params`
pathParam({
  name: "id",
  description: "log id",
  schema: {
    type: "string",
    format: "uuid",
  },
});
```

## Header Parameter Validation

```typescript
// Validate `x-api-key` against `req.headers`
import { wingnut, getMethod, path, headerParam } from "wingnut";

// ...

const apiKeyHandler = getMethod({
  parameters: [
    headerParam({
      name: "x-api-key",
      description: "API Key for authentication",
      schema: {
        type: "string",
        minLength: 32,
      },
      required: true,
    }),
  ],
  middleware: [
    (req: express.Request, res: express.Response) => {
      // Access the validated header
      const apiKey = req.headers["x-api-key"];
      console.log("API Key:", apiKey);
      res.status(200).send("OK");
    },
  ],
});
```

## Secure Routes with Scopes

```typescript
import { Request, Response } from "express";
import {
  scope,
  Security,
  authPathOp,
  securitySchemes,
  ScopeHandler,
  putMethod,
  ParamSchema,
} from "wingnut";

interface UserAuth extends Request {
  user?: { level: number };
}

// Build a scope handler to evaluate the user context (session)
const userLevelAuth =
  (minLevel: number): ScopeHandler =>
  (req: UserAuth): boolean =>
    (req.user?.level ?? 0) >= minLevel;

// A Security definition: enforcement middleware + OpenAPI docs in one place,
// so the guards and the documentation cannot drift.
const auth: Security = {
  // name is the securityScheme key each operation references
  name: "bearerAuth",
  // OpenAPI securityScheme, emitted into components.securitySchemes
  scheme: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
  // optional 401 handler — invoked when authentication fails
  // (missing/invalid token). Verify the token in a `before` hook.
  unauthorized: (_req: Request, res: Response) => {
    res.status(401).send("Unauthenticated");
  },
  // 403 handler — invoked when authenticated but the scope check fails
  forbidden: (_req: Request, res: Response) => {
    res.status(403).send("Forbidden");
  },
  scopes: {
    // OpenAPI security scopes, evaluated with OR semantics
    admin: userLevelAuth(100),
    user: userLevelAuth(10),
  },
  // response schemas surfaced on each secured operation
  responses: {
    "401": { description: "Unauthenticated" },
    "403": { description: "Forbidden" },
  },
};

// reusable scope handler to secure admin-only routes
const adminAuth = authPathOp(scope(auth, "admin"));

// possible user update schema
const updateUserSchema: ParamSchema = {
  type: "object",
  properties: {
    user: {
      type: "object",
      properties: {
        level: {
          type: "integer",
          minimum: 0,
        },
      },
      required: ["level"],
    },
  },
  required: ["user"],
};

// perform authorization using AdminAuth before updating
const editUserAPI = adminAuth(
  putMethod({
    description: "Edit a user",
    requestBody: {
      description: "user attributes to edit",
      content: {
        "application/json": {
          schema: updateUserSchema,
        },
      },
    },
    middleware: [
      // express.js RequestHandler — admin-scoped automatically
    ],
  }),
);

// Emit components.securitySchemes so per-operation security references
// resolve in Swagger UI / Redoc / Schemathesis. Securities without a
// scheme are skipped.
const schemes = securitySchemes(auth);
// → { bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" } }
```

Wingnut ships **no** JWT/OAuth/session library — bring your own crypto. Verify
the token in a `before` hook and populate `req.user`; wingnut only composes
the middleware and documents the scheme.

## Type-Safe Request Values

`WnDataType<S>` resolves a Wingnut / OpenAPI-3 schema to the TypeScript type a
handler sees in `req.body`, `req.query`, or `req.params`. Pair it with
`WnParamDef` and `satisfies` so the literal schema is preserved for inference.

```typescript
import { WnParamDef, WnDataType } from "wingnut";

const ListQueryParams = {
  properties: {
    limit: {
      description: "Number of logs to return",
      schema: {
        type: "integer",
        minimum: 1,
        maximum: 100,
        default: 10,
      },
    },
    filter: {
      description: "Filter logs by message",
      schema: {
        type: "string",
        nullable: true,
      },
    },
  },
} satisfies WnParamDef;

type ListRequest = Request<
  unknown,
  unknown,
  unknown,
  WnDataType<typeof ListQueryParams>
>;

// limit: number | undefined, filter: string | null | undefined
const listLogsHandler = (req: ListRequest, res: Response, next: NextFunction) => {
  const { limit, filter } = req.query;
  // ...
};
```

`nullable: true` (OpenAPI 3.0) and `type` arrays including `"null"`
(JSON Schema / OpenAPI 3.1) both resolve to `T | null`:

```typescript
type A = WnDataType<{ type: "string"; nullable: true }>; // string | null
type B = WnDataType<{ type: readonly ["string", "null"] }>; // string | null
```

`const` and `enum` resolve to their literal union (use `as const` on the
array):

```typescript
type Role = WnDataType<{ type: "string"; enum: readonly ["admin", "user"] }>; // "admin" | "user"
type Status = WnDataType<{ const: "pending" }>; // "pending"
```

Composition keywords resolve as unions or intersections:

```typescript
type Id = WnDataType<{
  anyOf: readonly [{ type: "string" }, { type: "integer" }];
}>; // string | number

type Audit = WnDataType<{
  allOf: readonly [
    { properties: { by: { type: "string" } } },
    { properties: { at: { type: "integer" } }; required: readonly ["at"] },
  ];
}>; // { by?: string } & { at: number }
```

Object schemas with `required`, optional properties, and `additionalProperties`
combine into a single inferred type:

```typescript
type Body = WnDataType<{
  type: "object";
  properties: {
    name: { type: "string" };
    role: { type: "string"; enum: readonly ["admin", "user"] };
    meta: { type: "object" };
  };
  required: readonly ["name", "role"];
  additionalProperties: true;
}>;
// { name?: string; role?: "admin" | "user"; meta?: Record<string, unknown> }
//   & { name: string; role: "admin" | "user" }
//   & { [key: string]: unknown }
```

### Swagger Documentation

```typescript
import express from 'express';
import Ajv from 'ajv';
import { PathItem, wingnut, securitySchemes, Security } from 'wingnut';
import swaggerUI from 'swagger-ui-express';

const ajv = new Ajv();
ajv.opts.coerceTypes = true;

// `auth` is the Security definition from "Secure Routes with Scopes"
const securities: Security[] = [auth];

// base swagger document
const swaggerPath = (paths: PathItem) => ({
  openapi: '3.0.0',
  info: {
    version: '1.0.0',
    title: 'My App Swagger Doc',
    description: 'My App Swagger Doc',
  },
  paths,
  components: { securitySchemes: securitySchemes(...securities) },
})

const { route, paths, controller } = wingnut(ajv)

const app = express()

export const apis = (app: Express) => {
  const openApiPaths = paths(
    app,
    controller({
      // map the above handler to /api/logs
    })
  )
  // map all paths within the swagger documentation
  const swaggerDoc = swaggerPath(openApiPaths)
  // serve swagger documentation at /api-docs
  app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerDoc))
}

// app.ts
apis(app)
app.listen(3000)
```
