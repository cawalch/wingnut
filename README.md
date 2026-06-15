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

## Secure Routes with Scheme Builders

Authentication scheme builders compose extraction, verification, and the
OpenAPI securityScheme from one config — bring-your-own crypto. A failed
`verify` returns **401**; a failed scope returns **403**.

```typescript
import { Request, Response } from "express";
import {
  bearerAuth,
  authPathOp,
  scope,
  securitySchemes,
  putMethod,
  ParamSchema,
} from "wingnut";

// The user shape lives in the generic — no manual `extends Request` interface.
type AppUser = { id: string; level: number };

// A Security: extraction in `before`, verification via `verify`, the correct
// securityScheme on `scheme`, and a 401 slot — all from one config.
// bearerAuth<Scopes, User> threads the type through to verify + scope handlers.
const auth = bearerAuth<"admin", AppUser>({
  // name is the securityScheme key each operation references
  name: "bearerAuth",
  description: "JWT access token",
  bearerFormat: "JWT",
  // caller-supplied verification — false or a throw → 401
  verify: (token, req) => {
    try {
      req.user = verifyJwt(token); // your JWT lib — req.user is AppUser | undefined
      return true;
    } catch {
      return false;
    }
  },
  // authorization half — scope handlers evaluated with OR semantics
  // req.user is typed from the generic — no cast needed
  scopes: {
    admin: (req) => (req.user?.level ?? 0) >= 100,
  },
});

// authorization layer — authenticated but missing the scope → 403
const adminAuth = authPathOp(scope(auth, "admin"));

const updateUserSchema: ParamSchema = {
  type: "object",
  properties: {
    user: {
      type: "object",
      properties: { level: { type: "integer", minimum: 0 } },
      required: ["level"],
    },
  },
  required: ["user"],
};

// enforcement middleware is attached automatically; security docs too
const editUserAPI = adminAuth(
  putMethod({
    description: "Edit a user",
    requestBody: {
      description: "user attributes to edit",
      content: { "application/json": { schema: updateUserSchema } },
    },
    middleware: [
      /* express.js RequestHandler */
    ],
  }),
);

// Emit components.securitySchemes so per-operation security references
// resolve in Swagger UI / Redoc / Schemathesis.
const schemes = securitySchemes(auth);
// → { bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT", description: "JWT access token" } }
```

### apiKey & oauth2

```typescript
import { apiKey, oauth2 } from "wingnut";

// API key in a header (also: in: "query" | "cookie"; cookie needs cookie-parser)
const key = apiKey<"admin", AppUser>({
  name: "apiKey",
  in: "header",
  fieldName: "X-API-Key",
  verify: (value, req) => {
    req.user = lookupKey(value); // req.user is AppUser | undefined
    return !!req.user;
  },
});

// OAuth 2.0 — bearer extraction + flow documentation
const oauth = oauth2<"admin", AppUser>({
  name: "oauth2",
  flows: {
    authorizationCode: {
      authorizationUrl: "https://example.com/oauth/authorize",
      tokenUrl: "https://example.com/oauth/token",
      scopes: { read: "read access", write: "write access" },
    },
  },
  verify: (token, req) => {
    req.user = verifyAccessToken(token);
    return !!req.user;
  },
});
```

Wingnut ships **no** JWT/OAuth/session library — bring your own crypto. The
scheme builders compose the middleware and document the scheme; you supply
`verify` and populate `req.user`.

### Combining scopes & schemes (AND)

`scope()` OR-matches — a request is authorized when **any** listed scope
passes. Real authorization rules often need AND: "every one of these
scopes" or "every one of these schemes". Two combinators cover it, and both
emit OpenAPI the spec mandates, so docs and enforcement agree.

**`allScopes(auth, ...names)`** — AND within one scheme. Every named scope
must pass; a request missing any one is forbidden (**403**). The emitted
`security` entry is identical to `scope()`'s — only the runtime combination
differs.

```typescript
import { allScopes, authPathOp } from "wingnut";

const auth = bearerAuth<"read" | "paid", AppUser>({
  name: "bearerAuth",
  verify: (token, req) => {
    req.user = verifyJwt(token);
    return !!req.user;
  },
  scopes: {
    read: (req) => req.user?.canRead ?? false,
    paid: (req) => req.user?.isPaid ?? false,
  },
});

// Require BOTH 'read' AND 'paid' — a free-tier user with only 'read' is denied.
// Contrast: scope(auth, "read", "paid") would admit them (OR).
const paidReader = authPathOp(allScopes(auth, "read", "paid"));
```

**`both(...requirements)`** — AND across schemes. Each scheme's middleware
runs in order and every scheme must be satisfied; the first failing scheme
rejects the request via its own **401** (unauthenticated) or **403**
(forbidden) handler. `authPathOp` accepts the requirements directly or via
`both(...)`.

```typescript
import { apiKey, bearerAuth, both, scope, authPathOp } from "wingnut";

const jwt = bearerAuth<"admin", AppUser>({
  name: "bearerAuth",
  verify: (token, req) => {
    req.user = verifyJwt(token);
    return !!req.user;
  },
  scopes: { admin: (req) => req.user?.level >= 100 },
});

const key = apiKey<"admin", AppUser>({
  name: "apiKey",
  in: "header",
  fieldName: "X-API-Key",
  verify: (value, req) => {
    req.user = lookupKey(value);
    return !!req.user;
  },
  scopes: { admin: (req) => req.user?.level >= 100 },
});

// Require a valid JWT AND a valid API key. Emits security: [
//   { bearerAuth: ["admin"] }, { apiKey: ["admin"] }
// ] — OpenAPI AND's array entries, so Swagger UI / Redoc show both required.
const twoFactor = authPathOp(both(scope(jwt, "admin"), scope(key, "admin")));

// Equivalent — authPathOp is variadic and accepts the requirements directly.
const twoFactorAlt = authPathOp(scope(jwt, "admin"), scope(key, "admin"));
```

There is intentionally **no cross-scheme OR** combinator. OpenAPI 3.0's
`security` array is AND-only, so an honest `either(...)` cannot be emitted
without docs/runtime drift. For within-scheme OR, use `scope()`.

### Typed auth context

Each builder accepts `<Scopes, User>` generics that flow to `verify` and
scope handlers — no manual `extends Request` interfaces or casts. Derive the
authed-request shape in your handlers with `WnAuthType`:

```typescript
import { WnAuthType } from "wingnut";

type Authed = WnAuthType<typeof auth>; // Request & { user?: AppUser }

const me: Authed = /* ... */;
me.user?.id; // string | undefined — typed, no cast
```

### Low-level `Security`

Need a scheme the builders don't cover? Construct a `Security` directly — the
builders are thin wrappers over the same interface. Set `scheme`, wire
extraction in `before`, and provide `unauthorized` (401) / `forbidden` (403)
handlers.

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

// `auth` is the Security built by bearerAuth() in "Secure Routes with Scheme Builders"
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
