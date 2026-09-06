# Wingnut

A node.js library to build express.js APIs using [OpenAPI V3 specs](https://swagger.io/specification/)
for validation and documentation.

[![npm version](https://badge.fury.io/js/wingnut.svg)](https://badge.fury.io/js/wingnut)
[![codecov](https://codecov.io/gh/cawalch/wingnut/graph/badge.svg?token=E7LJCNGZET)](https://codecov.io/gh/cawalch/wingnut)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cawalch/wingnut/badge)](https://scorecard.dev/viewer/?uri=github.com/cawalch/wingnut)

## Node.js support

Wingnut requires **Node.js >= 22** (the current LTS baseline; Node 20 reached end of
life in April 2026). The published bundle is built with `esbuild --target=node22` and
type declarations target ES2022, matching this floor. CI runs on Node 22.

## OpenAPI version support

Wingnut accepts **both OpenAPI 3.0 and OpenAPI 3.1** specs.

- **Types.** `ParamSchema` is a superset of the 3.0 Schema Object that also covers the
  JSON Schema 2020-12 keywords used in 3.1: `type` arrays (e.g.
  `["string", "null"]`), the `"null"` type, `$defs` / `$ref`, `const`, `enum` with
  any JSON values, `not`, `if` / `then` / `else`, numeric `exclusiveMinimum` /
  `exclusiveMaximum`, and schema-valued `additionalProperties`.
- **Runtime.** The default `createWingnutAjv()` is a draft-07 AJV that evaluates 3.0
  specs; it also accepts and correctly validates the common 3.1 shorthands
  (`nullable`, `type` arrays, `const`, same-document `$ref`). For full 2020-12
  semantics — cross-schema `$ref` via `addSchema`, strict dialect checking — use
  `createWingnutAjv({ openapi: "3.1" })` (AJV 2020) or pass any `ajv/dist/2020`
  instance to `wingnut(ajv)`.
- **Nullability.** OpenAPI 3.0 `nullable: true` and 3.1 `type: [..., "null"]` both
  validate at runtime and both resolve to `T | null` via `WnDataType`.

## Installation

Install wingnut using `npm i wingnut`, or `pnpm i wingnut`, or `yarn i wingnut`.

### Dependencies

1. Express.js - `npm i express`
2. Ajv - `npm i ajv`
3. Ajv Formats (optional) - `npm i ajv-formats`

**Express compatibility:** supports Express 4 (>= 4.18.2) and Express 5 (`^4.18.2 || ^5.0.0`).

## Recommended AJV setup

Use the exported `createWingnutAjv()` helper instead of a bare `new Ajv()`. It applies the
config OpenAPI users almost always want:

- `coerceTypes: true` — Express hands query/path/header params to you as **strings**, so a
  `{ type: "integer" }` param only validates once AJV coerces `"42"` to a number.
- `allErrors: true` — report every failing field, not just the first.
- `formats: true` — installs [`ajv-formats`](https://github.com/ajv-validator/ajv-formats) so
  `format: "uuid" | "email" | "date-time" | ...` actually validates. (Install `ajv-formats`
  to use the default; pass `{ formats: false }` to opt out.)
- `openapi: "3.0" | "3.1"` — the schema dialect evaluated at runtime. `"3.0"`
  (default) is draft-07 AJV; `"3.1"` is AJV 2020 (JSON Schema 2020-12) for full
  OpenAPI 3.1 specs. See [OpenAPI version support](#openapi-version-support).

```typescript
import { createWingnutAjv } from "wingnut";

const ajv = createWingnutAjv(); // = new Ajv({ coerceTypes: true, allErrors: true }) + ajv-formats
```

Bring-your-own-AJV still works: pass any AJV instance (with the options you need) to `wingnut(ajv)`.

## Build-time validators (codegen)

The runtime path compiles every schema with AJV on each cold start. If you want to ship
**zero AJV at runtime**, generate precompiled, self-contained validators at build time:

```sh
npx wingnut build --entry src/build.ts --out dist/validators.cjs
```

Your build entry is a plain function that returns `Record<key, schema>` — typically the same
object you'd hand to the facade, so the validator keys always match:

```ts
// src/build.ts
export const build = () => ({
  [paramsKey]: paramsSchema,   // from getMethod / wingnut facade
  [bodyKey]: bodySchema,
});
```

Then at runtime use the **thin** entry (it ships no AJV — `require`-able without ajv or
ajv-formats installed):

```ts
import { codegenAjvLike, codegenSchemaKey, verifyCodegenMeta } from "wingnut/codegen";
import express from "express";
import * as validators from "../dist/validators.cjs";
import { meta } from "../dist/meta.json";

const { route, paths, controller } = wingnut(codegenAjvLike(validators, meta));
```

Guarantees and behavior:

- **Byte-parity semantics.** Generated code is AJV's own standalone output, compiled by the
  identical generator options AJV applies at runtime (`coerceTypes`, `allErrors`, formats,
  `openapi` dialect). Results, error arrays, and in-place coercion match the live path.
- **Fail-closed drift.** Validators are looked up by `JSON.stringify(schema)`. If a runtime
  schema has no precompiled entry — spec changed and you forgot to rebuild — the facade
  throws `WingnutCodegenError` instead of validating anything.
- **Stale detection in CI.** `npx wingnut build --check --entry src/build.ts --out dist/validators.cjs`
  re-runs the capture and exits `3` when the validator key set or generation metadata
  (AJV version, dialect, options hash) no longer matches the committed artifact.
- **Cold start.** No AJV module load and no per-schema compilation — only `require` of the
  generated file (~25 ms → ~8–16 ms measured for a 200-route app; the rest of the startup
  is Express and your code).

Limitations:

- **Static schemas only.** Schemas computed at request time, or from runtime inputs, are
  not supported (they would miss the artifact and fail closed).
- **Canonical generator options.** The thin runtime assumes the `createWingnutAjv()`
  defaults. Non-default AJV options (e.g. strict mode changes, custom keywords) stay on the
  runtime-AJV path.
- **Express stays.** Codegen removes AJV (~2.1 MB transitive) from the deployment, not
  Express.

## Usage

```typescript
import express, { Express, Router, Request, Response } from "express";

import { createWingnutAjv, wingnut, queryParam, getMethod, path, ParamSchema } from "wingnut";

const ajv = createWingnutAjv();

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

### Content-type dispatch

Wingnut inspects each request's `Content-Type` and validates against the matching media type declared in `content`, instead of picking one type up front:

```typescript
postMethod({
  requestBody: {
    content: {
      "application/json": { schema: jsonSchema },
      "application/x-www-form-urlencoded": { schema: formSchema },
    },
  },
});
```

- A JSON request validates against the `application/json` schema; a form request against the `application/x-www-form-urlencoded` schema.
- Vendor JSON types (`application/vnd.api+json`) and suffix wildcards (`application/*+json`) are supported wherever the spec allows them. (Your body parser must be configured to parse the media type, e.g. `express.json({ type: [...] })`.)
- If the request's `Content-Type` matches no declared type, Wingnut falls back to `application/json`, then `application/x-www-form-urlencoded` — the historical default — when one of those is declared. This preserves pre-existing behavior.
- If nothing matches and no such default is declared, validation fails with `UnsupportedMediaTypeError`; map its `status` (415) in your error handler.

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

3.1-only constructs with no TS equivalent — `$ref`, `not`, and `if` / `then` /
`else` — resolve to `unknown`. `$ref` targets are resolved by AJV at runtime
(local `$defs` included);

```typescript
type Geo = WnDataType<{ $ref: "#/$defs/Geo" }>; // unknown — AJV resolves the ref
```

### Swagger Documentation

```typescript
import express from 'express';
import { PathItem, createWingnutAjv, wingnut, securitySchemes, Security } from 'wingnut';
import swaggerUI from 'swagger-ui-express';

const ajv = createWingnutAjv();

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
