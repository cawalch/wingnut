# Wingnut

A node.js library to build express.js APIs using [OpenAPI V3 specs](https://swagger.io/specification/) for validation and documentation.

[![npm version](https://badge.fury.io/js/wingnut.svg)](https://badge.fury.io/js/wingnut)
[![codecov](https://codecov.io/gh/cawalch/wingnut/graph/badge.svg?token=E7LJCNGZET)](https://codecov.io/gh/cawalch/wingnut)

## Installation

Install wingnut using `npm i wingnut`, or `pnpm i wingnut`, or `yarn i wingnut`.

### Dependencies

1. Express.js - `npm i express`
2. Ajv - `npm i ajv`

## Usage

```typescript
import express, { Express, Router } from "express";
import Ajv from 'ajv';

import { PathItem, wingnut } from 'wingnut';`

const { Route, Paths, Controller } = wingunut(ajv, router)

const app: Express = express();

const logListHandler = (req, res, next) => {
  res.status(200).json({
    logs: [
      "log1",
      "log2",
    ]
  })
}

const logResponseSchema = {
  type: "object",
  properties: {
    logs: {
      type: "array",
      items: {
        type: "string"
      }
    }
  }
}

const logListController = Get({
  tags: ["logs"],
  description: "List all logs",
  parameters: [
    // query parameter validation
    QueryParam({
      name: "limit",
      description: "Number of logs to return",
      schema: {
        type: "integer",
        minimum: 1,
        maximum: 100
      }
    })
  ],
  middleware: [
    logListHandler
  ],
  responses: {
    200: {
      description: "Logs",
      content: {
        "application/json": {
          schema: logResponseSchema
        }
      }
    }
  }
})

// similar to app.use(apis)
Paths(
  app,
  Controller({
    // map the above handler to /api/logs
    prefix: "/api/logs",
    route: (router: Router) => Route(
      Path(
        "/",
        logListController
      )
    )
  })
)
```

## Query Params

```typescript
// Validate `limit` against `req.query`
Query({
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
Post({
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
PathParam({
  name: "id",
  description: "log id",
  schema: {
    type: "string",
    format: "uuid",
  },
});
```

## Secure Routes with Scopes

```typescript
import { Scope, Security, AuthPathOp, ScopeHandler } from "wingnut";

// Build a scope handler to evaluate the user context (session)
const UserLevelAuth =
  (minLevel: number): ScopeHandler =>
  (req: UserAuth): boolean =>
    (req.user?.level ?? 0) >= minLevel;

// Build Authorization Security object
const auth: Security = {
  name: "user level authorization",
  // handler if user is not authenticated
  handler: (_req: Request, res: Response, next: NextFunction) => {
    res.status(400).send("Not Authorized");
  },
  scopes: {
    // define OpenAPI security scopes based on user levels
    // these can be referenced with wingunut's Scope
    admin: UserLeveltAuth(100),
    user: UserLevelAuth(10),
  },
  // response schema for authorization failure
  responses: {
    "400": {
      description: "Not Authorized",
    },
  },
};

// reusable scope handler to secure admin-only routes
const AdminAuth = AuthPathOp(Scope(auth, "admin"));

// possible user update schema
const updateUserSchema = {
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
const editUserAPI = AdminAuth(
  Put({
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
      // express.js RequestHandler requires admin authentication now
    ],
  }),
);
```

## Type-Safe Request Values

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
        format: "number",
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

// Request Handler
const ListLogsHandler = (
  req: ListRequest,
  res: Response,
  next: NextFunction,
) => {
  // limit and filter are correctly typed
  const { limit, filter } = req.query;
  // ...
};
```

### Swagger Documentation

```typescript
import express from 'express';
import Ajv from 'ajv';
import { PathItem, wingnut } from 'wingunut';
import swaggerUI from 'swagger-ui-express';

const ajv = new Ajv();
ajv.opts.coerceTypes = true;

// base swagger document
const swaggerPath = (paths: PathItem) => ({
  openapi: '3.0.0',
  info: {
    version: '1.0.0',
    title: 'My App Swagger Doc',
    description: 'My App Swagger Doc',
  },
  paths;
})

const { Route, Paths, Controller } = wingnut(ajv, router)

const app = express()

export const apis = (app: Express) => {
  const openApiPaths = Paths(
    app,
    Controller({
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
