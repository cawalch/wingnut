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

const logListHandler = (req, res, next) => {
  res.status(200).json({
    logs: [
      "log1",
      "log2",
    ]
  })
}

Paths(
  app,
  Controller({
    prefix: "/api/logs",
    route: (router: Router) => Route(
      Path(
        "/",
        Get({
          tags: ["logs"],
          description: "List all logs",
          parameters: [
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
      )
    )
  })
)
```
