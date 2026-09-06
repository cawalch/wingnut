import type { Request } from 'express'
import { describe, expect, it } from 'vitest'
import type { WnDataType, WnParamDef } from '../index'
import { createWingnutAjv, wingnut } from '../index'

// Guards the documented public entry:
// `import { WnParamDef, WnDataType } from "wingnut"` (README, "Type-Safe
// Request Values"). `WnDataType`/`WnParamDef` are type-only, so they are
// imported with `import type`.
const Params = {
  properties: {
    limit: { description: 'max', schema: { type: 'integer', minimum: 1 } },
  },
} satisfies WnParamDef

type Query = WnDataType<typeof Params>
export type _Request = Request<unknown, unknown, unknown, Query>

describe('package entry', () => {
  it('exports the documented names', () => {
    expect(typeof createWingnutAjv).toBe('function')
    expect(typeof wingnut).toBe('function')
  })
})
