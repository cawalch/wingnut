import type { Request } from 'express'
import type { Security, WnAuthType } from '../lib'
import { bearerAuth } from '../lib'
import type { ScopeHandler } from '../types/open-api-3'

// Bidirectional assignability: true when A and B are mutually assignable.
type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false

// --- WnAuthType derives the authed-request shape from a Security definition ---

interface AppUser {
  id: string
  role: 'admin' | 'user'
}

// A Security<User> carries the user type; WnAuthType extracts it.
const typedAuth: Security<string, AppUser> = {
  name: 'bearerAuth',
  scheme: { type: 'http', scheme: 'bearer' },
  forbidden: () => undefined,
  scopes: {},
}

// WnAuthType<typeof typedAuth> should be Request & { user?: AppUser }
export const _authedRequest: Equals<
  WnAuthType<typeof typedAuth>,
  Request & { user?: AppUser }
> = true

// --- Untyped Security (User defaults to unknown) ---

const untypedAuth: Security = {
  name: 'bearerAuth',
  forbidden: () => undefined,
  scopes: {},
}

// WnAuthType of an untyped Security falls back to Request & { user?: unknown }
export const _untypedAuth: Equals<
  WnAuthType<typeof untypedAuth>,
  Request & { user?: unknown }
> = true

// --- bearerAuth threads User through to the Security ---

const jwt = bearerAuth<'admin', AppUser>({
  name: 'bearerAuth',
  verify: (_token, req) => {
    // req.user is AppUser | undefined — typed from the generic, no cast
    return req.user?.role === 'admin'
  },
  scopes: {
    // req.user is AppUser | undefined — no manual extends-Request interface
    admin: (req) => req.user?.role === 'admin',
  },
})

// WnAuthType<typeof jwt> preserves AppUser
export const _bearerAuthType: Equals<
  WnAuthType<typeof jwt>,
  Request & { user?: AppUser }
> = true

// --- ScopeHandler<User> provides typed req.user ---

// No manual UserAuth extends Request interface — the generic is the source.
const isAdmin: ScopeHandler<AppUser> = (req) => req.user?.role === 'admin'

export const _scopeHandlerType: Equals<
  ReturnType<typeof isAdmin>,
  boolean
> = true

// --- Default User=unknown: scope handlers see user?: unknown ---

const defaultHandler: ScopeHandler = (req) => req.user !== undefined
export const _defaultScopeHandler: Equals<
  ReturnType<typeof defaultHandler>,
  boolean
> = true
