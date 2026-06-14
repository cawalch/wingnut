# Roadmap

Direction for wingnut beyond the 2026-05-07 review items (all closed, see
`BUGS.md`). The work below is scoped to a single defensible differentiator
and gated by a set of integrity constraints.

## Thesis

Wingnut is a code-first OpenAPI 3 builder for Express that composes
validation, auth, request handling, and response layers from functions — no
code generation step, no decorator/DI system, no schema-private runtime
format. Request and response types are inferred from real JSON Schema
(`WnDataType`); the same schemas power ajv validation and served Swagger
docs.

The uncontested differentiator is the **security-DSL**: a single `Security`
definition that yields authorization middleware *and* OpenAPI `security`
documentation from one object. No incumbent composes both from one source:

- Fastify splits auth from `@fastify/swagger`; the docs and the guards drift.
- Hono's `createRoute.security` is documentation metadata only — no
  enforcement.
- NestJS runs parallel `@UseGuards` and `@ApiBearerAuth` systems.
- passport is authentication only, with no OpenAPI emission.

This roadmap is about finishing and sharpening that layer — without turning
wingnut into a framework or an auth library.

## Integrity constraints

Any change must satisfy all of these. They follow from the thesis above,
not from preference.

1. **Standards-native.** Emit real OpenAPI 3.0 / JSON Schema. No
   wingnut-private auth vocabulary on the wire.
2. **Composable functions.** No decorators, no classes, no DI container.
3. **Bring-your-own crypto.** Like ajv, wingnut ships no JWT/OAuth/session
   library. It composes and documents; the caller supplies verification.
4. **Single source of truth.** One definition → middleware + docs that
   cannot drift.
5. **Zero core deps beyond ajv + the router surface.** Security must not
   pull in passport or a token library.
6. **Testable.** Scope handlers stay pure functions over a request shape.

Proposals on the wrong side of any line belong in a different project.

## Current state of the security-DSL

The wedge exists but is ~40% built. Grounded gaps:

- **`components.securitySchemes` is never emitted.** Per-operation
  `security` references resolve to names that do not appear in the spec
  (`authPathOp`, `src/lib/index.ts:556`). Swagger UI and Redoc cannot render
  auth; Schemathesis contract tests drop the requirement.
- **The spec field is misspelled.** `Components.securitySchema` in
  `src/types/open-api-3.ts:22`; the OpenAPI field is `securitySchemes`.
  Spec-compliant tools ignore the misspelled key.
- **Only authorization, no authentication.** `scope()` OR-matches scope
  handlers via `some()` (`scopeWrapper`, `src/lib/index.ts:460`). There is
  no credential extraction, no scheme modeling, no 401-vs-403 distinction.
  `Security.before` is an undocumented escape hatch for extraction.
- **OR-only composition.** No AND (`allScopes`), no multi-scheme
  combination.
- **Untyped auth context.** `ScopeHandler` receives bare `Request`
  (`src/types/open-api-3.ts:47`). `req.user` requires a manual
  `UserAuth extends Request` per app.

## Roadmap

### Layer 0 — Fix the foundation

Must-do; unblocks everything else. Independently shippable.

- Rename `securitySchema` → `securitySchemes` across types and usage.
- Emit `components.securitySchemes` from registered `Security` objects so
  per-op `security` references resolve.
- Model 401 (unauthenticated) vs 403 (forbidden). The README currently
  teaches `400` for unauthorized.

**Integrity:** pure standards compliance, no new surface.

### Layer 1 — Authentication scheme builders

The actual value-add. Adds the missing authentication half.

Scheme builders modeled on the OpenAPI securityScheme types, each returning
a `Security` with extraction in `before` and bring-your-own verification:

```typescript
const jwt = bearerAuth({
  name: 'bearerAuth',
  description: 'JWT access token',
  verify: (token, req) => {
    ;(req as AuthedRequest).user = verifyJwt(token) // caller's lib
    return true // false → 401 handler
  },
})

const admin = scope(jwt, 'admin') // authorization layer
const editUser = authPathOp(admin)(putMethod({ /* ... */ }))
```

Deliverables: `bearerAuth`, `apiKey({ in, name })`, `oauth2({ flows })`.
Each emits its correct `securityScheme` type. Failed `verify` → 401; failed
scope → 403; distinct handlers.

**Integrity:** callers supply `verify`, satisfying constraint 3. Wingnut
composes and documents only.

### Layer 2 — Composition algebra

Moderate value; build only when real usage demands it.

- `allScopes(auth, 'read', 'paid')` — AND (current `scope` is OR).
- `both(schemeA, schemeB)` — multi-scheme combination.
- `either(...reqs)` — maps to multiple ops; document the spec limitation
  honestly (OpenAPI has no native cross-scheme OR).

Stop there. Do not build an RBAC/ABAC policy engine.

### Layer 3 — Type-safe auth

Sharpens the story; parallels the `WnDataType` work.

- `Security<User>` so scope handlers receive typed `req.user`.
- Optional `WnAuthType<S>` deriving the authed-request shape from the
  definition, zero-dep and pure type-level.

**Integrity:** pure type-level, zero runtime cost.

## Structural direction

The schema/router layer is a commodity won by TypeBox and Fastify. The
security-DSL is the layer wingnut can own. Three options, ranked by
integrity fit:

- **A. Stay Express-only, own the lane.** Lowest risk, capped ceiling.
  Pitch: "Fastify-grade schema-as-code with unified security, for Express."
  Audience is the brownfield of existing Express apps.
- **B. Router-adapter abstraction (`@wingnut/express|fastify|hono`).**
  Highest risk to integrity. Turns a composable library into a
  meta-framework; adapter seams leak; risks becoming a worse Fastify. Do
  not lead with this.
- **C. Make the security-DSL the product; keep Express as the reference
  substrate. Recommended.** Keep one package. Design Layer 1 so the
  `Security`/`scope`/scheme-builder definitions are framework-neutral and
  only the `scopeWrapper` binding is Express-specific (~one function of
  coupling). Later, evaluate contributing the security layer as a plugin to
  an ecosystem that already has the schema substrate (`@fastify/wingnut-security`
  or a Hono extension). Ride a large substrate; contribute the missing
  piece.

## Sequencing

```
Layer 0    fix securitySchemes typo + emit components.securitySchemes
           (clean, shippable; do first)
Layer 1    bearerAuth / apiKey / oauth2 scheme builders
           (the value-add; the reason to adopt wingnut)
Layer 3    typed Security<User>, WnAuthType
           (parallels WnDataType; sharpens the story)
Layer 2    allScopes / both — only if usage demands
Option C   evaluate a Fastify/Hono security plugin once the layer is
           proven on Express
```

Layer 0 before Layer 1: building auth on a broken foundation is wasted
effort, and the typo and missing emission are independently shippable.
Layer 1 before Layer 2/3: authentication is the missing half; the algebra
and typing decorate an incomplete story until it exists.

## Explicitly out of scope

- A JWT, OAuth, or session library (violates constraint 3).
- Decorators or a DI container (violates constraint 2; that is NestJS's
  lane).
- A router-adapter rewrite before the security layer is proven (turns a
  library into a framework; risks becoming a worse Fastify).
- An RBAC/ABAC policy engine (scope creep into a different product).
