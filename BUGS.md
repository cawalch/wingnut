# Wingnut Bug Findings — Code Review 2026-05-07

## Critical

### BUG-1: `scopeWrapper` passes `next` to scope handlers — double `next()` calls
- **File:** `src/lib/index.ts:446-455`
- **Status:** ✅ Fixed (merged via #59)
- **Branch:** `bugfix/BUG-1-scope-wrapper-double-next`
- Every `ScopeHandler` receives Express `next` as its 3rd argument. If a scope handler both returns `true` AND calls `next()`, the middleware chain advances twice. Since `some()` passes `next` to every scope until one returns `true`, a failing scope handler could also call `next()` prematurely.
- **Impact:** Duplicate handler execution, double responses, or "headers already sent" errors.

### BUG-2: `paths()` duplicate detection only checks the first method of a PathObject
- **File:** `src/lib/index.ts:363-367`
- **Status:** ✅ Fixed (merged via PR #60)
- **Branch:** `bugfix/BUG-2-paths-duplicate-detection-first-method-only`
- `Object.keys(item[path])[0]` only inspects the first HTTP method. Additional methods bypass the duplicate check.
- **Impact:** Silent route conflicts, undefined routing behavior.

### BUG-3: `authPathOp` only applies security to the first method
- **File:** `src/lib/index.ts:542-553`
- **Status:** 🔧 In Progress
- **Branch:** `bugfix/BUG-3-authpathop-only-secures-first-method`
- `const [[method, operation]] = Object.entries(pathObject)` destructures only the first entry. Remaining methods are silently unprotected (dropped from returned PathObject).
- **Impact:** Security middleware silently not applied to additional methods.

### BUG-4: Schema cache key collision via `$id` — wrong validator returned
- **File:** `src/lib/index.ts:141-148`
- **Status:** 📋 Pending
- Two structurally different schemas with the same `$id` produce the same cache key, returning the wrong compiled validator.
- **Impact:** Incorrect request validation — bad data passes, valid data rejected.

## Medium

### BUG-5: `Object.assign` in `paths()` silently overwrites routes
- **File:** `src/lib/index.ts:375`
- **Status:** 📋 Pending
- If two controllers produce PathItems with overlapping path keys, `Object.assign(acc.out, item)` silently overwrites.
- **Impact:** Lost route definitions.

### BUG-6: `validateParams` shares param schema objects by reference
- **File:** `src/lib/index.ts:74`
- **Status:** 📋 Pending
- `schema.properties[param.name] = param.schema` is a direct reference. AJV may mutate schemas during compilation, contaminating shared Parameter objects across routes.
- **Impact:** Cross-route schema contamination.

### BUG-7: `param()` spread allows `in` to be overridden at runtime
- **File:** `src/lib/index.ts:558-563`
- **Status:** 📋 Pending
- `Omit<Parameter, 'in'>` only protects at compile time. At runtime, an object with `in` property would override the intended param location.
- **Impact:** Wrong validation target (e.g., body instead of query).
