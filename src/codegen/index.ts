// Thin runtime entry for codegen-mode deploys. Bundled with AJV aliased to
// fail-fast stubs, so no ajv/ajv-formats at runtime and createWingnutAjv()
// throws instead of silently falling back. __WINGNUT_* are injected by
// esbuild --define (scripts/build.mjs); see defines.d.ts.
export * from '../index'
export type { CodegenDialect, CodegenMeta } from '../lib/codegen'
export {
  CODEGEN_CANONICAL_OPTIONS,
  codegenAjvLike,
  codegenOptionsHash,
  codegenSchemaKey,
  WingnutCodegenError,
} from '../lib/codegen'

import type { CodegenMeta } from '../lib/codegen'
import { codegenAjvLike as codegenAjvLikeImpl } from '../lib/codegen'
import type { AjvLikeValidateFunction } from '../types/common'

/**
 * `codegenAjvLike` that also verifies `meta.json` against this runtime's
 * identity (generator version, AJV major, options hash). Use with
 * artifacts produced by `wingnut build`.
 */
export const codegenAjvLikeVerified = (
  validators: Record<string, AjvLikeValidateFunction>,
  meta: CodegenMeta,
) =>
  codegenAjvLikeImpl(validators, meta, {
    generator: `wingnut@${__WINGNUT_VERSION__}`,
    ajv: __WINGNUT_AJV_VERSION__,
  })
