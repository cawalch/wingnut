import { createHash } from 'node:crypto'
import type {
  AjvLike,
  AjvLikeSchemaObject,
  AjvLikeValidateFunction,
} from '../types/common'

// Codegen runtime. Never import ajv/ajv-formats here — codegen deploys
// don't install them.

/** Thrown on any codegen drift or miss — fail closed, never silent. */
export class WingnutCodegenError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'WingnutCodegenError'
    Object.setPrototypeOf(this, WingnutCodegenError.prototype)
  }
}

export type CodegenDialect = '3.0' | '3.1'

/** Artifact identity written to `meta.json` by `wingnut build`. */
export interface CodegenMeta {
  /** `wingnut@<version>` that emitted the artifact. */
  generator: string
  /** AJV version that compiled the validators. */
  ajv: string
  /** ajv-formats version (format regex data may be vendored in). */
  ajvFormats: string
  /** Dialect the validators were compiled for. */
  dialect: CodegenDialect
  /** `codegenOptionsHash(dialect)`; rejects non-canonical option sets. */
  optionsHash: string
  /** Unique schemas in the artifact. */
  count: number
  /** `JSON.stringify(schema)` keys, in emit order. */
  keys: string[]
}

/**
 * The only compile options codegen mode supports (v0.6): the canonical
 * `createWingnutAjv()` defaults. Non-default options stay on the
 * runtime-AJV path.
 */
export const CODEGEN_CANONICAL_OPTIONS = {
  formats: true,
  coerceTypes: true,
  allErrors: true,
} as const

/** Deterministic hash over dialect + canonical options. */
export const codegenOptionsHash = (dialect: CodegenDialect): string =>
  createHash('sha256')
    .update(JSON.stringify({ dialect, ...CODEGEN_CANONICAL_OPTIONS }))
    .digest('hex')

/** Same key the runtime schema cache uses — build/runtime parity by construction. */
export const codegenSchemaKey = (schema: Record<string, unknown>): string =>
  JSON.stringify(schema)

/**
 * `AjvLike` backed by a generated artifact. A schema with no entry
 * (stale artifact, runtime-constructed schema) throws — never a
 * silent no-validation.
 */
export const codegenAjvLike = (
  validators: Record<string, AjvLikeValidateFunction>,
  meta?: CodegenMeta,
  expected?: { generator: string; ajv: string },
): AjvLike => {
  if (meta && expected) verifyCodegenMeta(meta, expected)
  if (meta) assertArtifactComplete(meta, validators)
  return {
    compile(schema: AjvLikeSchemaObject): AjvLikeValidateFunction {
      const key = codegenSchemaKey(schema)
      const v = validators[key]
      if (!v) {
        throw new WingnutCodegenError(
          `no precompiled validator for this schema — the codegen build ` +
            `artifact is stale (a schema changed after \`wingnut build\` ran, ` +
            `or this schema was constructed at runtime). Re-run the codegen ` +
            `build step. schema head: ${key.slice(0, 160)}`,
        )
      }
      return v
    },
  }
}

/** Reject an artifact built by a different wingnut, AJV major, or option set. */
export const verifyCodegenMeta = (
  meta: CodegenMeta,
  expected: { generator: string; ajv: string },
): void => {
  const problems: string[] = []
  if (meta.generator !== expected.generator) {
    problems.push(
      `generator mismatch (artifact=${meta.generator}, ` +
        `runtime=${expected.generator})`,
    )
  }
  const ajvMajor = (v: string) => v.split('.')[0]
  if (ajvMajor(meta.ajv) !== ajvMajor(expected.ajv)) {
    problems.push(
      `AJV major mismatch (artifact=${meta.ajv}, runtime=${expected.ajv})`,
    )
  }
  if (meta.optionsHash !== codegenOptionsHash(meta.dialect)) {
    problems.push(
      `options hash mismatch (artifact=${meta.optionsHash}, ` +
        `canonical=${codegenOptionsHash(meta.dialect)})`,
    )
  }
  if (problems.length > 0) {
    throw new WingnutCodegenError(
      `codegen artifact drift — ${problems.join('; ')}. ` +
        `Re-run the codegen build step with the current wingnut.`,
    )
  }
}

/** Reject artifacts whose recorded keys are missing from the module. */
const assertArtifactComplete = (
  meta: CodegenMeta,
  validators: Record<string, AjvLikeValidateFunction>,
): void => {
  const missing = meta.keys.filter((k) => validators[k] === undefined)
  if (missing.length > 0) {
    throw new WingnutCodegenError(
      `codegen artifact incomplete — ${missing.length}/${meta.count} ` +
        `recorded keys missing from the validators module (truncated or ` +
        `partially copied artifact). Re-run the codegen build step.`,
    )
  }
}
