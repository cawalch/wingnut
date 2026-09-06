// Fail-fast stand-in for `ajv` in the thin bundle. esbuild aliases `ajv`
// here so codegen deploys never ship or load real AJV; constructing a live
// instance is a loud error, not a silent fallback.
export default class Ajv {
  constructor(_opts?: unknown) {
    throw new Error(
      'wingnut/codegen: AJV is not available in codegen mode. This bundle ' +
        'was built without it on purpose — use codegenAjvLike(validators) ' +
        'with a `wingnut build` artifact, or import from "wingnut" (the ' +
        'runtime-AJV entry) instead of "wingnut/codegen".',
    )
  }
}
