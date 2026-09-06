// Fail-fast stand-in for `ajv/dist/2020` in the thin bundle. See ajv.ts.
export default class Ajv2020 {
  constructor(_opts?: unknown) {
    throw new Error(
      'wingnut/codegen: AJV 2020 is not available in codegen mode. This ' +
        'bundle was built without it on purpose — use codegenAjvLike(' +
        'validators) with a `wingnut build` artifact, or import from ' +
        '"wingnut" (the runtime-AJV entry) instead of "wingnut/codegen".',
    )
  }
}
