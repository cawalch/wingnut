// Fail-fast stand-in for `ajv-formats` in the thin bundle. `src/lib/ajv.ts`
// calls the default export; it throws on first use. See ajv.ts.
export default function addFormats(_ajv: unknown): void {
  throw new Error(
    'wingnut/codegen: ajv-formats is not available in codegen mode. ' +
      'Formats are precompiled into the `wingnut build` artifact at build ' +
      'time; no format plugin is needed at runtime.',
  )
}
