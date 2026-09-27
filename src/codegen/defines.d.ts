// Build-time constants injected by esbuild --define (scripts/build.mjs).
// `__WINGNUT_VERSION__` is the package version; `__WINGNUT_AJV_VERSION__`
// is the AJV version recorded in artifact meta.json. Ambient only.
declare const __WINGNUT_VERSION__: string
declare const __WINGNUT_AJV_VERSION__: string
