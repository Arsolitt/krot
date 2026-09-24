package web

import "embed"

// static holds the vendored htmx and the portal stylesheet; served under
// /static/ with far-from-perfect but harmless cache headers.
//
//go:embed static
var static embed.FS
