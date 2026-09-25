package web

import "embed"

// static holds the portal's vendored front-end assets: htmx 2.0.10 at
// static/htmx.min.js, distributed under the Zero-Clause BSD license, whose
// text ships beside it at static/htmx.LICENSE, and the portal stylesheet at
// static/app.css. Every file here is served verbatim under /static/ with
// far-from-perfect but harmless cache headers.
//
//go:embed static
var static embed.FS
