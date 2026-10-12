// Rebuild endpoint: the sealed-capability flavour of /sub. A provider
// subscription is fetched through the SSRF-guarded upstream fetcher and
// rewritten with the control plane's routing profile, so Happ clients that
// cannot apply their own routing profile to a 1:1 JSON passthrough still get
// krot's rules. Client identification headers travel upstream untouched
// (within the fetcher's allowlist), keeping the provider's device counting
// intact.

package sub

import (
	"log/slog"
	"net/http"

	"github.com/Arsolitt/krot/internal/rebuild"
	"github.com/Arsolitt/krot/internal/upstream"
)

const (
	// rebuildNotFoundMessage answers both a tampered and an unknown token, as
	// for /sub: a bad capability is indistinguishable from a missing one.
	rebuildNotFoundMessage = "not found"
	// rebuildFailedMessage answers upstream and rewrite failures with a short,
	// URL-free message. Details stay in the log, which never records the
	// provider URL either (its query string is a credential).
	rebuildFailedMessage = "subscription rebuild failed"
	// rebuildDefaultContentType is the fallback content type when the rewrite
	// result names none: the rewriter classifies every rebuilt body it
	// produces, so this only covers a Result assembled by other means.
	rebuildDefaultContentType = "text/plain; charset=utf-8"
	// rebuildMaxConcurrent bounds concurrent rewrites. The fetcher bounds its
	// own network work, but a cache hit still costs a decode and re-encode of
	// a body of up to the fetcher's per-response cap on every request, so
	// without this bound parallel /rbr requests sharing a token could exhaust
	// the control plane's memory and CPU. Exceeding the bound answers 503
	// rather than queueing, keeping the single-threaded worst case bounded.
	rebuildMaxConcurrent = 8
	// rebuildBusyMessage answers a request that arrived while the bound was
	// saturated; clients retry, the subscription endpoint stays independent.
	rebuildBusyMessage = "subscription rebuild is busy; try again"
)

// RebuildHandler returns the routed HTTP handler:
//
//	GET /rbr/{token} — the subscription sealed into token, fetched upstream
//	                   and rewritten with the krot routing profile
//
// The token is a sealed spec (rebuild.Seal) and doubles as the capability:
// it is the only credential the endpoint accepts, so /rbr deliberately has no
// auth. key is the dedicated rebuild key (KROT_REBUILD_KEY), held separately
// from the subscription token key; profileJSON is the routing profile baked
// into every rebuilt body. Concurrent rewrites are bounded by
// rebuildMaxConcurrent: a request that finds every slot taken is answered 503
// instead of queueing, so a burst of parallel requests cannot pile up
// decode-and-marshal work against the container's memory limit.
func (s *Server) RebuildHandler(
	key []byte,
	f upstream.Fetcher,
	profileJSON []byte,
	logger *slog.Logger,
) http.Handler {
	if logger == nil {
		logger = s.logger
	}
	slots := make(chan struct{}, rebuildMaxConcurrent)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /rbr/{token}", func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, rebuildBusyMessage, http.StatusServiceUnavailable)
			return
		}
		s.handleRebuild(w, r, key, f, profileJSON, logger)
	})
	return mux
}

// handleRebuild resolves one sealed token and streams the rewritten
// subscription with the upstream's Happ management headers.
func (s *Server) handleRebuild(
	w http.ResponseWriter,
	r *http.Request,
	key []byte,
	f upstream.Fetcher,
	profileJSON []byte,
	logger *slog.Logger,
) {
	token := r.PathValue("token")

	spec, err := rebuild.Open(key, token)
	if err != nil {
		logger.InfoContext(r.Context(), "rebuild token rejected")
		http.Error(w, rebuildNotFoundMessage, http.StatusNotFound)
		return
	}

	res, err := rebuild.Rewrite(r.Context(), f, key, rebuild.SessionID(key, token),
		upstream.Request{URL: spec.UpstreamURL, Header: r.Header},
		profileJSON, spec.ProxyTag, spec.AdsMode, spec.RouteMode, logger)
	if err != nil {
		logger.ErrorContext(r.Context(), "subscription rebuild failed", "error", err)
		http.Error(w, rebuildFailedMessage, http.StatusBadGateway)
		return
	}

	h := w.Header()
	// Relay every Happ management header the fetcher surfaced; the routing
	// header the rewriter sets for link-list payloads travels the same way.
	for name, values := range res.ProfileHeaders {
		for _, value := range values {
			h.Add(name, value)
		}
	}
	// A provider that advertises no title gets the control plane's own, so
	// Happ always shows a subscription name.
	if h.Get("profile-title") == "" {
		h.Set("profile-title", s.profile.Title)
	}
	// The rewrite classifies the content type from the payload (JSON or link
	// list); the provider's own type is never relayed, and the fallback only
	// covers a result built outside the rewriter. nosniff pins the type so a
	// browser cannot sniff the body into something else on the
	// control-plane origin, which also serves /admin.
	contentType := res.ContentType
	if contentType == "" {
		contentType = rebuildDefaultContentType
	}
	h.Set("Content-Type", contentType)
	h.Set("X-Content-Type-Options", "nosniff")

	logger.InfoContext(r.Context(), "rebuild served", "bytes", len(res.Body))

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(res.Body)
}
