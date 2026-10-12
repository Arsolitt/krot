package sub

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Arsolitt/krot/internal/rebuild"
	"github.com/Arsolitt/krot/internal/upstream"
)

// fakeFetcher records the request it received and returns a canned result,
// standing in for the caching, SSRF-guarded upstream fetcher.
type fakeFetcher struct {
	req    upstream.Request
	err    error
	result upstream.Result
}

func (f *fakeFetcher) Fetch(_ context.Context, req upstream.Request) (upstream.Result, error) {
	f.req = req
	return f.result, f.err
}

// rebuildEnv seals spec into a capability token under the shared test key and
// returns a server whose profile carries the fixture title.
func rebuildEnv(t *testing.T, spec upstream.Spec) (*Server, string) {
	t.Helper()
	token, err := rebuild.Seal(tokenKey32, spec)
	if err != nil {
		t.Fatalf("seal token: %v", err)
	}
	server, _ := testEnv(nil)
	return server, token
}

// plainLinkList is the minimal upstream payload the rewriter classifies as a
// link list, so the tests bypass content sniffing and pin the handler.
const plainLinkList = "vless://11111111-1111-1111-1111-111111111111@edge.example.com:443\n"

func TestRebuildHandlerServesRewrittenLinkList(t *testing.T) {
	spec := upstream.Spec{UpstreamURL: "https://provider.example/sub/opaque"}
	profileJSON := []byte(`{"name":"krot"}`)
	f := &fakeFetcher{result: upstream.Result{
		Status: http.StatusOK,
		// A hostile upstream type: the handler must classify the served type
		// from the payload, not relay this value onto the control-plane origin.
		ContentType: "text/html; charset=utf-8",
		Body:        []byte(plainLinkList),
		ProfileHeaders: http.Header{
			"Subscription-Userinfo":   {"upload=1; download=2; total=3; expire=4"},
			"Profile-Title":           {"Provider Plan"},
			"Profile-Update-Interval": {"12"},
			"Support-Url":             {"https://support.example.com"},
		},
	}}
	server, token := rebuildEnv(t, spec)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/rbr/"+token, nil)
	req.Header.Set("User-Agent", "Happ/1.0")
	req.Header.Set("X-Hwid", "hwid-abc")
	server.RebuildHandler(tokenKey32, f, profileJSON, nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "vless://11111111-1111-1111-1111-111111111111@edge.example.com:443") {
		t.Errorf("body missing provider link:\n%s", body)
	}
	if !strings.HasPrefix(body, "happ://routing/onadd/") {
		t.Errorf("body must lead with the happ routing line:\n%s", body)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("content-type = %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("x-content-type-options = %q, want nosniff", got)
	}
	if got := rec.Header().Get("Subscription-Userinfo"); got != "upload=1; download=2; total=3; expire=4" {
		t.Errorf("subscription-userinfo = %q", got)
	}
	if got := rec.Header().Get("Profile-Title"); got != "Provider Plan" {
		t.Errorf("profile-title = %q", got)
	}
	if got := rec.Header().Get("Profile-Update-Interval"); got != "12" {
		t.Errorf("profile-update-interval = %q", got)
	}
	if got := rec.Header().Get("Support-Url"); got != "https://support.example.com" {
		t.Errorf("support-url = %q", got)
	}
	if got := rec.Header().Get("Routing"); !strings.HasPrefix(got, "happ://routing/onadd/") {
		t.Errorf("routing = %q", got)
	}

	if f.req.URL != spec.UpstreamURL {
		t.Errorf("fetched URL = %q, want sealed upstream URL", f.req.URL)
	}
	for name, want := range map[string]string{
		"User-Agent": "Happ/1.0",
		"X-Hwid":     "hwid-abc",
	} {
		if got := f.req.Header.Get(name); got != want {
			t.Errorf("relayed %s = %q, want %q", name, got, want)
		}
	}
}

// TestRebuildHandlerClassifiesContentType pins the XSS fix at the served
// response: the payload classification decides the content type even when the
// provider advertises text/html, and nosniff keeps a browser from re-sniffing
// the body on the control-plane origin.
func TestRebuildHandlerClassifiesContentType(t *testing.T) {
	const jsonConfig = `{"outbounds":[` +
		`{"tag":"proxy","protocol":"vless"},` +
		`{"tag":"direct","protocol":"freedom"},` +
		`{"tag":"block","protocol":"blackhole"}]}`
	cases := []struct {
		name string
		body string
		want string
	}{
		{"json config", jsonConfig, "application/json; charset=utf-8"},
		{"link list", plainLinkList, "text/plain; charset=utf-8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := upstream.Spec{UpstreamURL: "https://provider.example/sub/opaque"}
			f := &fakeFetcher{result: upstream.Result{
				Status:      http.StatusOK,
				ContentType: "text/html; charset=utf-8",
				Body:        []byte(tc.body),
			}}
			server, token := rebuildEnv(t, spec)
			rec := httptest.NewRecorder()

			server.RebuildHandler(tokenKey32, f, []byte(`{"name":"krot"}`), nil).
				ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/rbr/"+token, nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); got != tc.want {
				t.Errorf("content-type = %q, want the classified %q", got, tc.want)
			}
			if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("x-content-type-options = %q, want nosniff", got)
			}
		})
	}
}

// TestRebuildHandlerBoundsConcurrentRewrites pins the saturation guard: with
// every rewrite slot held, a further request is answered 503 (with Retry-After)
// instead of piling decode-and-marshal work onto the control plane, and the
// handler recovers once the slots free up.
func TestRebuildHandlerBoundsConcurrentRewrites(t *testing.T) {
	release := make(chan struct{})
	blocking := &blockingFetcher{release: release}
	server, token := rebuildEnv(t, upstream.Spec{UpstreamURL: "https://provider.example/sub/opaque"})
	handler := server.RebuildHandler(tokenKey32, blocking, []byte(`{"name":"krot"}`), nil)

	// Hold every slot with requests parked inside the rewrite.
	end := make(chan struct{})
	held := make(chan struct{}, rebuildMaxConcurrent)
	var wg sync.WaitGroup
	for range rebuildMaxConcurrent {
		wg.Go(func() {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/rbr/"+token, nil)
			req = req.WithContext(waitCtx{Context: req.Context(), done: end})
			held <- struct{}{}
			handler.ServeHTTP(rec, req)
		})
	}
	for range rebuildMaxConcurrent {
		<-held
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/rbr/"+token, nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("saturated status = %d, want 503; body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Error("saturated response carries no Retry-After header")
	}

	close(release)
	close(end)
	wg.Wait()

	server2, token2 := rebuildEnv(t, upstream.Spec{UpstreamURL: "https://provider.example/sub/opaque"})
	rec2 := httptest.NewRecorder()
	server2.RebuildHandler(tokenKey32, &fakeFetcher{result: upstream.Result{
		Status: http.StatusOK,
		Body:   []byte(plainLinkList),
	}}, []byte(`{"name":"krot"}`), nil).
		ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/rbr/"+token2, nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("post-saturation status = %d, want 200", rec2.Code)
	}
}

// blockingFetcher parks every fetch until release is closed, holding the
// rewrite slot it was admitted for.
type blockingFetcher struct {
	release <-chan struct{}
}

func (f *blockingFetcher) Fetch(ctx context.Context, _ upstream.Request) (upstream.Result, error) {
	select {
	case <-f.release:
	case <-ctx.Done():
	}
	return upstream.Result{Status: http.StatusOK, Body: []byte(plainLinkList)}, nil
}

// waitCtx renders a request context in cancelable form so a held request can
// be released deterministically.
type waitCtx struct {
	context.Context

	done <-chan struct{}
}

func (c waitCtx) Done() <-chan struct{} { return c.done }

// TestRebuildHandlerFallsBackToControlPlaneProfile pins that an upstream that
// sends no profile title or content type still yields a named, sniffable
// subscription: Happ reads the title from the response header.
func TestRebuildHandlerFallsBackToControlPlaneProfile(t *testing.T) {
	spec := upstream.Spec{UpstreamURL: "https://provider.example/sub/opaque"}
	f := &fakeFetcher{result: upstream.Result{
		Status: http.StatusOK,
		Body:   []byte(plainLinkList),
	}}
	server, token := rebuildEnv(t, spec)

	rec := httptest.NewRecorder()
	server.RebuildHandler(tokenKey32, f, []byte(`{"name":"krot"}`), nil).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/rbr/"+token, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Profile-Title"); got != "Krot VPN" {
		t.Errorf("profile-title = %q, want control-plane title", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("content-type = %q, want default", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("x-content-type-options = %q, want nosniff", got)
	}
}

func TestRebuildHandlerRejectsBadTokens(t *testing.T) {
	spec := upstream.Spec{UpstreamURL: "https://provider.example/sub/opaque"}
	foreignKey := []byte("ffffffffffffffffffffffffffffffff")
	foreign, err := rebuild.Seal(foreignKey, spec)
	if err != nil {
		t.Fatalf("seal foreign token: %v", err)
	}
	f := &fakeFetcher{result: upstream.Result{Status: http.StatusOK, Body: []byte(plainLinkList)}}
	server, _ := rebuildEnv(t, spec)
	h := server.RebuildHandler(tokenKey32, f, []byte(`{"name":"krot"}`), nil)

	cases := []struct {
		name string
		path string
	}{
		{"empty token", "/rbr/"},
		{"garbage token", "/rbr/rbr_not-a-sealed-token"},
		{"token sealed under another key", "/rbr/" + foreign},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))

			if rec.Code != http.StatusNotFound {
				t.Errorf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			if f.req.URL != "" {
				t.Errorf("upstream fetched for invalid token: %q", f.req.URL)
			}
		})
	}
}

// TestRebuildHandlerFetcherError pins the fail-closed response: a short
// message, no upstream URL and no query-string secret anywhere in it.
func TestRebuildHandlerFetcherError(t *testing.T) {
	spec := upstream.Spec{UpstreamURL: "https://provider.example/sub?token=QUERY-SECRET"}
	f := &fakeFetcher{err: errors.New("dial https://provider.example/sub?token=QUERY-SECRET: connection refused")}
	server, token := rebuildEnv(t, spec)

	rec := httptest.NewRecorder()
	server.RebuildHandler(tokenKey32, f, []byte(`{"name":"krot"}`), nil).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/rbr/"+token, nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if body != rebuildFailedMessage+"\n" {
		t.Errorf("body = %q, want the short constant message", body)
	}
	if strings.Contains(body, "provider.example") || strings.Contains(body, "QUERY-SECRET") {
		t.Errorf("body leaks the upstream URL: %q", body)
	}
}
