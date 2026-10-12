package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// routingDeps wires only the public routing surface: the handlers must not
// need a session, an identity provider or the store.
func routingDeps() *Deps {
	return &Deps{
		RoutingURI:         "happ://routing/onadd/cHJvZmlsZQ==",
		RoutingProfileJSON: []byte(`{"Name":"Krot VPN"}`),
		ProfileTitle:       "Krot VPN",
	}
}

// TestRoutingProfileServesJSON pins the raw profile endpoint: the artifact
// bytes verbatim, unauthenticated.
func TestRoutingProfileServesJSON(t *testing.T) {
	deps := routingDeps()
	rec := httptest.NewRecorder()

	deps.RoutingProfile(rec, httptest.NewRequest(http.MethodGet, "/routing.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got, want := rec.Header().Get("Content-Type"), "application/json; charset=utf-8"; got != want {
		t.Errorf("content-type = %q, want %q", got, want)
	}
	if got := rec.Body.String(); got != string(deps.RoutingProfileJSON) {
		t.Errorf("body = %q, want the profile bytes %q", got, deps.RoutingProfileJSON)
	}
}

// TestRoutingImportRedirectsToDeeplink pins the shareable https URL: it hands
// the happ:// deeplink straight to the client.
func TestRoutingImportRedirectsToDeeplink(t *testing.T) {
	deps := routingDeps()
	rec := httptest.NewRecorder()

	deps.RoutingImport(rec, httptest.NewRequest(http.MethodGet, "/routing/import", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != deps.RoutingURI {
		t.Errorf("location = %q, want %q", got, deps.RoutingURI)
	}
}

// TestRoutingPageIsPublic pins that the landing page renders without a
// session and carries the deeplink and the raw JSON link.
func TestRoutingPageIsPublic(t *testing.T) {
	deps := routingDeps()
	rec := httptest.NewRecorder()

	deps.RoutingPage(rec, httptest.NewRequest(http.MethodGet, "/routing", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no session may be required)", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{deps.RoutingURI, "Happ routing profile", "/routing.json", deps.ProfileTitle} {
		if !strings.Contains(body, want) {
			t.Errorf("page body does not contain %q:\n%s", want, body)
		}
	}
}

// rebuildDeps wires the public re-builder surface with a stub builder.
func rebuildDeps(
	create func(ctx context.Context, r *http.Request, upstreamURL, proxyTag, adsMode, secret string) (string, error),
) *Deps {
	return &Deps{
		ProfileTitle:  "Krot VPN",
		BaseURL:       "https://krot.example",
		RebuildCreate: create,
	}
}

// rebuildForm builds a urlencoded POST request for /rebuild, optionally
// marked as an htmx request.
func rebuildForm(t *testing.T, form url.Values, htmx bool) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/rebuild", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if htmx {
		req.Header.Set("Hx-Request", "true")
	}
	return req
}

// TestRebuildPageRendersForm pins the public form: every field, the htmx
// wiring and the result placeholder.
func TestRebuildPageRendersForm(t *testing.T) {
	deps := rebuildDeps(nil)
	rec := httptest.NewRecorder()

	deps.RebuildPage(rec, httptest.NewRequest(http.MethodGet, "/rebuild", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (no session may be required)", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`hx-post="/rebuild"`,
		`hx-target="#rebuild-result"`,
		`hx-swap="innerHTML"`,
		`action="/rebuild"`,
		`name="upstream_url"`,
		`name="proxy_tag"`,
		`name="ads_mode"`,
		`id="rebuild-result"`,
		`value="light"`,
		`value="full"`,
		deps.ProfileTitle,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page body does not contain %q:\n%s", want, body)
		}
	}
}

// TestRebuildPageSecretFieldVisibility pins that the access-secret field is
// hidden unless the control plane requires a secret.
func TestRebuildPageSecretFieldVisibility(t *testing.T) {
	cases := []struct {
		name      string
		secretSet bool
	}{
		{name: "no secret configured", secretSet: false},
		{name: "secret configured", secretSet: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := rebuildDeps(nil)
			deps.RebuildSecretSet = tc.secretSet
			rec := httptest.NewRecorder()

			deps.RebuildPage(rec, httptest.NewRequest(http.MethodGet, "/rebuild", nil))

			body := rec.Body.String()
			hasField := strings.Contains(body, `name="secret"`)
			if hasField != tc.secretSet {
				t.Errorf("secret field rendered = %v, want %v:\n%s", hasField, tc.secretSet, body)
			}
			if tc.secretSet && !strings.Contains(body, `type="password"`) {
				t.Errorf("secret field is not a password input:\n%s", body)
			}
		})
	}
}

// TestRebuildCreateRejectsInvalidInput pins the server-side validation: bad
// input answers 400 with a short message and never calls the builder. htmx
// requests get the fragment, plain posts the full page.
func TestRebuildCreateRejectsInvalidInput(t *testing.T) {
	longURL := "https://upstream.invalid/" + strings.Repeat("a", maxRebuildURLLen-len("https://upstream.invalid/")+1)
	cases := []struct {
		name string
		form url.Values
		want string
	}{
		{name: "missing url", form: url.Values{}, want: "required"},
		{name: "not https", form: url.Values{"upstream_url": {"http://upstream.invalid/sub"}}, want: "https"},
		{name: "not a url", form: url.Values{"upstream_url": {"://garbage"}}, want: "not a valid URL"},
		{
			name: "userinfo",
			form: url.Values{"upstream_url": {"https://user:pass@upstream.invalid/sub"}},
			want: "credentials",
		},
		{name: "too long", form: url.Values{"upstream_url": {longURL}}, want: "too long"},
		{
			name: "unknown ads mode",
			form: url.Values{"upstream_url": {"https://upstream.invalid/sub"}, "ads_mode": {"medium"}},
			want: "ads mode",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, htmx := range []bool{true, false} {
				var calls int
				deps := rebuildDeps(func(_ context.Context, _ *http.Request, _, _, _, _ string) (string, error) {
					calls++
					return "", nil
				})
				rec := httptest.NewRecorder()

				deps.RebuildCreateHandler(rec, rebuildForm(t, tc.form, htmx))

				if rec.Code != http.StatusBadRequest {
					t.Fatalf("htmx=%v: status = %d, want 400", htmx, rec.Code)
				}
				if calls != 0 {
					t.Errorf("htmx=%v: builder called %d times for invalid input", htmx, calls)
				}
				body := rec.Body.String()
				if !strings.Contains(body, tc.want) {
					t.Errorf("htmx=%v: body does not contain %q:\n%s", htmx, tc.want, body)
				}
				hasDoctype := strings.Contains(strings.ToLower(body), "<!doctype")
				if hasDoctype == htmx {
					t.Errorf("htmx=%v: full page = %v, want %v", htmx, hasDoctype, !htmx)
				}
				if raw := tc.form.Get("upstream_url"); raw != "" && strings.Contains(body, raw) {
					t.Errorf("htmx=%v: error page echoes the submitted URL:\n%s", htmx, body)
				}
			}
		})
	}
}

// TestRebuildCreateSuccess pins the happy path: the builder receives the
// form values and the response carries the /rbr/ link with a copy button.
func TestRebuildCreateSuccess(t *testing.T) {
	plainURL := "https://provider.example/sub"
	maxURL := "https://provider.example/" + strings.Repeat("a", maxRebuildURLLen-len("https://provider.example/"))
	cases := []struct {
		form     url.Values
		wantArgs [4]string
		name     string
		htmx     bool
	}{
		{
			name: "all fields fragment",
			form: url.Values{
				"upstream_url": {"https://provider.example/sub?s=1"},
				"proxy_tag":    {"proxy-out"},
				"ads_mode":     {"full"},
				"secret":       {"s3cret"},
			},
			htmx:     true,
			wantArgs: [4]string{"https://provider.example/sub?s=1", "proxy-out", "full", "s3cret"},
		},
		{
			name:     "full page with defaults",
			form:     url.Values{"upstream_url": {plainURL}},
			wantArgs: [4]string{plainURL, "", "", ""},
		},
		{
			name:     "maximum length url accepted",
			form:     url.Values{"upstream_url": {maxURL}},
			wantArgs: [4]string{maxURL, "", "", ""},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotArgs [4]string
			deps := rebuildDeps(
				func(_ context.Context, _ *http.Request, upstreamURL, proxyTag, adsMode, secret string) (string, error) {
					gotArgs = [4]string{upstreamURL, proxyTag, adsMode, secret}
					return "rbr_TESTTOKEN", nil
				},
			)
			rec := httptest.NewRecorder()

			deps.RebuildCreateHandler(rec, rebuildForm(t, tc.form, tc.htmx))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200:\n%s", rec.Code, rec.Body.String())
			}
			if gotArgs != tc.wantArgs {
				t.Errorf("builder args = %q, want %q", gotArgs, tc.wantArgs)
			}
			wantLink := deps.BaseURL + "/rbr/rbr_TESTTOKEN"
			body := rec.Body.String()
			if !strings.Contains(body, wantLink) {
				t.Errorf("body does not contain the link %q:\n%s", wantLink, body)
			}
			if !strings.Contains(body, `data-url="`+wantLink+`"`) {
				t.Errorf("body does not carry the link on the copy button:\n%s", body)
			}
			hasDoctype := strings.Contains(strings.ToLower(body), "<!doctype")
			if hasDoctype == tc.htmx {
				t.Errorf("full page = %v, want %v", hasDoctype, !tc.htmx)
			}
			if got, want := rec.Header().Get("Content-Type"), "text/html; charset=utf-8"; got != want {
				t.Errorf("content-type = %q, want %q", got, want)
			}
		})
	}
}

// TestRebuildCreateBuilderError pins the builder-failure path: 400 with the
// builder's message, and masking of any error text that would echo the
// submitted URL or secret.
func TestRebuildCreateBuilderError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
		gone string
	}{
		{
			name: "short builder error is shown",
			err:  errors.New("invalid access secret"),
			want: "invalid access secret",
			gone: "",
		},
		{
			name: "url in builder error is masked",
			err:  errors.New("fetch https://provider.example/sub?s=1: connection refused"),
			want: "could not build the subscription link",
			gone: "provider.example",
		},
		{
			name: "secret in builder error is masked",
			err:  errors.New(`access secret "s3cret" is invalid`),
			want: "could not build the subscription link",
			gone: "s3cret",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := rebuildDeps(func(_ context.Context, _ *http.Request, _, _, _, _ string) (string, error) {
				return "", tc.err
			})
			form := url.Values{"upstream_url": {"https://provider.example/sub?s=1"}, "secret": {"s3cret"}}
			rec := httptest.NewRecorder()

			deps.RebuildCreateHandler(rec, rebuildForm(t, form, true))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, tc.want) {
				t.Errorf("body does not contain %q:\n%s", tc.want, body)
			}
			if tc.gone != "" && strings.Contains(body, tc.gone) {
				t.Errorf("body echoes %q:\n%s", tc.gone, body)
			}
		})
	}
}

// TestRebuildCreateNotConfigured pins that an unwired builder answers 503
// instead of panicking.
func TestRebuildCreateNotConfigured(t *testing.T) {
	deps := rebuildDeps(nil)
	form := url.Values{"upstream_url": {"https://provider.example/sub"}}
	rec := httptest.NewRecorder()

	deps.RebuildCreateHandler(rec, rebuildForm(t, form, true))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "not configured") {
		t.Errorf("body does not contain the unavailable message:\n%s", body)
	}
}

// rebuildTestClock is a manually advanced clock for the throttle tests.
type rebuildTestClock struct {
	at time.Time
}

// now reports the current fake time.
func (c *rebuildTestClock) now() time.Time { return c.at }

// advance moves the fake time forward.
func (c *rebuildTestClock) advance(d time.Duration) { c.at = c.at.Add(d) }

// TestRebuildCreateThrottlesFailedAttempts pins the per-IP failure limiter: a
// burst of failed attempts exhausts the budget, further attempts are answered
// 429 before the builder is consulted — even when a forwarding header names
// another address — and one refill window restores the budget.
func TestRebuildCreateThrottlesFailedAttempts(t *testing.T) {
	clock := &rebuildTestClock{at: time.Unix(1_700_000_000, 0)}
	var calls int
	deps := rebuildDeps(func(_ context.Context, _ *http.Request, _, _, _, _ string) (string, error) {
		calls++
		return "", errors.New("invalid access secret")
	})
	deps.rebuildLimit = newRebuildLimiter(clock.now)

	form := url.Values{"upstream_url": {"https://provider.example/sub"}, "secret": {"guess"}}
	for attempt := 1; attempt <= rebuildLimitBurst; attempt++ {
		rec := httptest.NewRecorder()
		deps.RebuildCreateHandler(rec, rebuildForm(t, form, true))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: status = %d, want 400", attempt, rec.Code)
		}
	}
	if calls != rebuildLimitBurst {
		t.Fatalf("builder calls = %d, want %d", calls, rebuildLimitBurst)
	}

	// The exhausted client is throttled before the builder; a forwarding
	// header it sets cannot rotate its identity.
	throttled := rebuildForm(t, form, true)
	throttled.Header.Set("X-Forwarded-For", "198.51.100.9")
	rec := httptest.NewRecorder()
	deps.RebuildCreateHandler(rec, throttled)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled status = %d, want 429", rec.Code)
	}
	if calls != rebuildLimitBurst {
		t.Errorf("builder called %d times for a throttled attempt, want %d", calls, rebuildLimitBurst)
	}
	if !strings.Contains(rec.Body.String(), rebuildThrottledMsg) {
		t.Errorf("throttled body does not carry the message:\n%s", rec.Body.String())
	}

	// A different client address keeps its own budget.
	other := rebuildForm(t, form, true)
	other.RemoteAddr = "203.0.113.7:4567"
	rec = httptest.NewRecorder()
	deps.RebuildCreateHandler(rec, other)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("other client status = %d, want 400 on its own budget", rec.Code)
	}

	// One refill window restores the exhausted client's budget.
	clock.advance(rebuildLimitWindow)
	recovered := httptest.NewRecorder()
	deps.RebuildCreateHandler(recovered, rebuildForm(t, form, true))
	if recovered.Code != http.StatusBadRequest {
		t.Fatalf("after refill status = %d, want 400 (budget recovered)", recovered.Code)
	}
	if want := rebuildLimitBurst + 2; calls != want {
		t.Errorf("builder calls = %d, want %d", calls, want)
	}
}

// TestRebuildCreateSuccessResetsBudget pins that completed rebuilds clear the
// failure budget: only a client that never succeeds is throttled, however
// many failures it accumulates across successes.
func TestRebuildCreateSuccessResetsBudget(t *testing.T) {
	clock := &rebuildTestClock{at: time.Unix(1_700_000_000, 0)}
	var calls int
	deps := rebuildDeps(func(_ context.Context, _ *http.Request, _, _, _, secret string) (string, error) {
		calls++
		if secret != "sesame" {
			return "", errors.New("invalid access secret")
		}
		return "rbr_TESTTOKEN", nil
	})
	deps.rebuildLimit = newRebuildLimiter(clock.now)

	failForm := url.Values{"upstream_url": {"https://provider.example/sub"}, "secret": {"guess"}}
	goodForm := url.Values{"upstream_url": {"https://provider.example/sub"}, "secret": {"sesame"}}
	failures := rebuildLimitBurst / 2
	for round := 1; round <= 3; round++ {
		for range failures {
			rec := httptest.NewRecorder()
			deps.RebuildCreateHandler(rec, rebuildForm(t, failForm, true))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("round %d: failed attempt status = %d, want 400", round, rec.Code)
			}
		}
		rec := httptest.NewRecorder()
		deps.RebuildCreateHandler(rec, rebuildForm(t, goodForm, true))
		if rec.Code != http.StatusOK {
			t.Fatalf("round %d: success status = %d, want 200; body %s", round, rec.Code, rec.Body.String())
		}
	}
	if want := 3*failures + 3; calls != want {
		t.Errorf("builder calls = %d, want %d", calls, want)
	}
}
