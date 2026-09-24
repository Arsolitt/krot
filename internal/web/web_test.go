package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
