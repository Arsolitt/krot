package web

// Navigation rendering: the shared layout carries a conditional nav bar, so
// every page shows the entries that apply to the visitor — the admin entry
// only for members, sign-in or sign-out following the session.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

// renderPage renders a component through the standard render helpers, so the
// test observes exactly what a handler would write.
func renderPage(t *testing.T, deps *Deps, r *http.Request, c templ.Component) string {
	t.Helper()
	rec := httptest.NewRecorder()
	deps.render(rec, r, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("render status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// TestNavAnonymousPage links to the portal and the re-builder and offers
// sign-in, never the admin entry.
func TestNavAnonymousPage(t *testing.T) {
	deps := routingDeps()
	req := httptest.NewRequest(http.MethodGet, "/routing", nil)
	body := renderPage(t, deps, req, routing(RoutingData{
		Nav:      deps.nav(req),
		Title:    deps.ProfileTitle,
		Deeplink: deps.RoutingURI,
	}))

	for _, want := range []string{`href="/"`, `href="/rebuild"`, `href="/login"`} {
		if !strings.Contains(body, want) {
			t.Errorf("anonymous page lacks %s:\n%s", want, body)
		}
	}
	for _, unwanted := range []string{`href="/admin"`, `href="/logout"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("anonymous page must not carry %s:\n%s", unwanted, body)
		}
	}
}

// TestNavAdminPage pins the member view: the admin entry appears alongside
// sign-out, and sign-in disappears.
func TestNavAdminPage(t *testing.T) {
	deps := routingDeps()
	req := httptest.NewRequest(http.MethodGet, "/rebuild", nil)
	body := renderPage(t, deps, req, rebuildPage(RebuildData{
		Nav:       Nav{SignedIn: true, Admin: true, SignOut: true},
		Title:     deps.ProfileTitle,
		SecretSet: true,
	}))

	for _, want := range []string{`href="/"`, `href="/admin"`, `href="/rebuild"`, `href="/logout"`} {
		if !strings.Contains(body, want) {
			t.Errorf("admin page lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, `href="/login"`) {
		t.Errorf("signed-in page must not offer sign-in:\n%s", body)
	}
}

// TestNavSignedInNonMember keeps the admin entry out for a plain session.
func TestNavSignedInNonMember(t *testing.T) {
	deps := routingDeps()
	req := httptest.NewRequest(http.MethodGet, "/rebuild", nil)
	body := renderPage(t, deps, req, rebuildPage(RebuildData{
		Nav:   Nav{SignedIn: true, SignOut: true},
		Title: deps.ProfileTitle,
	}))

	if !strings.Contains(body, `href="/logout"`) {
		t.Errorf("signed-in page lacks sign-out:\n%s", body)
	}
	if strings.Contains(body, `href="/admin"`) {
		t.Errorf("non-member page must not carry the admin entry:\n%s", body)
	}
}

// TestNavHelperWithoutProvider covers the guard the handlers rely on: with no
// identity provider wired yet, nav reports an anonymous visitor rather than
// panicking, so the public pages keep rendering during OIDC discovery.
func TestNavHelperWithoutProvider(t *testing.T) {
	deps := routingDeps()
	req := httptest.NewRequest(http.MethodGet, "/routing", nil)

	nav := deps.nav(req)
	if nav.SignedIn || nav.Admin {
		t.Fatalf("nav without a provider = %+v, want anonymous", nav)
	}
	if !nav.SignIn {
		t.Fatalf("nav without a provider = %+v, want the sign-in entry", nav)
	}
}
