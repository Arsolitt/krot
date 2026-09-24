package zitadel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// capturedRequest is what a stub endpoint recorded about one call.
type capturedRequest struct {
	method  string
	path    string
	headers http.Header
	body    listRequest
}

// stubAPI serves the ListAuthorizations endpoint with the given page handler
// and records the request it saw.
func stubAPI(
	t *testing.T,
	handler func(w http.ResponseWriter, req listRequest, page int),
) (*httptest.Server, *[]capturedRequest) {
	t.Helper()
	var seen []capturedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body listRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request body: %v", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		page := 0
		if body.Pagination != nil {
			page = body.Pagination.Offset
		}
		seen = append(seen, capturedRequest{method: r.Method, path: r.URL.Path, headers: r.Header.Clone(), body: body})
		handler(w, body, page)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// writeAuthPage encodes one authorizations listing page.
func writeAuthPage(t *testing.T, w http.ResponseWriter, total int, rows ...apiAuthorization) {
	t.Helper()
	resp := listResponse{
		Authorizations: rows,
	}
	resp.Pagination.TotalResult = total
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		t.Fatalf("encode stub page: %v", err)
	}
}

// authRow builds one authorization row.
func authRow(subject, displayName, state string, roleKeys ...string) apiAuthorization {
	row := apiAuthorization{
		User:  apiUser{ID: subject, DisplayName: displayName},
		State: state,
	}
	for _, key := range roleKeys {
		row.Roles = append(row.Roles, apiRole{Key: key})
	}
	return row
}

func TestMembersRequestShape(t *testing.T) {
	srv, seen := stubAPI(t, func(w http.ResponseWriter, _ listRequest, _ int) {
		writeAuthPage(t, w, 0)
	})

	client := NewClient(srv.URL+"/", "pat-token", "proj-42", "vpn", srv.Client())
	if _, err := client.Members(t.Context()); err != nil {
		t.Fatalf("Members: %v", err)
	}

	if len(*seen) != 1 {
		t.Fatalf("requests = %d, want 1", len(*seen))
	}
	req := (*seen)[0]
	if req.method != http.MethodPost {
		t.Errorf("method = %s, want POST", req.method)
	}
	if want := "/zitadel.authorization.v2.AuthorizationService/ListAuthorizations"; req.path != want {
		t.Errorf("path = %s, want %s", req.path, want)
	}
	if got := req.headers.Get("Authorization"); got != "Bearer pat-token" {
		t.Errorf("authorization = %q, want %q", got, "Bearer pat-token")
	}
	if got := req.headers.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type = %q, want application/json", got)
	}
	if got := req.headers.Get("Connect-Protocol-Version"); got != "1" {
		t.Errorf("connect-protocol-version = %q, want 1", got)
	}
	if req.body.Pagination == nil || req.body.Pagination.Offset != 0 || req.body.Pagination.Limit != pageLimit ||
		!req.body.Pagination.Asc {
		t.Errorf("pagination = %+v, want offset 0, limit %d, asc", req.body.Pagination, pageLimit)
	}
	checkFilters(t, req.body.Filters, false, "")
}

func TestAllowedRequestShape(t *testing.T) {
	srv, seen := stubAPI(t, func(w http.ResponseWriter, _ listRequest, _ int) {
		writeAuthPage(t, w, 0)
	})

	client := NewClient(srv.URL, "pat-token", "proj-42", "vpn", srv.Client())
	if _, err := client.Allowed(t.Context(), "user-7"); err != nil {
		t.Fatalf("Allowed: %v", err)
	}

	if len(*seen) != 1 {
		t.Fatalf("requests = %d, want 1", len(*seen))
	}
	checkFilters(t, (*seen)[0].body.Filters, true, "user-7")
}

// checkFilters asserts the ANDed filter list: project id, role key and active
// state always; the subject filter only for a per-user check.
func checkFilters(t *testing.T, filters []searchFilter, wantSubject bool, subject string) {
	t.Helper()
	var (
		projectIDs []string
		roleKeys   []string
		states     []string
		subjects   []string
	)
	for _, f := range filters {
		if f.ProjectID != nil {
			projectIDs = append(projectIDs, f.ProjectID.ID)
		}
		if f.RoleKey != nil {
			roleKeys = append(roleKeys, f.RoleKey.Key)
		}
		if f.State != nil {
			states = append(states, f.State.State)
		}
		if f.InUserIDs != nil {
			subjects = append(subjects, f.InUserIDs.IDs...)
		}
	}
	if !reflect.DeepEqual(projectIDs, []string{"proj-42"}) {
		t.Errorf("projectId filters = %v, want [proj-42]", projectIDs)
	}
	if !reflect.DeepEqual(roleKeys, []string{"vpn"}) {
		t.Errorf("roleKey filters = %v, want [vpn]", roleKeys)
	}
	if !reflect.DeepEqual(states, []string{"STATE_ACTIVE"}) {
		t.Errorf("state filters = %v, want [STATE_ACTIVE]", states)
	}
	if wantSubject {
		if !reflect.DeepEqual(subjects, []string{subject}) {
			t.Errorf("inUserIds filters = %v, want [%s]", subjects, subject)
		}
		return
	}
	if len(subjects) != 0 {
		t.Errorf("inUserIds filters = %v, want none for a listing", subjects)
	}
}

func TestMembersPaginatesUntilTotalResult(t *testing.T) {
	srv, seen := stubAPI(t, func(w http.ResponseWriter, _ listRequest, page int) {
		switch page {
		case 0:
			writeAuthPage(t, w, 3, authRow("uuid-c", "carol", stateActive, "vpn"))
		case 1:
			writeAuthPage(t, w, 3, authRow("uuid-a", "alice", stateActive, "vpn"))
		case 2:
			writeAuthPage(t, w, 3, authRow("uuid-b", "bob", stateActive, "vpn"))
		default:
			t.Errorf("unexpected page offset %d", page)
			writeAuthPage(t, w, 3)
		}
	})

	client := NewClient(srv.URL, "tok", "proj", "vpn", srv.Client())
	members, err := client.Members(t.Context())
	if err != nil {
		t.Fatalf("Members: %v", err)
	}

	if len(*seen) != 3 {
		t.Fatalf("requests = %d, want 3", len(*seen))
	}
	for i, want := range []int{0, 1, 2} {
		if got := (*seen)[i].body.Pagination.Offset; got != want {
			t.Errorf("request %d offset = %d, want %d", i, got, want)
		}
	}
	var usernames []string
	for _, m := range members {
		usernames = append(usernames, m.Username)
	}
	if want := []string{"alice", "bob", "carol"}; !reflect.DeepEqual(usernames, want) {
		t.Fatalf("usernames = %v, want %v (sorted)", usernames, want)
	}
}

func TestMembersDeduplicatesAndSorts(t *testing.T) {
	srv, _ := stubAPI(t, func(w http.ResponseWriter, _ listRequest, _ int) {
		writeAuthPage(t, w, 4,
			authRow("uuid-b", "bravo", stateActive, "vpn"),
			// A project grant from another org yields a second row for the
			// same subject.
			authRow("uuid-b", "bravo", stateActive, "vpn"),
			authRow("uuid-a", "alpha", stateActive, "vpn"),
			authRow("uuid-a", "alpha", stateActive, "vpn"),
		)
	})

	client := NewClient(srv.URL, "tok", "proj", "vpn", srv.Client())
	members, err := client.Members(t.Context())
	if err != nil {
		t.Fatalf("Members: %v", err)
	}

	want := []struct{ subject, username string }{
		{"uuid-a", "alpha"},
		{"uuid-b", "bravo"},
	}
	if len(members) != len(want) {
		t.Fatalf("members = %+v, want %+v", members, want)
	}
	for i, w := range want {
		if members[i].Subject != w.subject || members[i].Username != w.username {
			t.Fatalf("members[%d] = %+v, want %+v", i, members[i], w)
		}
	}
}

func TestMembersExcludesInactiveAuthorizations(t *testing.T) {
	srv, _ := stubAPI(t, func(w http.ResponseWriter, _ listRequest, _ int) {
		writeAuthPage(t, w, 2,
			authRow("uuid-a", "alpha", stateActive, "vpn"),
			authRow("uuid-b", "bravo", "STATE_INACTIVE", "vpn"),
		)
	})

	client := NewClient(srv.URL, "tok", "proj", "vpn", srv.Client())
	members, err := client.Members(t.Context())
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(members) != 1 || members[0].Subject != "uuid-a" {
		t.Fatalf("members = %+v, want only the active authorization", members)
	}
}

func TestMembersFallsBackToLoginNameThenID(t *testing.T) {
	srv, _ := stubAPI(t, func(w http.ResponseWriter, _ listRequest, _ int) {
		rows := []apiAuthorization{
			{User: apiUser{ID: "uuid-a", PreferredLoginName: "alpha@example.com"}, State: stateActive},
			{User: apiUser{ID: "uuid-b"}, State: stateActive},
		}
		writeAuthPage(t, w, 2, rows...)
	})

	client := NewClient(srv.URL, "tok", "proj", "vpn", srv.Client())
	members, err := client.Members(t.Context())
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	got := map[string]string{}
	for _, m := range members {
		got[m.Subject] = m.Username
	}
	if got["uuid-a"] != "alpha@example.com" || got["uuid-b"] != "uuid-b" {
		t.Fatalf("usernames = %v, want login name then id fallback", got)
	}
}

func TestAllowedVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows []apiAuthorization
		want bool
	}{
		{
			name: "active authorization with the role",
			rows: []apiAuthorization{authRow("uuid-a", "alice", stateActive, "other", "vpn")},
			want: true,
		},
		{
			name: "authorization without the role",
			rows: []apiAuthorization{authRow("uuid-a", "alice", stateActive, "other")},
			want: false,
		},
		{
			name: "inactive authorization",
			rows: []apiAuthorization{authRow("uuid-a", "alice", "STATE_INACTIVE", "vpn")},
			want: false,
		},
		{
			name: "no authorization",
			rows: nil,
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := stubAPI(t, func(w http.ResponseWriter, _ listRequest, _ int) {
				writeAuthPage(t, w, len(tc.rows), tc.rows...)
			})

			client := NewClient(srv.URL, "tok", "proj", "vpn", srv.Client())
			got, err := client.Allowed(t.Context(), "uuid-a")
			if err != nil {
				t.Fatalf("Allowed: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Allowed = %v, want %v", got, tc.want)
			}
		})
	}
}

// apiCall is one client operation under test.
type apiCall struct {
	run  func(*Client) error
	name string
}

func TestSurfacesAPIError(t *testing.T) {
	for _, call := range []apiCall{
		{name: "Members", run: func(c *Client) error { _, err := c.Members(t.Context()); return err }},
		{name: "Allowed", run: func(c *Client) error { _, err := c.Allowed(t.Context(), "uuid-a"); return err }},
	} {
		t.Run(call.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"code":16,"message":"token invalid"}`))
			}))
			defer srv.Close()

			client := NewClient(srv.URL, "tok", "proj", "vpn", srv.Client())
			err := call.run(client)
			if err == nil {
				t.Fatal("expected an error on API 500")
			}
			if want := "token invalid"; !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %q, want it to carry %q", err, want)
			}
		})
	}
}
