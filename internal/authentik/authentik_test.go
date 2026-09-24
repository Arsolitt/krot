package authentik

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// stubUser builds an apiUser with the given direct groups.
func stubUser(username, userUUID string, active bool, groups ...string) apiUser {
	u := apiUser{
		Username: username,
		UUID:     userUUID,
		IsActive: active,
	}
	for _, g := range groups {
		u.GroupsObj = append(u.GroupsObj, groupRef{Name: g})
	}
	return u
}

// writePage encodes one core/users listing page.
func writePage(t *testing.T, w http.ResponseWriter, next int, results []apiUser) {
	t.Helper()
	resp := struct {
		Results    []apiUser `json:"results"`
		Pagination struct {
			Next int `json:"next"`
		} `json:"pagination"`
	}{}
	resp.Pagination.Next = next
	resp.Results = results
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		t.Fatalf("encode stub page: %v", err)
	}
}

func TestMembersPaginatesAndSorts(t *testing.T) {
	var sawAuth string
	var sawQuery []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawQuery = r.URL.Query()["page"]
		switch {
		case len(sawQuery) == 0:
			writePage(t, w, 2, []apiUser{stubUser("zeta", "uuid-z", true)})
		case sawQuery[0] == "2":
			writePage(t, w, 0, []apiUser{stubUser("alpha", "uuid-a", true)})
		default:
			t.Errorf("unexpected page request: %q", sawQuery[0])
		}
	}))
	defer srv.Close()

	client := NewClient(srv.URL+"/", "tok", "krot::vpn", srv.Client())

	members, err := client.Members(t.Context())
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	want := []struct{ username, subject string }{
		{"alpha", "uuid-a"},
		{"zeta", "uuid-z"},
	}
	if len(members) != len(want) {
		t.Fatalf("members = %+v, want %+v", members, want)
	}
	for i, w := range want {
		if members[i].Username != w.username || members[i].Subject != w.subject {
			t.Fatalf("members[%d] = %+v, want %+v", i, members[i], w)
		}
	}
	if auth := "Bearer tok"; sawAuth != auth {
		t.Fatalf("authorization header = %q, want %q", sawAuth, auth)
	}
}

func TestMembersChecksQueryFilters(t *testing.T) {
	var groups, active, includeGroups string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		groups = q.Get("groups_by_name")
		active = q.Get("is_active")
		includeGroups = q.Get("include_groups")
		writePage(t, w, 0, nil)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "tok", "krot::vpn", srv.Client())
	if _, err := client.Members(t.Context()); err != nil {
		t.Fatalf("Members: %v", err)
	}
	if groups != "krot::vpn" || active != "true" || includeGroups != "false" {
		t.Fatalf("query filters: groups=%q is_active=%q include_groups=%q", groups, active, includeGroups)
	}
}

func TestMembersExcludesInactiveUsers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		users []apiUser
		want  []string
	}{
		{
			name:  "active member kept",
			users: []apiUser{stubUser("alpha", "uuid-a", true, "krot::vpn")},
			want:  []string{"alpha"},
		},
		{
			name:  "inactive member dropped",
			users: []apiUser{stubUser("bravo", "uuid-b", false, "krot::vpn")},
			want:  nil,
		},
		{
			// A listing that ignores the is_active filter must not leak a
			// deactivated account into the member set.
			name: "mixed listing keeps active members only",
			users: []apiUser{
				stubUser("alpha", "uuid-a", true, "krot::vpn"),
				stubUser("bravo", "uuid-b", false, "krot::vpn"),
				stubUser("charlie", "uuid-c", true, "krot::vpn"),
			},
			want: []string{"alpha", "charlie"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writePage(t, w, 0, tc.users)
			}))
			defer srv.Close()

			client := NewClient(srv.URL, "tok", "krot::vpn", srv.Client())
			members, err := client.Members(t.Context())
			if err != nil {
				t.Fatalf("Members: %v", err)
			}
			got := make([]string, 0, len(members))
			for _, m := range members {
				got = append(got, m.Username)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("members = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMembersAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, "tok", "krot::vpn", srv.Client())
	if _, err := client.Members(t.Context()); err == nil {
		t.Fatal("Members: expected error on API 500")
	}
}

func TestAllowedVerdicts(t *testing.T) {
	users := map[string]apiUser{
		"uuid-ok":       stubUser("alice", "uuid-ok", true, "other", "krot::vpn"),
		"uuid-inactive": stubUser("bob", "uuid-inactive", false, "krot::vpn"),
		"uuid-nogroup":  stubUser("carol", "uuid-nogroup", true, "other"),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := users[r.URL.Query().Get("uuid")]
		if !ok {
			writePage(t, w, 0, nil)
			return
		}
		writePage(t, w, 0, []apiUser{u})
	}))
	defer srv.Close()

	for _, tc := range []struct {
		subject string
		want    bool
	}{
		{"uuid-ok", true},
		{"uuid-inactive", false},
		{"uuid-nogroup", false},
		{"uuid-unknown", false},
	} {
		client := NewClient(srv.URL, "tok", "krot::vpn", srv.Client())
		got, err := client.Allowed(t.Context(), tc.subject)
		if err != nil {
			t.Fatalf("Allowed(%s): %v", tc.subject, err)
		}
		if got != tc.want {
			t.Errorf("Allowed(%s) = %v, want %v", tc.subject, got, tc.want)
		}
	}
}
