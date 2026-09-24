// Package authentik is a minimal authentik API v3 client covering the two
// calls the control plane needs: listing the members of one group and
// checking whether a single subject is still an active member of that group.
//
// The package is deliberately stdlib-only, mirroring internal/sub: it ships in
// the krot-cp image and must not drag the sing-box dependency tree into that
// build. Caching and the fail-open grace window live in internal/directory,
// shared with every other provider.
package authentik

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Arsolitt/krot/internal/model"
)

const (
	// defaultTimeout bounds a single authentik API request.
	defaultTimeout = 10 * time.Second
	// maxPages bounds the pagination loop against a server that keeps
	// reporting another page.
	maxPages = 1000
)

// groupRef is one entry of the groups_obj array of an authentik user.
type groupRef struct {
	Name string `json:"name"`
}

// apiUser is the subset of the authentik core/users object used here.
type apiUser struct {
	Username  string     `json:"username"`
	UUID      string     `json:"uuid"`
	GroupsObj []groupRef `json:"groups_obj"`
	IsActive  bool       `json:"is_active"`
}

// userList is one page of the core/users listing.
type userList struct {
	Results    []apiUser `json:"results"`
	Pagination struct {
		Next int `json:"next"`
	} `json:"pagination"`
}

// Client talks to the authentik API v3 for a single group. It is safe for
// concurrent use.
type Client struct {
	hc       *http.Client
	baseURL  string
	apiToken string
	group    string
}

// NewClient builds a Client for group. A nil hc installs an HTTP client with
// a 10s per-request timeout.
func NewClient(baseURL, apiToken, group string, hc *http.Client) *Client {
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiToken: apiToken,
		group:    group,
		hc:       withDefaultClient(hc),
	}
}

// withDefaultClient installs the default timeout when no client was given.
func withDefaultClient(hc *http.Client) *http.Client {
	if hc == nil {
		return &http.Client{Timeout: defaultTimeout}
	}
	return hc
}

// Members returns all active members of the group, sorted by username. The
// listing follows pagination.next until the API reports no further page. The
// is_active filter is requested server-side and re-checked on every returned
// user, so a deactivated account can never enter the member list (and with it
// the mirrored user set of the control plane).
func (c *Client) Members(ctx context.Context) ([]model.Member, error) {
	var members []model.Member
	next := 0
	for pages := 0; ; pages++ {
		if pages >= maxPages {
			return nil, fmt.Errorf("authentik: users listing exceeded %d pages", maxPages)
		}
		query := url.Values{}
		query.Set("groups_by_name", c.group)
		query.Set("is_active", "true")
		query.Set("include_groups", "false")
		if next > 0 {
			query.Set("page", strconv.Itoa(next))
		}

		var list userList
		if err := c.getJSON(ctx, "/api/v3/core/users/", query, &list); err != nil {
			return nil, err
		}
		for _, u := range list.Results {
			// Defence in depth: the query already asks for active users
			// only, but an API that ignores the parameter (or a proxy that
			// drops it) must not resurrect a deactivated account.
			if !u.IsActive {
				continue
			}
			members = append(members, model.Member{Username: u.Username, Subject: u.UUID})
		}
		if list.Pagination.Next == 0 {
			break
		}
		next = list.Pagination.Next
	}

	slices.SortFunc(members, func(a, b model.Member) int {
		return strings.Compare(a.Username, b.Username)
	})
	return members, nil
}

// Allowed reports whether the subject is an active member of the group. The
// lookup is uncached; internal/directory wraps every Source with the verdict
// cache and the fail-open grace window.
func (c *Client) Allowed(ctx context.Context, subject string) (bool, error) {
	query := url.Values{}
	query.Set("uuid", subject)

	var list userList
	if err := c.getJSON(ctx, "/api/v3/core/users/", query, &list); err != nil {
		return false, err
	}
	if len(list.Results) != 1 {
		return false, nil
	}
	u := list.Results[0]
	if !u.IsActive {
		return false, nil
	}
	for _, g := range u.GroupsObj {
		if g.Name == c.group {
			return true, nil
		}
	}
	return false, nil
}

// getJSON performs a bearer-authenticated GET against the authentik API and
// decodes the JSON body into out. Non-200 responses are errors.
func (c *Client) getJSON(ctx context.Context, path string, query url.Values, out any) error {
	reqURL := c.baseURL + path
	if encoded := query.Encode(); encoded != "" {
		reqURL += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("authentik: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiToken)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("authentik: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentik: %s: unexpected status %s", path, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("authentik: %s: decode response: %w", path, err)
	}
	return nil
}
