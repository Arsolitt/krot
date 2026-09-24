// Package zitadel is a minimal Zitadel API v2 client covering the two calls
// the control plane needs: listing the users holding one project role and
// checking whether a single user still holds it.
//
// It speaks Connect-JSON, the HTTP/JSON encoding of the Zitadel v2 services:
// a POST to /<service>/<Method>, a JSON body, and the Connect-Protocol-Version
// header. The package is deliberately stdlib-only, mirroring
// internal/authentik: it ships in the krot-cp image and must not drag the
// sing-box dependency tree into that build.
package zitadel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Arsolitt/krot/internal/model"
)

const (
	// listAuthorizationsPath is the Connect path of the v2 authorization
	// service listing RPC.
	listAuthorizationsPath = "/zitadel.authorization.v2.AuthorizationService/ListAuthorizations"
	// connectProtocolVersion is the protocol header the v2 services expect.
	connectProtocolVersion = "1"
	// pageLimit is the page size of the listing requests.
	pageLimit = 100
	// defaultTimeout bounds a single Zitadel API request.
	defaultTimeout = 10 * time.Second
	// maxPages bounds the pagination loop against a server that keeps
	// reporting another page.
	maxPages = 1000
	// stateActive is the STATE_ACTIVE enum name of an authorization in force.
	stateActive = "STATE_ACTIVE"
	// errorBodyLimit bounds how much of an API failure body is read for the
	// message suffix.
	errorBodyLimit = 4096
)

// Client talks to the Zitadel v2 authorization service for one project role.
// It is safe for concurrent use.
type Client struct {
	hc        *http.Client
	baseURL   string
	apiToken  string
	projectID string
	role      string
}

// NewClient builds a Client for one project role. A nil hc installs an HTTP
// client with a 10s per-request timeout.
func NewClient(baseURL, apiToken, projectID, role string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{
		baseURL:   strings.TrimRight(baseURL, "/"),
		apiToken:  apiToken,
		projectID: projectID,
		role:      role,
		hc:        hc,
	}
}

// paginationRequest is the pagination fragment of a listing request.
type paginationRequest struct {
	Offset int  `json:"offset"`
	Limit  int  `json:"limit"`
	Asc    bool `json:"asc"`
}

// idFilter matches one resource id (IDFilter.id).
type idFilter struct {
	ID string `json:"id"`
}

// inIDsFilter matches any of the given ids (InIDsFilter.ids).
type inIDsFilter struct {
	IDs []string `json:"ids"`
}

// roleKeyFilter matches one role key (RoleKeyQuery.key).
type roleKeyFilter struct {
	Key string `json:"key"`
}

// stateFilter matches one authorization state by enum name.
type stateFilter struct {
	State string `json:"state"`
}

// searchFilter is one entry of the ANDed filters list: exactly one field is
// set per entry.
type searchFilter struct {
	ProjectID *idFilter      `json:"projectId,omitempty"`
	RoleKey   *roleKeyFilter `json:"roleKey,omitempty"`
	State     *stateFilter   `json:"state,omitempty"`
	InUserIDs *inIDsFilter   `json:"inUserIds,omitempty"`
}

// listRequest is the ListAuthorizations request body.
type listRequest struct {
	Pagination *paginationRequest `json:"pagination,omitempty"`
	Filters    []searchFilter     `json:"filters"`
}

// apiRole is one role of an authorization.
type apiRole struct {
	Key string `json:"key"`
}

// apiUser is the user fragment of an authorization.
type apiUser struct {
	ID                 string `json:"id"`
	DisplayName        string `json:"displayName"`
	PreferredLoginName string `json:"preferredLoginName"`
}

// apiAuthorization is one authorization row.
type apiAuthorization struct {
	User  apiUser   `json:"user"`
	State string    `json:"state"`
	Roles []apiRole `json:"roles"`
}

// listResponse is the ListAuthorizations response body.
type listResponse struct {
	Authorizations []apiAuthorization `json:"authorizations"`
	Pagination     struct {
		TotalResult int `json:"totalResult"`
	} `json:"pagination"`
}

// Members lists every user holding the project role, sorted by display name.
// A project grant from another organization yields a second authorization row
// for the same user, so the result is deduplicated by subject.
func (c *Client) Members(ctx context.Context) ([]model.Member, error) {
	seen := make(map[string]struct{})
	members := make([]model.Member, 0)
	for offset, pages := 0, 0; ; pages++ {
		if pages >= maxPages {
			return nil, fmt.Errorf("zitadel: authorizations listing exceeded %d pages", maxPages)
		}
		body := listRequest{
			Pagination: &paginationRequest{Offset: offset, Limit: pageLimit, Asc: true},
			Filters: []searchFilter{
				{ProjectID: &idFilter{ID: c.projectID}},
				{RoleKey: &roleKeyFilter{Key: c.role}},
				{State: &stateFilter{State: stateActive}},
			},
		}
		var resp listResponse
		if err := c.postJSON(ctx, listAuthorizationsPath, body, &resp); err != nil {
			return nil, err
		}
		for _, a := range resp.Authorizations {
			// Defence in depth: the request already filters on the active
			// state, but an API that ignores the filter must not resurrect
			// a revoked role.
			if a.State != stateActive {
				continue
			}
			if _, dup := seen[a.User.ID]; dup {
				continue
			}
			seen[a.User.ID] = struct{}{}
			members = append(members, model.Member{Subject: a.User.ID, Username: displayName(a)})
		}
		if len(resp.Authorizations) == 0 || offset+len(resp.Authorizations) >= resp.Pagination.TotalResult {
			break
		}
		offset += len(resp.Authorizations)
	}

	slices.SortFunc(members, func(a, b model.Member) int {
		if byName := strings.Compare(a.Username, b.Username); byName != 0 {
			return byName
		}
		return strings.Compare(a.Subject, b.Subject)
	})
	return members, nil
}

// Allowed reports whether the subject holds the project role with an active
// authorization.
func (c *Client) Allowed(ctx context.Context, subject string) (bool, error) {
	body := listRequest{
		Pagination: &paginationRequest{Offset: 0, Limit: pageLimit, Asc: true},
		Filters: []searchFilter{
			{ProjectID: &idFilter{ID: c.projectID}},
			{RoleKey: &roleKeyFilter{Key: c.role}},
			{State: &stateFilter{State: stateActive}},
			{InUserIDs: &inIDsFilter{IDs: []string{subject}}},
		},
	}
	var resp listResponse
	if err := c.postJSON(ctx, listAuthorizationsPath, body, &resp); err != nil {
		return false, err
	}
	for _, a := range resp.Authorizations {
		if a.State != stateActive {
			continue
		}
		for _, r := range a.Roles {
			if r.Key == c.role {
				return true, nil
			}
		}
	}
	return false, nil
}

// displayName picks the human-readable name of an authorization's user.
func displayName(a apiAuthorization) string {
	if a.User.DisplayName != "" {
		return a.User.DisplayName
	}
	if a.User.PreferredLoginName != "" {
		return a.User.PreferredLoginName
	}
	return a.User.ID
}

// postJSON performs a bearer-authenticated Connect-JSON POST against the
// Zitadel API and decodes the JSON body into out. Non-200 responses are
// errors, carrying the API's own message when it sends one.
func (c *Client) postJSON(ctx context.Context, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("zitadel: %s: encode request: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("zitadel: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Connect-Protocol-Version", connectProtocolVersion)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("zitadel: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("zitadel: %s: unexpected status %s%s", path, resp.Status, apiError(resp.Body))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("zitadel: %s: decode response: %w", path, err)
	}
	return nil
}

// apiError renders the {"code","message"} failure body as a suffix so the
// caller sees why the API rejected the request.
func apiError(r io.Reader) string {
	raw, err := io.ReadAll(io.LimitReader(r, errorBodyLimit))
	if err != nil || len(raw) == 0 {
		return ""
	}
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.Message == "" {
		return ""
	}
	return ": " + body.Message
}
