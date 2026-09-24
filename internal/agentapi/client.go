// Package agentapi is the agent-side HTTP client for the krot control
// plane API: desired-state polling and heartbeats over the public ingress.
package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Arsolitt/krot/internal/model"
)

// defaultTimeout bounds one API round trip.
const defaultTimeout = 10 * time.Second

// maxBodyBytes caps response bodies; desired states are a few kilobytes.
const maxBodyBytes = 4 << 20

// maxErrorSnippet caps how much of an error body is embedded in errors.
const maxErrorSnippet = 200

// ConfigError marks a 400 response from the control plane: the agent's
// declared spec is invalid. The agent keeps its current config and reports
// the message as config_error.
type ConfigError struct {
	Message string
}

// Error implements error.
func (e *ConfigError) Error() string {
	return fmt.Sprintf("control plane rejected spec: %s", e.Message)
}

// Client talks to the control plane agent API.
type Client struct {
	hc    *http.Client
	cpURL string
	token string
}

// New builds a client for cpURL (e.g. http://krot-cp:8080). A nil hc
// gets a default 10s-timeout client.
func New(cpURL, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{cpURL: strings.TrimSuffix(cpURL, "/"), token: token, hc: hc}
}

// DesiredState posts the declared spec and returns the rendered desired
// state. A 400 response yields *ConfigError; other failures yield plain
// errors the caller treats as transient.
func (c *Client) DesiredState(ctx context.Context, spec model.Spec) (model.DesiredState, error) {
	var out model.DesiredState
	if err := c.post(ctx, "/api/v1/agents/desired-state", spec, &out); err != nil {
		return model.DesiredState{}, err
	}
	return out, nil
}

// Heartbeat reports agent status to the control plane.
func (c *Client) Heartbeat(ctx context.Context, hb model.Heartbeat) error {
	return c.post(ctx, "/api/v1/agents/heartbeat", hb, nil)
}

// post sends one authenticated JSON request and optionally decodes the
// response body into out.
func (c *Client) post(ctx context.Context, path string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cpURL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return fmt.Errorf("read response %s: %w", path, err)
	}

	if resp.StatusCode == http.StatusBadRequest {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != "" {
			return &ConfigError{Message: errResp.Error}
		}
		return &ConfigError{Message: snippet(respBody)}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: status %d: %s", path, resp.StatusCode, snippet(respBody))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode %s response: %w", path, err)
	}
	return nil
}

// snippet trims and bounds an error body for embedding in errors.
func snippet(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > maxErrorSnippet {
		return text[:maxErrorSnippet] + "... (truncated)"
	}
	return text
}
