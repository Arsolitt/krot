// Package directory is the identity-directory contract of the control plane:
// one Source per identity provider, plus the shared verdict cache and
// fail-open grace window every consumer sees.
package directory

import (
	"context"
	"sync"
	"time"

	"github.com/Arsolitt/krot/internal/model"
)

// Source is the raw provider API: listing the members of the configured group
// or role and checking one subject's membership.
type Source interface {
	// Members lists every subject currently holding the configured
	// group/role, sorted by display name.
	Members(ctx context.Context) ([]model.Member, error)
	// Allowed reports whether subject still holds the configured group/role.
	Allowed(ctx context.Context, subject string) (bool, error)
}

// verdict is the cached result of one successful access check.
type verdict struct {
	at time.Time
	ok bool
}

// Cached adds the verdict cache and the fail-open grace window to a Source:
// a fresh verdict is served from cache, a stale one is revalidated, and while
// the provider API is unreachable a previously allowed subject stays allowed
// until grace has passed since its last successful check. Every other failure
// surfaces the error.
type Cached struct {
	src   Source
	cache map[string]verdict
	ttl   time.Duration
	grace time.Duration
	mu    sync.Mutex
}

// Wrap returns src behind the shared verdict cache. Verdicts are cached for
// ttl; while the provider API is unreachable, a subject last seen allowed
// stays allowed until grace has passed since that successful check.
func Wrap(src Source, ttl, grace time.Duration) *Cached {
	return &Cached{
		src:   src,
		ttl:   ttl,
		grace: grace,
		cache: make(map[string]verdict),
	}
}

// Members lists every subject currently holding the configured group/role.
// The sync loop calls it once per interval, so this is a straight delegation:
// caching the full listing would only delay revocation.
func (c *Cached) Members(ctx context.Context) ([]model.Member, error) {
	return c.src.Members(ctx)
}

// Allowed reports whether subject still holds the configured group/role. A
// fresh verdict is served from cache; a stale one is revalidated. When
// revalidation fails, the last successful allowance still counts inside the
// grace window (deliberate fail-open so a provider outage does not cut off
// subscribers); every other case surfaces the error.
func (c *Cached) Allowed(ctx context.Context, subject string) (bool, error) {
	c.mu.Lock()
	cached, hit := c.cache[subject]
	if hit && time.Since(cached.at) < c.ttl {
		c.mu.Unlock()
		return cached.ok, nil
	}
	c.mu.Unlock()

	ok, err := c.src.Allowed(ctx, subject)
	if err == nil {
		c.mu.Lock()
		c.cache[subject] = verdict{ok: ok, at: time.Now()}
		c.mu.Unlock()
		return ok, nil
	}

	c.mu.Lock()
	cached, hit = c.cache[subject]
	c.mu.Unlock()
	if hit && cached.ok && time.Since(cached.at) < c.grace {
		return true, nil
	}
	return false, err
}
