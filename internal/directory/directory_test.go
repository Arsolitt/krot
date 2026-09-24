package directory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Arsolitt/krot/internal/model"
)

// stubSource is a Source whose verdict and error the test controls; calls
// counts every method invocation so caching is observable.
type stubSource struct {
	membersErr error
	allowedErr error
	members    []model.Member
	calls      int
	allowed    bool
}

func (s *stubSource) Members(context.Context) ([]model.Member, error) {
	s.calls++
	return s.members, s.membersErr
}

func (s *stubSource) Allowed(context.Context, string) (bool, error) {
	s.calls++
	return s.allowed, s.allowedErr
}

func TestMembersDelegatesToSource(t *testing.T) {
	want := []model.Member{{Subject: "uuid-a", Username: "alice"}}
	src := &stubSource{members: want}
	c := Wrap(src, time.Hour, time.Hour)

	got, err := c.Members(context.Background())
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("Members = %+v, want %+v", got, want)
	}
}

func TestMembersSurfacesSourceError(t *testing.T) {
	src := &stubSource{membersErr: errors.New("boom")}
	c := Wrap(src, time.Hour, time.Hour)

	if _, err := c.Members(context.Background()); err == nil {
		t.Fatal("Members: expected the source error")
	}
}

func TestAllowedServesFreshCacheWithoutSourceCall(t *testing.T) {
	src := &stubSource{allowed: true}
	c := Wrap(src, time.Hour, time.Hour)

	for range 2 {
		got, err := c.Allowed(context.Background(), "uuid-a")
		if err != nil || !got {
			t.Fatalf("Allowed = (%v, %v), want (true, nil)", got, err)
		}
	}
	if src.calls != 1 {
		t.Fatalf("source calls = %d, want 1 (fresh cache must not revalidate)", src.calls)
	}
}

func TestAllowedCachesDeniedVerdicts(t *testing.T) {
	src := &stubSource{allowed: false}
	c := Wrap(src, time.Hour, time.Hour)

	for range 2 {
		got, err := c.Allowed(context.Background(), "uuid-a")
		if err != nil || got {
			t.Fatalf("Allowed = (%v, %v), want (false, nil)", got, err)
		}
	}
	if src.calls != 1 {
		t.Fatalf("source calls = %d, want 1 (denied verdicts are cached too)", src.calls)
	}
}

func TestAllowedFailOpenInsideGrace(t *testing.T) {
	src := &stubSource{allowed: true}
	c := Wrap(src, 0, time.Hour)
	if _, err := c.Allowed(context.Background(), "uuid-a"); err != nil {
		t.Fatalf("prime Allowed: %v", err)
	}

	src.allowedErr = errors.New("provider unreachable")
	got, err := c.Allowed(context.Background(), "uuid-a")
	if err != nil || !got {
		t.Fatalf("Allowed = (%v, %v), want (true, nil) inside grace", got, err)
	}
}

func TestAllowedFailsClosedAfterGrace(t *testing.T) {
	src := &stubSource{allowed: true, allowedErr: errors.New("provider unreachable")}
	c := Wrap(src, 0, time.Hour)
	c.cache["uuid-a"] = verdict{ok: true, at: time.Now().Add(-2 * time.Hour)}

	got, err := c.Allowed(context.Background(), "uuid-a")
	if err == nil || got {
		t.Fatalf("Allowed = (%v, %v), want (false, error) after grace", got, err)
	}
}

func TestAllowedNeverCheckedSurfacesError(t *testing.T) {
	src := &stubSource{allowedErr: errors.New("provider unreachable")}
	c := Wrap(src, 0, time.Hour)

	got, err := c.Allowed(context.Background(), "uuid-a")
	if err == nil || got {
		t.Fatalf("Allowed = (%v, %v), want (false, error) when never checked", got, err)
	}
}
