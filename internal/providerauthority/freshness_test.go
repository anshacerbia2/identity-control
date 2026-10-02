package providerauthority

// Freshness (TDD-identity-control-006 §Freshness): fresh within the budget, stale past it, stale
// while security debt is reported, stale before a bootstrap, and stale when the frontier cannot be
// read.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// clock is a settable now.
type clock struct{ at time.Time }

func (c *clock) now() time.Time { return c.at }

func freshness(t *testing.T) (*Freshness, *clock) {
	t.Helper()
	f, err := NewFreshness(DefaultBudget)
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{at: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	f.now = c.now
	return f, c
}

func TestABudgetMustBePositive(t *testing.T) {
	for _, budget := range []time.Duration{0, -time.Second} {
		if _, err := NewFreshness(budget); err == nil {
			t.Errorf("a budget of %s was accepted", budget)
		}
	}
}

func TestFreshness(t *testing.T) {
	for _, tc := range []struct {
		what         string
		bootstrapped bool
		observation  *Observation
		elapsed      time.Duration
		fresh        bool
		reason       string
	}{
		{"before a bootstrap", false, &Observation{}, 0, false, StaleNotBootstrapped},
		{"before any reading", true, nil, 0, false, StaleUnobserved},
		{"nothing owed, just read", true, &Observation{}, 0, true, ""},
		{"nothing owed, at the budget", true, &Observation{}, DefaultBudget, true, ""},
		{"nothing owed, past the budget", true, &Observation{}, DefaultBudget + time.Second, false, StaleAge},
		{"owed, within the budget", true, &Observation{Owed: true, OldestOwedAge: 40 * time.Second}, 20 * time.Second, true, ""},
		{"owed, past the budget", true, &Observation{Owed: true, OldestOwedAge: 40 * time.Second}, 21 * time.Second, false, StaleAge},
		{"an age with nothing owed is ignored", true, &Observation{OldestOwedAge: time.Hour}, 0, true, ""},
		{"security debt", true, &Observation{SecurityDebt: true}, 0, false, StaleDebt},
	} {
		t.Run(tc.what, func(t *testing.T) {
			f, c := freshness(t)
			f.record(tc.bootstrapped, tc.observation)
			c.at = c.at.Add(tc.elapsed)
			fresh, reason := f.Fresh()
			if fresh != tc.fresh || reason != tc.reason {
				t.Errorf("Fresh() = %v, %q; want %v, %q", fresh, reason, tc.fresh, tc.reason)
			}
		})
	}
}

// A failed reading keeps the last one, which then ages: an unreachable Organization makes the
// projection stale rather than leaving it fresh.
func TestAFailedReadingLetsTheLastOneAge(t *testing.T) {
	f, c := freshness(t)
	f.record(true, &Observation{})
	c.at = c.at.Add(30 * time.Second)
	f.record(true, nil)
	if fresh, _ := f.Fresh(); !fresh {
		t.Fatal("a failed reading within the budget made the projection stale at once")
	}
	c.at = c.at.Add(31 * time.Second)
	f.record(true, nil)
	if fresh, reason := f.Fresh(); fresh || reason != StaleAge {
		t.Errorf("Fresh() = %v, %q after failed readings past the budget; want stale by age", fresh, reason)
	}
}

// source is Organization Control as a test scripts it.
type source struct {
	mu          sync.Mutex
	observation Observation
	err         error
	reports     []int64
	read        chan struct{}
}

func (s *source) Frontier(context.Context) (Observation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		select {
		case s.read <- struct{}{}:
		default:
		}
	}()
	return s.observation, s.err
}

func (s *source) ReportProgress(_ context.Context, mark int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = append(s.reports, mark)
	return nil
}

func (s *source) reported() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.reports...)
}

// Poll reads the projection's status and the frontier, and reports progress once bootstrapped.
func TestPollReportsProgressOnceBootstrapped(t *testing.T) {
	p := pool(t)
	keepProjectionRow(t, p)
	clearProjectionRow(t, p)
	projection, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	poll := func(s *source) *Freshness {
		t.Helper()
		f, err := NewFreshness(DefaultBudget)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { f.Poll(ctx, projection, s, time.Hour, logger); close(done) }()
		select {
		case <-s.read:
		case <-time.After(10 * time.Second):
			t.Fatal("Poll did not read the frontier")
		}
		cancel()
		<-done
		return f
	}

	unbootstrapped := &source{read: make(chan struct{}, 1)}
	if fresh, reason := poll(unbootstrapped).Fresh(); fresh || reason != StaleNotBootstrapped {
		t.Errorf("before a bootstrap Fresh() = %v, %q", fresh, reason)
	}
	if got := unbootstrapped.reported(); len(got) != 0 {
		t.Errorf("progress %v was reported before a bootstrap", got)
	}

	if err := projection.ReplaceFromSnapshot(context.Background(), 12, nil); err != nil {
		t.Fatal(err)
	}
	bootstrapped := &source{read: make(chan struct{}, 1)}
	if fresh, reason := poll(bootstrapped).Fresh(); !fresh {
		t.Errorf("after a bootstrap Fresh() = %v, %q", fresh, reason)
	}
	if got := bootstrapped.reported(); len(got) != 1 || got[0] != 12 {
		t.Errorf("progress reported %v; want [12]", got)
	}

	unreachable := &source{read: make(chan struct{}, 1), err: errors.New("connection refused")}
	if fresh, reason := poll(unreachable).Fresh(); fresh || reason != StaleUnobserved {
		t.Errorf("with the frontier unreadable Fresh() = %v, %q", fresh, reason)
	}
}
