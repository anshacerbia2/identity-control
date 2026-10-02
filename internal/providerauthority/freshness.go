package providerauthority

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// DefaultBudget is the freshness budget this service declared at registration (ADR-ORG-002 §5.3).
const DefaultBudget = 60 * time.Second

// PollInterval is how often the frontier is read and progress reported.
const PollInterval = 15 * time.Second

// Observation is one reading of Organization Control's frontier for this consumer.
type Observation struct {
	// Owed is whether any delivery to this consumer was unpublished, and OldestOwedAge how long
	// the oldest had waited, at the instant of the reading.
	Owed          bool
	OldestOwedAge time.Duration

	// SecurityDebt is an unresolved authority-bearing dead letter of this consumer's.
	SecurityDebt bool
}

// Source is Organization Control as this consumer reads it.
type Source interface {
	Frontier(ctx context.Context) (Observation, error)
	ReportProgress(ctx context.Context, appliedMark int64) error
}

// Freshness holds the last frontier observation, so the provider decision reads it without a
// network call (TDD-identity-control-006 §Freshness).
type Freshness struct {
	budget time.Duration
	now    func() time.Time

	mu           sync.RWMutex
	bootstrapped bool
	observed     bool
	receivedAt   time.Time
	observation  Observation
}

// NewFreshness builds the holder with the declared budget.
func NewFreshness(budget time.Duration) (*Freshness, error) {
	if budget <= 0 {
		return nil, errors.New("providerauthority: the freshness budget must be positive")
	}
	return &Freshness{budget: budget, now: time.Now}, nil
}

// Stale reasons, for logs and for the decision's refusal.
const (
	StaleNotBootstrapped = "the projection has not been bootstrapped"
	StaleUnobserved      = "Organization Control's frontier has not been read"
	StaleDebt            = "Organization Control reports security debt for this consumer"
	StaleAge             = "the projection is older than its budget"
)

// Fresh reports whether the projection may authorize an activation at this instant, and why not.
//
// The age is measured on this process's clock from when the observation was received, plus the
// oldest owed delivery's age at that instant, so no instant is subtracted across two clocks. The
// receipt is no earlier than Organization's reading, so the error is the round trip, on the safe
// side.
func (f *Freshness) Fresh() (bool, string) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	switch {
	case !f.bootstrapped:
		return false, StaleNotBootstrapped
	case !f.observed:
		return false, StaleUnobserved
	case f.observation.SecurityDebt:
		return false, StaleDebt
	}
	age := f.now().Sub(f.receivedAt)
	if f.observation.Owed {
		age += f.observation.OldestOwedAge
	}
	if age > f.budget {
		return false, StaleAge
	}
	return true, ""
}

func (f *Freshness) record(bootstrapped bool, observation *Observation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bootstrapped = bootstrapped
	if observation != nil {
		f.observed, f.receivedAt, f.observation = true, f.now(), *observation
	}
}

// Poll reads the projection's status and Organization Control's frontier every interval, and
// reports progress once bootstrapped, until ctx is done. A failed read keeps the last observation,
// which then ages past the budget: an unreachable Organization makes the projection stale rather
// than leaving it fresh.
func (f *Freshness) Poll(ctx context.Context, projection *Projection, source Source, interval time.Duration, logger *slog.Logger) {
	wasFresh, lastReason := false, ""
	tick := func() {
		status, err := projection.Status(ctx)
		if err != nil {
			logger.Error("the provider projection's status could not be read", slog.String("error", err.Error()))
		}
		observation, err := source.Frontier(ctx)
		if err != nil {
			logger.Warn("Organization Control's frontier could not be read; the last reading ages",
				slog.String("error", err.Error()))
			f.record(status.Bootstrapped, nil)
		} else {
			f.record(status.Bootstrapped, &observation)
		}
		if status.Bootstrapped {
			if err := source.ReportProgress(ctx, status.AppliedMark); err != nil && ctx.Err() == nil {
				logger.Warn("progress could not be reported to Organization Control", slog.String("error", err.Error()))
			}
		}
		if fresh, reason := f.Fresh(); fresh != wasFresh || reason != lastReason {
			if fresh {
				logger.Info("the provider projection is fresh")
			} else {
				logger.Warn("the provider projection is stale; activations are not honored", slog.String("reason", reason))
			}
			wasFresh, lastReason = fresh, reason
		}
	}
	tick()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}
