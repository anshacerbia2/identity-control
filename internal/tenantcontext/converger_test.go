package tenantcontext

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/keycloak/keycloakfake"
)

type unavailable struct{ calls int }

func (u *unavailable) InTx(context.Context, func(context.Context, db.Tx) error) error {
	u.calls++
	return errors.New("the database is unavailable")
}

func TestTheConvergerIsConfiguredOrRefused(t *testing.T) {
	good := ConvergerConfig{Realm: "r", Interval: time.Millisecond, AttemptTimeout: time.Second, Lease: time.Minute,
		MaxAttempts: 1}
	kernel := &keycloakfake.Client{}
	for name, cfg := range map[string]ConvergerConfig{
		"no realm":    {Interval: time.Second, AttemptTimeout: time.Second, Lease: time.Minute, MaxAttempts: 1},
		"no interval": {Realm: "r", AttemptTimeout: time.Second, Lease: time.Minute, MaxAttempts: 1},
		"no attempts": {Realm: "r", Interval: time.Second, AttemptTimeout: time.Second, Lease: time.Minute},
	} {
		if _, err := NewConverger(&unavailable{}, kernel, cfg, nil, nil); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := NewConverger(nil, kernel, good, nil, nil); err == nil {
		t.Error("no transactor was accepted")
	}
	if _, err := NewDesired(nil); err == nil {
		t.Error("an intake with no transactor was accepted")
	}
	desired, err := NewDesired(&unavailable{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewReconciler(desired, &unavailable{}, kernel, "", nil, nil); err == nil {
		t.Error("a sweep with no realm was accepted")
	}
	if _, err := NewReconciler(nil, &unavailable{}, kernel, "r", nil, nil); err == nil {
		t.Error("a sweep with no desired state was accepted")
	}

	// Run keeps trying while the database is unavailable, and stops when its context ends.
	tx := &unavailable{}
	c, err := NewConverger(tx, kernel, good, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	c.Run(ctx)
	if tx.calls < 2 {
		t.Errorf("Run tried %d times in 20ms at a 1ms interval", tx.calls)
	}
}

func TestAFailureIsClassedNotQuoted(t *testing.T) {
	for err, want := range map[error]string{
		fmt.Errorf("x: %w", keycloak.ErrForbidden): "forbidden",
		fmt.Errorf("x: %w", keycloak.ErrAmbiguous): "ambiguous",
		fmt.Errorf("x: %w", errReadBack):           "read_back",
		context.DeadlineExceeded:                   "timeout",
		keycloak.ErrUnavailable:                    "unavailable",
	} {
		if got := errorClass(err); got != want {
			t.Errorf("%v: %s, want %s", err, got, want)
		}
	}
	if fullJitter(0) != 0 || fullJitter(time.Second) >= time.Second {
		t.Error("full jitter is outside [0, limit)")
	}
}
