package tenantcontext

// The converger (TDD-identity-control-002 2.0.0 §Converging a Tenant): it claims one marked Tenant at
// a time, reads its desired state, and makes the kernel's Organization and its members match. The
// order is disable, remove, add, enable, then a read-back, so a failure part way leaves the kernel
// holding no more than the authority grants.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// ConvergerConfig bounds the converger.
type ConvergerConfig struct {
	Realm          keycloak.Realm
	Interval       time.Duration // how often an idle converger looks for a marked Tenant
	AttemptTimeout time.Duration // upper bound on one Admin API call
	Lease          time.Duration // how long a claim holds a Tenant
	MaxAttempts    int           // attempts before a Tenant is unresolved
}

// Converger makes the kernel match the desired state.
type Converger struct {
	tx     Transactor
	kernel keycloak.TenantOrganizations
	cfg    ConvergerConfig
	logger *slog.Logger
	metric convergerInstruments
}

type convergerInstruments struct {
	attempts  metric.Int64Counter
	duration  metric.Float64Histogram
	converged metric.Int64Counter
	delay     metric.Float64Histogram
	shared    shared
}

// NewConverger builds the converger. A nil meter records nothing.
func NewConverger(tx Transactor, kernel keycloak.TenantOrganizations, cfg ConvergerConfig, logger *slog.Logger,
	meter metric.Meter) (*Converger, error) {
	switch {
	case tx == nil || kernel == nil:
		return nil, errors.New("tenantcontext: a transactor and a kernel are required")
	case cfg.Realm == "":
		return nil, errors.New("tenantcontext: a realm is required")
	case cfg.Interval <= 0 || cfg.AttemptTimeout <= 0 || cfg.Lease <= 0 || cfg.MaxAttempts < 1:
		return nil, errors.New("tenantcontext: the interval, attempt timeout, lease and attempts must be positive")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if meter == nil {
		meter = noop.NewMeterProvider().Meter("")
	}
	c := &Converger{tx: tx, kernel: kernel, cfg: cfg, logger: logger}
	var err error
	if c.metric.attempts, err = meter.Int64Counter("identity.tenant_projection.attempts",
		metric.WithDescription("Convergence attempts, by outcome: converged, retry, unresolved")); err != nil {
		return nil, err
	}
	if c.metric.duration, err = meter.Float64Histogram("identity.tenant_projection.duration", metric.WithUnit("s"),
		metric.WithDescription("One convergence's kernel calls")); err != nil {
		return nil, err
	}
	if c.metric.converged, err = meter.Int64Counter("identity.tenant_projection.converged",
		metric.WithDescription("Convergences recorded converged, not left pending by a later mark, by priority")); err != nil {
		return nil, err
	}
	if c.metric.delay, err = meter.Float64Histogram("identity.tenant_projection.delivery_to_converged", metric.WithUnit("s"),
		metric.WithDescription("From the earliest delivery a convergence closes to its record, by priority: "+
			"above 2 s a warning, above 4 s critical")); err != nil {
		return nil, err
	}
	if c.metric.shared, err = newShared(meter); err != nil {
		return nil, err
	}
	if _, err = meter.Int64ObservableGauge("identity.tenant_projection.unresolved",
		metric.WithDescription("Tenants parked as unresolved, by priority; a priority one is critical"),
		metric.WithInt64Callback(func(ctx context.Context, o metric.Int64Observer) error {
			var priority, standard int64
			err := tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE priority), count(*) FILTER (WHERE NOT priority)
				    FROM identity.tenant_convergence WHERE state = 'unresolved'`).Scan(&priority, &standard)
			})
			if err == nil {
				o.Observe(priority, metric.WithAttributes(attribute.Bool("priority", true)))
				o.Observe(standard, metric.WithAttributes(attribute.Bool("priority", false)))
			}
			return err
		})); err != nil {
		return nil, err
	}
	return c, nil
}

// claimStatement takes the most urgent due Tenant no other converger holds, and leases it.
const claimStatement = `UPDATE identity.tenant_convergence
SET lease_until = now() + $1 * interval '1 millisecond', attempts = attempts + 1
WHERE tenant_id = (
    SELECT tenant_id FROM identity.tenant_convergence
    WHERE state = 'pending' AND next_attempt_at <= now() AND (lease_until IS NULL OR lease_until < now())
    ORDER BY priority DESC, next_attempt_at
    LIMIT 1
    FOR UPDATE SKIP LOCKED)
RETURNING tenant_id::text, marked_at, attempts, coalesce(kernel_org_id, ''), priority, sweep`

// tenantStatement reads the Tenant's status in one row that always exists: empty when there is no
// Tenant row. No-rows would otherwise have to be recognised as a driver error, and arch.json keeps the
// driver out of this module.
const tenantStatement = `SELECT coalesce(max(tenant_status), '') FROM identity.tenant_desired WHERE tenant_id = $1`

// membersStatement is the kernel users of the Tenant's active Memberships. A Principal with no
// kernel user is no member: there is nobody to add.
const membersStatement = `SELECT DISTINCT pm.keycloak_user_id
FROM identity.membership_desired m
JOIN identity.principal_mapping pm ON pm.principal_id = m.principal_id AND pm.realm = $2
WHERE m.tenant_id = $1 AND m.membership_status = 'active' AND pm.keycloak_user_id IS NOT NULL`

// convergedStatement finishes a convergence. The Tenant stays pending when it was marked again
// after the claim, because that mark may carry state this convergence did not read, and it then
// keeps delivered_at. Recorded converged, it clears delivered_at and answers the delay from it, in
// the database's clock, which set it (TDD-identity-control-002 2.5.0).
const convergedStatement = `UPDATE identity.tenant_convergence t
SET state            = CASE WHEN t.marked_at = $2 THEN 'converged' ELSE 'pending' END,
    priority         = CASE WHEN t.marked_at = $2 THEN false ELSE t.priority END,
    sweep            = CASE WHEN t.marked_at = $2 THEN false ELSE t.sweep END,
    delivered_at     = CASE WHEN t.marked_at = $2 THEN NULL ELSE t.delivered_at END,
    next_attempt_at  = now(),
    lease_until      = NULL,
    attempts         = 0,
    last_error_class = NULL,
    kernel_org_id    = coalesce(nullif($3, ''), t.kernel_org_id),
    converged_at     = now()
FROM (SELECT delivered_at FROM identity.tenant_convergence WHERE tenant_id = $1) held
WHERE t.tenant_id = $1
RETURNING t.state = 'converged', extract(epoch FROM now() - held.delivered_at)::float8`

const failedStatement = `UPDATE identity.tenant_convergence
SET state            = CASE WHEN $2 THEN 'unresolved' ELSE 'pending' END,
    next_attempt_at  = now() + $3 * interval '1 millisecond',
    lease_until      = NULL,
    last_error_class = $4,
    kernel_org_id    = coalesce(nullif($5, ''), kernel_org_id)
WHERE tenant_id = $1`

type claim struct {
	tenant   id.UUID
	marked   time.Time
	attempts int
	orgID    string
	priority bool
	sweep    bool
}

// change is one thing a convergence did to the kernel, which a sweep records as a finding.
type change struct {
	class  string
	user   keycloak.UserID
	detail map[string]any
}

// RunOnce converges one due Tenant, and reports whether there was one.
func (c *Converger) RunOnce(ctx context.Context) (bool, error) {
	var (
		cl     claim
		found  bool
		status string
		want   map[keycloak.UserID]bool
	)
	err := c.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		raw, err := claimOne(ctx, tx, c.cfg.Lease, &cl)
		if err != nil || raw == "" {
			return err
		}
		found = true
		if err := tx.QueryRow(ctx, tenantStatement, raw).Scan(&status); err != nil {
			return fmt.Errorf("tenantcontext: reading tenant %s: %w", raw, err)
		}
		rows, err := tx.Query(ctx, membersStatement, raw, string(c.cfg.Realm))
		if err != nil {
			return fmt.Errorf("tenantcontext: reading the members of %s: %w", raw, err)
		}
		defer rows.Close()
		want = map[keycloak.UserID]bool{}
		for rows.Next() {
			var user string
			if err := rows.Scan(&user); err != nil {
				return err
			}
			want[keycloak.UserID(user)] = true
		}
		return rows.Err()
	})
	if err != nil || !found {
		return found, err
	}

	start := time.Now()
	orgID, changes, err := c.converge(ctx, cl, status, want)
	c.metric.duration.Record(ctx, time.Since(start).Seconds())
	attrs := []any{slog.String("tenant_id", cl.tenant.String()), slog.Int("attempt", cl.attempts),
		slog.Bool("priority", cl.priority)}
	if err == nil {
		recorded, delay, finishErr := c.converged(ctx, cl, orgID, changes)
		if finishErr != nil {
			return true, finishErr
		}
		c.metric.attempts.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", "converged")))
		if recorded {
			priority := metric.WithAttributes(attribute.Bool("priority", cl.priority))
			c.metric.converged.Add(ctx, 1, priority)
			if delay != nil {
				c.metric.delay.Record(ctx, *delay, priority)
				attrs = append(attrs, slog.Float64("delivery_to_converged_seconds", *delay))
			}
		}
		c.logger.InfoContext(ctx, "tenant converged", attrs...)
		return true, nil
	}

	unresolved := cl.attempts >= c.cfg.MaxAttempts
	backoff := fullJitter(min(30*time.Second, time.Second<<min(cl.attempts, 5)))
	class := errorClass(err)
	if finishErr := c.finish(ctx, failedStatement, cl.tenant.String(), unresolved, backoff.Milliseconds(), class,
		orgID); finishErr != nil {
		return true, finishErr
	}
	outcome := "retry"
	if unresolved {
		outcome = "unresolved"
	}
	c.metric.attempts.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
	attrs = append(attrs, slog.String("error_class", class), slog.String("error", err.Error()))
	if unresolved {
		c.logger.ErrorContext(ctx, "tenant convergence unresolved", attrs...)
	} else {
		c.logger.WarnContext(ctx, "tenant convergence failed; it will be retried", attrs...)
	}
	return true, nil
}

// converged finishes a convergence, and for a sweep's records each change it had to make: in one
// transaction, so a finding exists exactly when the convergence it describes is recorded.
//
// It reports whether the Tenant was recorded converged rather than left pending by a later mark, and
// the delay from the earliest delivery that convergence closed, nil when no delivery was waiting.
func (c *Converger) converged(ctx context.Context, cl claim, orgID string, changes []change) (bool, *float64, error) {
	var (
		recorded bool
		delay    *float64
	)
	err := c.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if err := tx.QueryRow(ctx, convergedStatement, cl.tenant.String(), cl.marked, orgID).Scan(&recorded, &delay); err != nil {
			return fmt.Errorf("tenantcontext: recording the convergence: %w", err)
		}
		if !recorded {
			delay = nil
		}
		if !cl.sweep {
			return nil
		}
		for _, ch := range changes {
			findingID, err := id.NewV7()
			if err != nil {
				return err
			}
			detail := map[string]any{"organization_id": orgID}
			for k, v := range ch.detail {
				detail[k] = v
			}
			if ch.user != "" {
				detail["kernel_user_id"] = string(ch.user)
			}
			encoded, err := json.Marshal(detail)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, findingStatement, findingID.String(), ch.class, cl.tenant.String(),
				string(ch.user), string(c.cfg.Realm), string(encoded)); err != nil {
				return fmt.Errorf("tenantcontext: recording a finding: %w", err)
			}
		}
		if len(changes) > 0 {
			c.logger.WarnContext(ctx, "a sweep found the kernel apart from the desired state",
				slog.String("tenant_id", cl.tenant.String()), slog.Int("findings", len(changes)))
		}
		return nil
	})
	if err != nil {
		return false, nil, err
	}
	if cl.sweep {
		for _, ch := range changes {
			c.metric.shared.finding(ctx, ch.class)
		}
	}
	return recorded, delay, nil
}

func (c *Converger) finish(ctx context.Context, statement string, args ...any) error {
	return c.tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, statement, args...); err != nil {
			return fmt.Errorf("tenantcontext: recording the convergence: %w", err)
		}
		return nil
	})
}

// converge makes the kernel match one Tenant's desired state, and returns the Organization's
// identifier, which it returns also on a failure once it knows it.
func (c *Converger) converge(ctx context.Context, cl claim, status string,
	want map[keycloak.UserID]bool) (string, []change, error) {
	if status == "" {
		// No Tenant row: nothing is projected until the Tenant is known.
		return cl.orgID, nil, nil
	}
	name := cl.tenant.String()
	enabled := status == "active"

	var changes []change
	org, created, err := c.organization(ctx, cl.orgID, name, enabled)
	if err != nil {
		return org.ID, nil, err
	}
	if created {
		changes = append(changes, change{class: "organization_state", detail: map[string]any{"created": true}})
	}
	if org.Enabled && !enabled {
		if err := c.call(ctx, func(ctx context.Context) error {
			return c.kernel.SetOrganizationEnabled(ctx, c.cfg.Realm, org.ID, false)
		}); err != nil {
			return org.ID, nil, fmt.Errorf("disabling the Organization: %w", err)
		}
		changes = append(changes, change{class: "organization_state", detail: map[string]any{"enabled": false}})
	}
	var have []keycloak.UserID
	if err := c.call(ctx, func(ctx context.Context) error {
		var err error
		have, err = c.kernel.OrganizationMembers(ctx, c.cfg.Realm, org.ID)
		return err
	}); err != nil {
		return org.ID, nil, fmt.Errorf("listing the members: %w", err)
	}
	held := map[keycloak.UserID]bool{}
	for _, user := range have {
		held[user] = true
		if want[user] {
			continue
		}
		if err := c.call(ctx, func(ctx context.Context) error {
			return c.kernel.RemoveOrganizationMember(ctx, c.cfg.Realm, org.ID, user)
		}); err != nil {
			return org.ID, nil, fmt.Errorf("removing a member: %w", err)
		}
		changes = append(changes, change{class: "extra_member", user: user})
	}
	for user := range want {
		if held[user] {
			continue
		}
		if err := c.call(ctx, func(ctx context.Context) error {
			return c.kernel.AddOrganizationMember(ctx, c.cfg.Realm, org.ID, user)
		}); err != nil {
			return org.ID, nil, fmt.Errorf("adding a member: %w", err)
		}
		changes = append(changes, change{class: "missing_member", user: user})
	}
	if !org.Enabled && enabled {
		if err := c.call(ctx, func(ctx context.Context) error {
			return c.kernel.SetOrganizationEnabled(ctx, c.cfg.Realm, org.ID, true)
		}); err != nil {
			return org.ID, nil, fmt.Errorf("enabling the Organization: %w", err)
		}
		changes = append(changes, change{class: "organization_state", detail: map[string]any{"enabled": true}})
	}
	return org.ID, changes, c.readBack(ctx, org.ID, enabled, want)
}

// organization finds the Tenant's Organization by its recorded identifier, then by its exact name,
// and creates it only when neither finds one. A create whose response was lost is found by name on
// the next attempt rather than made twice.
func (c *Converger) organization(ctx context.Context, orgID, name string, enabled bool) (keycloak.Organization, bool,
	error) {
	if orgID != "" {
		var org keycloak.Organization
		err := c.call(ctx, func(ctx context.Context) error {
			var err error
			org, err = c.kernel.GetOrganization(ctx, c.cfg.Realm, orgID)
			return err
		})
		// The recorded identifier is trusted only for the Organization that carries this Tenant's
		// name: one that names another Tenant is not this Tenant's, and is never changed for it.
		if err == nil && org.Name == name {
			return org, false, nil
		}
		if err != nil && !errors.Is(err, keycloak.ErrNotFound) {
			return keycloak.Organization{ID: orgID}, false, fmt.Errorf("reading the Organization: %w", err)
		}
	}
	var (
		org   keycloak.Organization
		found bool
	)
	if err := c.call(ctx, func(ctx context.Context) error {
		var err error
		org, found, err = c.kernel.FindOrganization(ctx, c.cfg.Realm, name)
		return err
	}); err != nil {
		return keycloak.Organization{}, false, fmt.Errorf("finding the Organization: %w", err)
	}
	if found {
		return org, false, nil
	}
	var created string
	if err := c.call(ctx, func(ctx context.Context) error {
		var err error
		created, err = c.kernel.CreateOrganization(ctx, c.cfg.Realm, name, enabled)
		return err
	}); err != nil {
		return keycloak.Organization{}, false, fmt.Errorf("creating the Organization: %w", err)
	}
	return keycloak.Organization{ID: created, Name: name, Alias: name, Enabled: enabled}, true, nil
}

// readBack confirms the kernel holds the desired state. A timeout or a lost response is no
// evidence either way; the read decides.
func (c *Converger) readBack(ctx context.Context, orgID string, enabled bool, want map[keycloak.UserID]bool) error {
	var (
		org  keycloak.Organization
		have []keycloak.UserID
	)
	if err := c.call(ctx, func(ctx context.Context) error {
		var err error
		if org, err = c.kernel.GetOrganization(ctx, c.cfg.Realm, orgID); err != nil {
			return err
		}
		have, err = c.kernel.OrganizationMembers(ctx, c.cfg.Realm, orgID)
		return err
	}); err != nil {
		return fmt.Errorf("reading back: %w", err)
	}
	if org.Enabled != enabled || len(have) != len(want) {
		return fmt.Errorf("%w: enabled %t, %d members; want %t, %d", errReadBack, org.Enabled, len(have), enabled,
			len(want))
	}
	for _, user := range have {
		if !want[user] {
			return fmt.Errorf("%w: an unexpected member", errReadBack)
		}
	}
	return nil
}

var errReadBack = errors.New("tenantcontext: the kernel does not hold the desired state")

func (c *Converger) call(ctx context.Context, fn func(context.Context) error) error {
	callCtx, cancel := context.WithTimeout(ctx, c.cfg.AttemptTimeout)
	defer cancel()
	return fn(callCtx)
}

// errorClass names a failure for the record and the metrics, never its message.
func errorClass(err error) string {
	switch {
	case errors.Is(err, keycloak.ErrForbidden):
		return "forbidden"
	case errors.Is(err, keycloak.ErrAmbiguous):
		return "ambiguous"
	case errors.Is(err, errReadBack):
		return "read_back"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "unavailable"
	}
}

// fullJitter is random(0, limit): AWS's full jitter, as the security operation executor uses.
func fullJitter(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	return rand.N(limit)
}

// Run converges due Tenants until ctx ends: every Tenant that is due, then a pause of Interval.
func (c *Converger) Run(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()
	for {
		for {
			found, err := c.RunOnce(ctx)
			if err != nil && ctx.Err() == nil {
				c.logger.Error("the tenant converger could not claim", slog.String("error", err.Error()))
			}
			if !found || err != nil {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// claimOne claims a due Tenant into cl, and returns its identifier, or "" when none is due.
func claimOne(ctx context.Context, tx db.Tx, lease time.Duration, cl *claim) (string, error) {
	rows, err := tx.Query(ctx, claimStatement, lease.Milliseconds())
	if err != nil {
		return "", fmt.Errorf("tenantcontext: claiming a Tenant: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", rows.Err()
	}
	var raw string
	if err := rows.Scan(&raw, &cl.marked, &cl.attempts, &cl.orgID, &cl.priority, &cl.sweep); err != nil {
		return "", err
	}
	if cl.tenant, err = id.Parse(raw); err != nil {
		return "", err
	}
	rows.Close()
	return raw, rows.Err()
}
