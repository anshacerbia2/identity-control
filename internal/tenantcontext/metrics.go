package tenantcontext

// The instruments TDD-identity-control-002 2.5.0 §Operational Notes names that more than one part of
// the projection records: a mark, by the intake, a repair, a sweep or a re-drive, and a finding, by a
// sweep's convergence or by the sweep itself. Each part registers them on the meter it is given; an
// identical registration returns the same instrument, so the series are one.

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// The kinds of mark, the marked counter's mark attribute.
const (
	markDelivery = "delivery"
	markSweep    = "sweep"
	markRedrive  = "redrive"
)

type shared struct {
	marked   metric.Int64Counter
	findings metric.Int64Counter
}

func newShared(meter metric.Meter) (shared, error) {
	if meter == nil {
		meter = noop.NewMeterProvider().Meter("")
	}
	var (
		s   shared
		err error
	)
	if s.marked, err = meter.Int64Counter("identity.tenant_projection.marked",
		metric.WithDescription("Tenants marked to converge, by mark (delivery, sweep, redrive) and priority")); err != nil {
		return shared{}, err
	}
	if s.findings, err = meter.Int64Counter("identity.tenant_projection.findings",
		metric.WithDescription("Findings recorded, by finding_class")); err != nil {
		return shared{}, err
	}
	return s, nil
}

func (s shared) mark(ctx context.Context, kind string, priority bool, n int64) {
	if n == 0 {
		return
	}
	s.marked.Add(ctx, n, metric.WithAttributes(attribute.String("mark", kind), attribute.Bool("priority", priority)))
}

func (s shared) finding(ctx context.Context, class string) {
	s.findings.Add(ctx, 1, metric.WithAttributes(attribute.String("finding_class", class)))
}
