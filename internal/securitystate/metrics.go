package securitystate

// The executor's metrics (TDD-identity-control-005 §Operating the Executor), the set STD-GLB-011
// §3.15 asks of every durable job implementation. Without a meter they go to OpenTelemetry's no-op
// instruments, so the service runs the same whether or not a Collector is configured.

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/anshacerbia2/foundation-platform/db"
)

type instruments struct {
	accepted  metric.Int64Counter
	attempts  metric.Int64Counter
	wait      metric.Float64Histogram
	duration  metric.Float64Histogram
	leaseLost metric.Int64Counter
	redrives  metric.Int64Counter
}

func newInstruments(meter metric.Meter, tx Transactor) (instruments, error) {
	if meter == nil {
		meter = noop.NewMeterProvider().Meter("")
	}
	var (
		in  instruments
		err error
	)
	if in.accepted, err = meter.Int64Counter("identity.security_operation.accepted",
		metric.WithDescription("Security commands accepted; replay marks a repeated Idempotency-Key")); err != nil {
		return in, err
	}
	if in.attempts, err = meter.Int64Counter("identity.security_operation.attempts",
		metric.WithDescription("Executor attempts, by outcome: applied, refused, retry, unresolved")); err != nil {
		return in, err
	}
	if in.wait, err = meter.Float64Histogram("identity.security_operation.wait", metric.WithUnit("s"),
		metric.WithDescription("Time from acceptance to an attempt's claim")); err != nil {
		return in, err
	}
	if in.duration, err = meter.Float64Histogram("identity.security_operation.duration", metric.WithUnit("s"),
		metric.WithDescription("One attempt's kernel calls")); err != nil {
		return in, err
	}
	if in.leaseLost, err = meter.Int64Counter("identity.security_operation.lease_lost",
		metric.WithDescription("Attempts whose lease another worker took over before they finished")); err != nil {
		return in, err
	}
	if in.redrives, err = meter.Int64Counter("identity.security_operation.redrives",
		metric.WithDescription("Parked operations an operator re-drove")); err != nil {
		return in, err
	}
	// The parked count is read when the reader collects, so it is the database's, not this replica's.
	if _, err = meter.Int64ObservableGauge("identity.security_operation.unresolved",
		metric.WithDescription("Operations parked as unresolved; any is critical"),
		metric.WithInt64Callback(func(ctx context.Context, o metric.Int64Observer) error {
			// Bounded, as STD-GLB-003 1.1.0 §State Metrics asks; a failed read observes nothing.
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			var count int64
			err := tx.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM identity.security_operation WHERE state = 'unresolved'`).Scan(&count)
			})
			if err == nil {
				o.Observe(count)
			}
			return err
		})); err != nil {
		return in, err
	}
	return in, nil
}

func typed(operationType string, more ...attribute.KeyValue) metric.MeasurementOption {
	return metric.WithAttributes(append([]attribute.KeyValue{attribute.String("operation_type", operationType)}, more...)...)
}

func seconds(d time.Duration) float64 { return d.Seconds() }
