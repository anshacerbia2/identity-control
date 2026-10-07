package registration

// The key expiry gauge (TDD-identity-control-003 1.31.0 §Key Expiry Warnings), a state metric as
// STD-GLB-003 1.1.0 §State Metrics defines one: read from the database when the reader collects,
// under a timeout, with severity as its only attribute and every severity observed.

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// gaugeReadTimeout bounds the callback's read of the database.
const gaugeReadTimeout = 5 * time.Second

// Instrument registers the key expiry gauge with the meter. A nil meter registers nothing.
func (s *Service) Instrument(meter metric.Meter) error {
	if meter == nil {
		return nil
	}
	_, err := meter.Int64ObservableGauge("identity.client_key.expiring",
		metric.WithDescription("Active keyed registrations whose last accepted key stops within 14 days, "+
			"by severity: warning, critical (3 days), no_key"),
		metric.WithInt64Callback(func(ctx context.Context, o metric.Int64Observer) error {
			ctx, cancel := context.WithTimeout(ctx, gaugeReadTimeout)
			defer cancel()
			expiring, err := s.ExpiringKeys(ctx)
			if err != nil {
				// Nothing is observed, so an alert on the gauge fires on its absence too.
				s.logger.ErrorContext(ctx, "the key expiry gauge could not read the registrations",
					slog.String("error", err.Error()))
				return err
			}
			counts := map[string]int64{SeverityNoKey: 0, SeverityCritical: 0, SeverityWarning: 0}
			for _, entry := range expiring.Registrations {
				counts[entry.Severity]++
			}
			for _, severity := range []string{SeverityNoKey, SeverityCritical, SeverityWarning} {
				o.Observe(counts[severity], metric.WithAttributes(attribute.String("severity", severity)))
			}
			return nil
		}))
	return err
}
