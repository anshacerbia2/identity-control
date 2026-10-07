package registration

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/anshacerbia2/foundation-platform/db"
)

// expiringGauge collects the key expiry gauge from a service: each severity's value, and whether the
// gauge was reported at all.
func expiringGauge(t *testing.T, s *Service) (map[string]int64, bool) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	if err := s.Instrument(provider.Meter("test")); err != nil {
		t.Fatal(err)
	}
	var collected metricdata.ResourceMetrics
	_ = reader.Collect(context.Background(), &collected) // a failed callback is reported here, and tested by what is absent
	for _, scope := range collected.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != "identity.client_key.expiring" {
				continue
			}
			gauge, ok := m.Data.(metricdata.Gauge[int64])
			if !ok {
				t.Fatalf("identity.client_key.expiring is %T, want an int64 gauge", m.Data)
			}
			out := map[string]int64{}
			for _, p := range gauge.DataPoints {
				severity, _ := p.Attributes.Value("severity")
				out[severity.AsString()] = p.Value
			}
			return out, len(gauge.DataPoints) > 0
		}
	}
	return nil, false
}

type failingTx struct{}

func (failingTx) InTx(context.Context, func(context.Context, db.Tx) error) error {
	return errors.New("the database is unreachable")
}

// A read that fails observes nothing, so an alert on the gauge fires on its absence
// (STD-GLB-003 1.1.0 §State Metrics rule 2).
func TestTheExpiryGaugeObservesNothingWhenItsReadFails(t *testing.T) {
	s := &Service{tx: failingTx{}, cfg: Config{Realm: "gauge-test"}, now: time.Now,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if values, reported := expiringGauge(t, s); reported {
		t.Errorf("a failed read reported %v; it must report nothing", values)
	}
}

func TestANilMeterInstrumentsNothing(t *testing.T) {
	if err := (&Service{}).Instrument(nil); err != nil {
		t.Errorf("Instrument(nil): %v", err)
	}
}
