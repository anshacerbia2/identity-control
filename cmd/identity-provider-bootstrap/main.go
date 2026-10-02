// Command identity-provider-bootstrap builds the provider authority projection from Organization
// Control's snapshot (TDD-identity-control-006 §Bootstrap).
//
// It reads the snapshot page by page under one mark, replaces the projection in one transaction,
// and then records the mark with Organization Control, which is what permits this service's progress
// reports. Until it has run, the projection is never fresh and no activation is honored.
//
// It is safe to run again. The snapshot is applied by version, so a rerun moves no grant backwards,
// and a grant held locally that the snapshot omits was revoked in Organization's record.
//
//	identity-provider-bootstrap
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"

	"github.com/anshacerbia2/identity-control/internal/config"
	"github.com/anshacerbia2/identity-control/internal/organization"
	"github.com/anshacerbia2/identity-control/internal/providerauthority"
)

func main() {
	timeout := flag.Duration("timeout", 2*time.Minute, "upper bound on the whole bootstrap")
	flag.Parse()

	if err := run(*timeout); err != nil {
		fmt.Fprintf(os.Stderr, "identity-provider-bootstrap: %v\n", err)
		os.Exit(1)
	}
}

func run(timeout time.Duration) error {
	cfg, err := config.LoadProviderBootstrap()
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pool, err := db.Open(ctx, db.Config{
		Name:     "identity-provider-bootstrap",
		DSN:      cfg.RuntimeDSN,
		MaxConns: 2,
	})
	if err != nil {
		return fmt.Errorf("control database: %w", err)
	}
	defer pool.Close()

	projection, err := providerauthority.New(pool)
	if err != nil {
		return fmt.Errorf("provider authority projection: %w", err)
	}
	client, err := organization.NewWorkload(organizationWorkload(cfg.Organization))
	if err != nil {
		return err
	}

	snapshot, err := client.ProviderSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("provider authority snapshot: %w", err)
	}
	if err := projection.ReplaceFromSnapshot(ctx, snapshot.Mark, snapshot.Grants); err != nil {
		return err
	}
	// Recorded after the local commit, so Organization never holds a mark this service did not
	// apply. A failure here leaves the projection built and the command safe to rerun.
	if err := client.RecordBootstrap(ctx, snapshot.Mark); err != nil {
		return fmt.Errorf("recording the bootstrap mark with Organization Control: %w", err)
	}

	logger.InfoContext(ctx, "provider authority projection bootstrapped",
		slog.Int64("mark", snapshot.Mark),
		slog.Int("grants", len(snapshot.Grants)))
	fmt.Printf("\nprovider authority projection bootstrapped\n")
	fmt.Printf("  mark    %d\n", snapshot.Mark)
	fmt.Printf("  grants  %d\n", len(snapshot.Grants))
	return nil
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// organizationWorkload is the configured workload client, in the client's terms.
func organizationWorkload(cfg config.Organization) organization.Workload {
	return organization.Workload{
		BaseURL: cfg.BaseURL, ClientID: cfg.WorkloadClientID, KeyFile: cfg.WorkloadKeyFile,
		TokenURL: cfg.WorkloadTokenURL, Audience: cfg.WorkloadAudience,
	}
}
