// Command identity-provider-bootstrap builds this consumer's two projections from Organization
// Control's snapshots: provider authority (TDD-identity-control-006 §Bootstrap) and the Tenant context
// (TDD-identity-control-002 2.3.0 §Reconciliation).
//
// It reads each snapshot page by page under one mark, applies it, and then records the lower of the
// two marks with Organization Control, which is what permits this service's progress reports: the
// recorded position must not claim more than either snapshot represents. Until it has run, the
// provider projection is never fresh and no activation is honored.
//
// A registration that does not yet subscribe to the Membership and Tenant types is refused the
// Organization snapshot. The provider projection is then bootstrapped alone, and the command says so.
//
// It is safe to run again. Each snapshot is applied by version, so a rerun moves nothing backwards.
//
//	identity-provider-bootstrap
package main

import (
	"context"
	"errors"
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
	"github.com/anshacerbia2/identity-control/internal/tenantcontext"
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

	mark, tenantRows := snapshot.Mark, -1
	orgMark, rows, err := client.OrganizationSnapshot(ctx)
	switch {
	case errors.Is(err, organization.ErrRefused):
		logger.WarnContext(ctx, "the Organization snapshot was refused: this consumer's registration does not "+
			"subscribe to the Membership and Tenant types yet, so the Tenant context is not bootstrapped")
	case err != nil:
		return fmt.Errorf("organization snapshot: %w", err)
	default:
		desired, err := tenantcontext.NewDesired(pool)
		if err != nil {
			return err
		}
		if err := desired.ApplySnapshot(ctx, rows); err != nil {
			return fmt.Errorf("applying the Organization snapshot: %w", err)
		}
		mark, tenantRows = min(mark, orgMark), len(rows)
	}

	// Recorded after the local commits, so Organization never holds a mark this service did not
	// apply. A failure here leaves the projections built and the command safe to rerun.
	if err := client.RecordBootstrap(ctx, mark); err != nil {
		return fmt.Errorf("recording the bootstrap mark with Organization Control: %w", err)
	}

	logger.InfoContext(ctx, "projections bootstrapped", slog.Int64("mark", mark),
		slog.Int("grants", len(snapshot.Grants)), slog.Int("tenant_context_rows", tenantRows))
	fmt.Printf("\nprojections bootstrapped\n")
	fmt.Printf("  mark            %d\n", mark)
	fmt.Printf("  grants          %d\n", len(snapshot.Grants))
	if tenantRows < 0 {
		fmt.Printf("  tenant context  not bootstrapped: the registration does not subscribe to it\n")
	} else {
		fmt.Printf("  memberships     %d\n", tenantRows)
	}
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
