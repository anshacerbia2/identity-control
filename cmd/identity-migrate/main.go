// Command identity-migrate applies the parts of the Control Database schema that Atlas
// does not own.
//
// Four sources build one database, and each is owned by whoever owns the SQL:
//
//	roles.sql                     this repository    cluster roles, no schema yet
//	foundation-platform platform  the shared module  the platform schema, shipped in Go
//	schema.hcl via Atlas          this repository    the identity schema
//	grants.sql                    this repository    privileges, after every object exists
//
// This command runs the first, second, and fourth. Atlas runs the third, which is why the
// stages are separate invocations rather than one:
//
//	identity-migrate -stage=pre     # roles, then the platform schema
//	atlas migrate apply --env ci    # the identity schema
//	identity-migrate -stage=post    # privileges
//
// The platform schema is applied from the module rather than copied into this repository.
// A column added to platform.outbox and a change to outbox.Append are one change, and
// splitting them across repositories permits a deployment where one has shipped and the
// other has not.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/migrations"

	"github.com/anshacerbia2/identity-control/internal/controldb"
)

const (
	stagePre  = "pre"
	stagePost = "post"
)

func main() {
	stage := flag.String("stage", "", "pre (roles and the platform schema) or post (privileges)")
	timeout := flag.Duration("timeout", 2*time.Minute, "upper bound on the whole run")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(*stage, *timeout, logger); err != nil {
		logger.Error("migration failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run(stage string, timeout time.Duration, logger *slog.Logger) error {
	if stage != stagePre && stage != stagePost {
		return fmt.Errorf("-stage must be %q or %q, got %q", stagePre, stagePost, stage)
	}

	dsn := os.Getenv("IDENTITY_MIGRATION_DATABASE_URL")
	if dsn == "" {
		return errors.New("IDENTITY_MIGRATION_DATABASE_URL is required")
	}

	// A migration run holds DDL locks. Cancelling on a signal lets an operator abort a
	// stuck deploy without waiting for the timeout, and the transaction rolls back.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// No SessionBinder. Row-Level Security binds a tenant, and a migration is not
	// tenant-scoped; binding one here would scope DDL to a tenant that does not exist yet.
	pool, err := db.Open(ctx, db.Config{
		Name:     "identity-migration",
		DSN:      dsn,
		MaxConns: 2,
	})
	if err != nil {
		return fmt.Errorf("open migration pool: %w", err)
	}
	defer pool.Close()

	switch stage {
	case stagePre:
		if err := applyStage(ctx, pool, controldb.StageRoles, logger); err != nil {
			return err
		}
		return applyPlatform(ctx, pool, logger)
	default:
		return applyStage(ctx, pool, controldb.StageGrants, logger)
	}
}

// applyStage runs one embedded statement file in a single transaction.
func applyStage(ctx context.Context, pool *db.Pool, stage controldb.Stage, logger *slog.Logger) error {
	body, err := controldb.SQL(stage)
	if err != nil {
		return err
	}
	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		_, execErr := tx.Exec(ctx, body)
		return execErr
	}); err != nil {
		return fmt.Errorf("apply %s: %w", stage, err)
	}
	logger.Info("applied", slog.String("source", string(stage)))
	return nil
}

// applyPlatform applies every migration foundation-platform ships, in name order, inside
// one transaction.
//
// One transaction for the whole set rather than one each: a partially applied platform
// schema is a database the dispatcher starts against and fails on at the first claim, and
// every shipped statement is idempotent, so a retry after a rollback is safe.
func applyPlatform(ctx context.Context, pool *db.Pool, logger *slog.Logger) error {
	set, err := migrations.PlatformMigrations()
	if err != nil {
		return fmt.Errorf("load platform migrations: %w", err)
	}
	if len(set) == 0 {
		return errors.New("foundation-platform shipped no migrations; the dependency is broken")
	}

	if err := pool.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		for _, migration := range set {
			if _, execErr := tx.Exec(ctx, migration.SQL); execErr != nil {
				return fmt.Errorf("%s: %w", migration.Name, execErr)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("apply platform schema: %w", err)
	}

	for _, migration := range set {
		logger.Info("applied",
			slog.String("source", "foundation-platform"),
			slog.String("migration", migration.Name))
	}
	return nil
}
