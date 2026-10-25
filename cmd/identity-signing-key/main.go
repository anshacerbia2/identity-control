// Command identity-signing-key is the realm signing keys' registry command (ADR-IAM-002 §5.5 Q5 to
// Q9, amended 2026-10-24; TDD-identity-control-001 1.29.0 §The Signing Key Registry).
//
// The identity kernel's rotation steps call it: each step asks `check` before it acts, and `record`
// after. A command rather than an endpoint, as the bootstrap ceremony is, so no new endpoint exists to
// protect (ADR-IAM-002 §5.5 Q9). It reaches the Control Database alone, as the runtime role, for which
// the registry is insert-only.
//
//	identity-signing-key stage   -realm scnehaux -kid <kid> -jwk <file> -custody-ref <ref> -operator <o> -witness <w> -reason <r> -correlation <c>
//	identity-signing-key approve -realm scnehaux -kid <kid> -transition activate -operator <o> -approver <a> -reason <r> -correlation <c> [-emergency]
//	identity-signing-key check   -realm scnehaux -kid <kid> -transition activate -operator <o> [-min-age 10m]
//	identity-signing-key record  -realm scnehaux -approval <id> -outcome completed [-evidence <e>]
//	identity-signing-key state   -realm scnehaux [-kid <kid>]
//
// Exit status: 0 done, 1 error, 2 refused by the registry.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/config"
	"github.com/anshacerbia2/identity-control/internal/signingkey"
)

const (
	exitError   = 1
	exitRefused = 2
)

const usage = "usage: identity-signing-key stage|approve|check|record|state [flags]"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return exitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	cfg, err := config.LoadSigningKey()
	if err != nil {
		fmt.Fprintf(stderr, "identity-signing-key: configuration: %v\n", err)
		return exitError
	}
	pool, err := db.Open(ctx, db.Config{Name: "identity-signing-key", DSN: cfg.RuntimeDSN, MaxConns: 2})
	if err != nil {
		fmt.Fprintf(stderr, "identity-signing-key: control database: %v\n", err)
		return exitError
	}
	defer pool.Close()

	err = dispatch(ctx, signingkey.New(pool), args[0], args[1:], stdout)
	switch {
	case errors.Is(err, signingkey.ErrRefused):
		fmt.Fprintf(stderr, "identity-signing-key: %v\n", err)
		return exitRefused
	case err != nil:
		fmt.Fprintf(stderr, "identity-signing-key: %v\n", err)
		return exitError
	}
	return 0
}

func dispatch(ctx context.Context, registry *signingkey.Registry, command string, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	realm := flags.String("realm", "", "the realm")
	kid := flags.String("kid", "", "the key's kid, its RFC 7638 thumbprint")
	jwk := flags.String("jwk", "", "stage: a file holding the key's public JWK, or - for standard input")
	custodyRef := flags.String("custody-ref", "", "stage: where the key is in custody, never the material")
	operator := flags.String("operator", "", "the step's operator")
	witness := flags.String("witness", "", "stage: the ceremony's witness, never the operator")
	approver := flags.String("approver", "", "approve: a holder of the ceremony role who is not the operator")
	transition := flags.String("transition", "", "approve, check: activate, retire, abandon or revoke")
	emergency := flags.Bool("emergency", false, "approve: an activation after a compromise, which does not wait")
	reason := flags.String("reason", "", "why")
	correlation := flags.String("correlation", "", "the correlation identifier, such as the change ticket")
	minAge := flags.Duration("min-age", 0, "check: how long the key must have been in its state")
	approval := flags.String("approval", "", "record: the approval the step ran under")
	outcome := flags.String("outcome", "", "record: completed or failed")
	evidence := flags.String("evidence", "", "record: the destruction's proof, or the failure's error")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *realm == "" {
		return errors.New("-realm is required")
	}

	switch command {
	case "stage":
		var content []byte
		var err error
		if *jwk == "-" {
			// From standard input, so the command can run in a container that cannot see the kernel's
			// keys directory: the public JWK is piped in.
			content, err = io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
		} else {
			content, err = os.ReadFile(*jwk)
		}
		if err != nil {
			return fmt.Errorf("reading the public JWK: %w", err)
		}
		if err := registry.Stage(ctx, signingkey.StageRequest{Realm: *realm, Kid: *kid, PublicJWK: content,
			CustodyRef: *custodyRef, Operator: *operator, Witness: *witness, Reason: *reason,
			CorrelationID: *correlation}); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "staged %s\n", *kid)
	case "approve":
		approvalID, err := registry.Approve(ctx, signingkey.ApproveRequest{Realm: *realm, Kid: *kid,
			Transition: *transition, Operator: *operator, Approver: *approver, Emergency: *emergency,
			Reason: *reason, CorrelationID: *correlation})
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, approvalID)
	case "check":
		found, err := registry.Check(ctx, signingkey.CheckRequest{Realm: *realm, Kid: *kid, Transition: *transition,
			Operator: *operator, MinAge: *minAge})
		if err != nil {
			return err
		}
		fmt.Fprintln(stdout, found.ID)
	case "record":
		approvalID, err := id.Parse(*approval)
		if err != nil {
			return fmt.Errorf("-approval: %w", err)
		}
		written, err := registry.Record(ctx, signingkey.RecordRequest{Realm: *realm, ApprovalID: approvalID,
			Outcome: *outcome, Evidence: *evidence})
		if err != nil {
			return err
		}
		for _, row := range written {
			fmt.Fprintf(stdout, "%s %s %s -> %s %s\n", row.Kid, row.Step, row.From, row.To, row.Outcome)
		}
	case "state":
		states, err := registry.State(ctx, *realm, *kid)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(stdout)
		for _, state := range states {
			if err := encoder.Encode(state); err != nil {
				return err
			}
		}
	default:
		return errors.New(usage)
	}
	return nil
}
