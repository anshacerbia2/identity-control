package securitynotify

// Enrolment messages through the dispatcher (TDD-identity-control-001 1.27.0, ADR-IAM-011 §5.2,
// §5.9): the code opened for the hand-over alone, the account message in its place, and the address
// and the seal cleared once handed over.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/securityref"
)

func TestEnrolmentMessagesAreHandedOverAndCleared(t *testing.T) {
	p := openPool(t)
	ctx := context.Background()
	refs, err := securityref.New([]securityref.Key{{ID: "k1", Secret: []byte("0123456789abcdef0123456789abcdef")}}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	enrolmentID := newID(t)
	codeAddress := "code." + enrolmentID.String() + "@example.test"
	accountAddress := "account." + enrolmentID.String() + "@example.test"
	if err := p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO identity.enrolment
		    (enrolment_id, invitation_id, address_hash, address, code_hash, code_expires_at, caller_principal_id)
		    VALUES ($1, $2, 'h', $3, 'c', now() + interval '10 minutes', $4)`,
			enrolmentID.String(), newID(t).String(), codeAddress, newID(t).String()); err != nil {
			return err
		}
		if err := QueueEnrolmentCode(ctx, tx, refs, enrolmentID, codeAddress, "12345678"); err != nil {
			return err
		}
		return QueueAccountExists(ctx, tx, accountAddress)
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return QueueEnrolmentCode(ctx, tx, nil, enrolmentID, codeAddress, "1")
	}); err == nil {
		t.Error("a code was queued without a sealer")
	}
	if scalar[int](t, p, `SELECT count(*) FROM identity.enrolment_message WHERE sealed_secret LIKE '%12345678%'`) != 0 {
		t.Error("a message holds the code in the clear")
	}

	refused := &deliverer{err: errors.New("the platform refused it")}
	d, _ := NewDispatcher(p, refused, nil)
	d.WithSealer(refs)
	if _, err := d.Dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	if got := scalar[string](t, p, `SELECT state || ' ' || attempts::text || ' ' || (address IS NOT NULL)::text
	    FROM identity.enrolment_message WHERE enrolment_id = $1`, enrolmentID.String()); got != "requested 1 true" {
		t.Errorf("a refused hand-over reads %q; want it kept for a retry", got)
	}
	exec(t, p, `UPDATE identity.enrolment_message SET next_attempt_at = now() WHERE address IN ($1, $2)`, codeAddress, accountAddress)

	capture := &deliverer{}
	d, _ = NewDispatcher(p, capture, nil)
	d.WithSealer(refs)
	if _, err := d.Dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	var code, account *Request
	for i := range capture.received {
		switch {
		case capture.received[i].Event == EventEnrolmentCode && capture.received[i].Addresses[0] == codeAddress:
			code = &capture.received[i]
		case capture.received[i].Event == EventEnrolmentAccount && capture.received[i].Addresses[0] == accountAddress:
			account = &capture.received[i]
		}
	}
	if code == nil || code.Code != "12345678" || account == nil || account.Code != "" {
		t.Fatalf("handed over %+v and %+v", code, account)
	}
	if scalar[int](t, p, `SELECT count(*) FROM identity.enrolment_message
	    WHERE (enrolment_id = $1 OR kind = 'account_exists') AND state = 'submitted'
	      AND (address IS NOT NULL OR sealed_secret IS NOT NULL) AND submitted_at > now() - interval '1 minute'`,
		enrolmentID.String()) != 0 {
		t.Error("a handed-over message keeps its address or its seal")
	}
	subject, body := render(*code)
	if !strings.Contains(subject, "create your account") || !strings.Contains(body, "Your code is 12345678") {
		t.Errorf("the code message renders %q / %q", subject, body)
	}
	subject, body = render(*account)
	if !strings.Contains(subject, "An account exists") || strings.Contains(strings.ToLower(body), "proven") ||
		!strings.Contains(body, "sign in") {
		t.Errorf("the account message renders %q / %q", subject, body)
	}
}

func TestAnEnrolmentCodeThatCannotBeOpenedIsFailed(t *testing.T) {
	p := openPool(t)
	ctx := context.Background()
	short, _ := securityref.New([]securityref.Key{{ID: "k1", Secret: []byte("0123456789abcdef0123456789abcdef")}}, time.Millisecond)
	enrolmentID := newID(t)
	address := "lapsed." + enrolmentID.String() + "@example.test"
	if err := p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO identity.enrolment
		    (enrolment_id, invitation_id, address_hash, address, code_hash, code_expires_at, caller_principal_id)
		    VALUES ($1, $2, 'h', $3, 'c', now() + interval '10 minutes', $4)`,
			enrolmentID.String(), newID(t).String(), address, id.UUID{}.String()); err != nil {
			return err
		}
		return QueueEnrolmentCode(ctx, tx, short, enrolmentID, address, "87654321")
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	capture := &deliverer{}
	d, _ := NewDispatcher(p, capture, nil)
	d.WithSealer(short)
	if _, err := d.Dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	if got := scalar[string](t, p, `SELECT state || ' ' || (address IS NULL AND sealed_secret IS NULL)::text
	    FROM identity.enrolment_message WHERE enrolment_id = $1`, enrolmentID.String()); got != "failed true" {
		t.Errorf("an unopenable code reads %q", got)
	}
}
