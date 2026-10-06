package securitynotify

// A person's own addresses against the real engine (TDD-identity-control-008 1.2.0).

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/db"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/securityref"
)

func addressService(t *testing.T, p Transactor) (*Addresses, *securityref.Codec, *string) {
	t.Helper()
	refs, err := securityref.New([]securityref.Key{{ID: "k1", Secret: []byte("0123456789abcdef0123456789abcdef")}}, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAddresses(p, refs, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var issued string
	a.newCode = func() (string, error) {
		code, err := proofCode()
		issued = code
		return code, err
	}
	return a, refs, &issued
}

func requests(t *testing.T, p Transactor, principal id.UUID, event string) []struct {
	recipients int
	state      string
	sealed     bool
	details    string
} {
	t.Helper()
	var out []struct {
		recipients int
		state      string
		sealed     bool
		details    string
	}
	_ = p.InTx(context.Background(), func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.Query(ctx, `SELECT cardinality(recipients), state, sealed_secret IS NOT NULL, details::text
		    FROM identity.security_notification WHERE principal_id = $1 AND event = $2 ORDER BY requested_at`,
			principal.String(), event)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var r struct {
				recipients int
				state      string
				sealed     bool
				details    string
			}
			if err := rows.Scan(&r.recipients, &r.state, &r.sealed, &r.details); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out
}

func TestAnAddressIsAddedProvenAndRemovedWithItsNotifications(t *testing.T) {
	p := openPool(t)
	ctx := context.Background()
	realm := keycloak.Realm("notify-" + newID(t).String())
	principal, _ := person(t, p, realm, "first@example.test")
	a, refs, issued := addressService(t, p)

	added, err := a.Add(ctx, principal, "second@example.test")
	if err != nil || added.State != "pending" {
		t.Fatalf("Add: %+v, %v", added, err)
	}
	// The code sent to it; a later Add draws another.
	code := *issued
	proofs := requests(t, p, principal, EventAddressProof)
	if len(proofs) != 1 || proofs[0].recipients != 1 || !proofs[0].sealed {
		t.Fatalf("the proof request is %+v; want one, to the new address alone, its code sealed", proofs)
	}
	if _, err := a.Add(ctx, principal, "SECOND@example.test"); !errors.Is(err, ErrAddressHeld) {
		t.Errorf("the same address again answered %v; want ErrAddressHeld", err)
	}

	// The dispatcher opens the code for the hand-over, and clears the seal.
	capture := &deliverer{}
	d, _ := NewDispatcher(p, capture, nil)
	d.WithSealer(refs)
	if _, err := d.Dispatch(ctx); err != nil {
		t.Fatal(err)
	}
	var handed *Request
	for i := range capture.received {
		if capture.received[i].PrincipalID == principal && capture.received[i].Event == EventAddressProof {
			handed = &capture.received[i]
		}
	}
	if handed == nil || handed.Code != code || len(handed.Addresses) != 1 || handed.Addresses[0] != "second@example.test" {
		got := "none"
		if handed != nil {
			got = fmt.Sprintf("to %v, code matches %t", handed.Addresses, handed.Code == code)
		}
		t.Fatalf("the hand-over was %s; want the issued code to the new address", got)
	}
	if proofs := requests(t, p, principal, EventAddressProof); proofs[0].sealed || proofs[0].state != StateSubmitted {
		t.Errorf("after the hand-over the proof request is %+v; want submitted, its seal cleared", proofs[0])
	}

	// A wrong code leaves it pending; the right one activates it and tells the first address.
	if err := a.Verify(ctx, principal, added.AddressID, "00000000"); !errors.Is(err, ErrWrongCode) {
		t.Errorf("a wrong code answered %v", err)
	}
	if err := a.Verify(ctx, principal, added.AddressID, code); err != nil {
		t.Fatalf("the right code answered %v", err)
	}
	changed := requests(t, p, principal, EventAddressChanged)
	if len(changed) != 1 || changed[0].recipients != 1 {
		t.Fatalf("the added notification is %+v; want one, to the address held before", changed)
	}
	if err := a.Verify(ctx, principal, added.AddressID, code); !errors.Is(err, ErrNotPending) {
		t.Errorf("verifying an active address answered %v", err)
	}

	list, err := a.List(ctx, principal)
	if err != nil || len(list) != 2 || list[1].State != "active" || list[1].VerifiedAt == nil {
		t.Fatalf("List: %+v, %v", list, err)
	}

	// Removing tells both addresses held before, the removed one included; the last one stays.
	if err := a.Remove(ctx, principal, list[0].AddressID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	changed = requests(t, p, principal, EventAddressChanged)
	if len(changed) != 2 || changed[1].recipients != 2 {
		t.Errorf("the removed notification is %+v; want it to both addresses held before", changed)
	}
	if err := a.Remove(ctx, principal, list[1].AddressID); !errors.Is(err, ErrLastAddress) {
		t.Errorf("removing the last address answered %v; want ErrLastAddress", err)
	}
	other, _ := person(t, p, realm, "else@example.test")
	if err := a.Remove(ctx, other, list[1].AddressID); !errors.Is(err, ErrNoSuchAddress) {
		t.Errorf("another person's address answered %v; want ErrNoSuchAddress", err)
	}
}

func TestAProofIsBoundedInAttemptsTimeAndNumber(t *testing.T) {
	p := openPool(t)
	ctx := context.Background()
	realm := keycloak.Realm("notify-" + newID(t).String())
	principal, _ := person(t, p, realm, "one@example.test")
	a, refs, issued := addressService(t, p)

	pending, err := a.Add(ctx, principal, "guess@example.test")
	if err != nil {
		t.Fatal(err)
	}
	code := *issued
	for range maxProofAttempts {
		_ = a.Verify(ctx, principal, pending.AddressID, "99999999")
	}
	if err := a.Verify(ctx, principal, pending.AddressID, code); !errors.Is(err, ErrWrongCode) {
		t.Errorf("the right code after five wrong ones answered %v; want ErrWrongCode", err)
	}

	late, err := a.Add(ctx, principal, "late@example.test")
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if err := a.Verify(ctx, principal, late.AddressID, *issued); !errors.Is(err, ErrWrongCode) {
		t.Errorf("an expired code answered %v; want ErrWrongCode", err)
	}
	a.now = time.Now

	// A seal that expired before the hand-over fails the request, and the code is not sent. The seal
	// carries the lifetime of the codec that made it.
	shortLived, _ := securityref.New([]securityref.Key{{ID: "k1", Secret: []byte("0123456789abcdef0123456789abcdef")}}, time.Millisecond)
	hurried, _ := NewAddresses(p, shortLived, 10*time.Minute)
	if _, err := hurried.Add(ctx, principal, "never@example.test"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	capture := &deliverer{}
	d, _ := NewDispatcher(p, capture, nil)
	d.WithSealer(refs)
	_, _ = d.Dispatch(ctx)
	for _, r := range capture.received {
		if r.PrincipalID == principal && r.Event == EventAddressProof && r.Addresses[0] == "never@example.test" {
			t.Error("a proof whose seal expired was handed over")
		}
	}
	var failed int
	_ = p.InTx(ctx, func(ctx context.Context, tx db.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM identity.security_notification n
		    JOIN identity.notification_address a ON a.address_id = n.recipients[1]
		    WHERE n.principal_id = $1 AND n.event = $2 AND a.address = 'never@example.test'
		      AND n.state = 'failed' AND n.sealed_secret IS NULL`, principal.String(), EventAddressProof).Scan(&failed)
	})
	if failed != 1 {
		t.Errorf("%d expired proofs failed with their seal cleared; want 1", failed)
	}

	for range MaxAddresses - 4 {
		if _, err := a.Add(ctx, principal, newID(t).String()+"@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Add(ctx, principal, "sixth@example.test"); !errors.Is(err, ErrTooMany) {
		t.Errorf("a sixth address answered %v; want ErrTooMany", err)
	}
}
