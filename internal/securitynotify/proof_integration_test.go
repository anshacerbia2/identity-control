package securitynotify

// Proving an address already held, and the identifier match, against the real engine
// (TDD-identity-control-008 1.7.0, ADR-ORG-007 §5.3).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/keycloak"
	"github.com/anshacerbia2/identity-control/internal/securityref"
)

func TestACreationAddressIsProvenWithACodeAndThenMatches(t *testing.T) {
	p := openPool(t)
	ctx := context.Background()
	realm := keycloak.Realm("proof-" + newID(t).String())
	principal, _ := person(t, p, realm, "Creation@Example.test")
	a, refs, issued := addressService(t, p)
	held, err := a.List(ctx, principal)
	if err != nil || len(held) != 1 || held[0].VerifiedAt != nil || held[0].ProofExpiresAt != nil {
		t.Fatalf("the creation address is %+v, %v; want one active address, unproven, no code outstanding", held, err)
	}
	creation := held[0].AddressID

	// Unproven, it does not match: a provider recorded it, and nobody has shown the person reads it.
	if match, err := a.Match(ctx, principal, "creation@example.test"); err != nil || match {
		t.Fatalf("an unproven creation address matched: %t, %v", match, err)
	}

	sent, err := a.SendProof(ctx, principal, creation)
	if err != nil || sent.ProofExpiresAt == nil || sent.State != "active" || sent.Address != "Creation@Example.test" {
		t.Fatalf("send-proof: %+v, %v", sent, err)
	}
	// One proof request, to that address alone, its code sealed.
	proofs := requests(t, p, principal, EventAddressProof)
	if len(proofs) != 1 || proofs[0].recipients != 1 || !proofs[0].sealed || proofs[0].state != StateRequested {
		t.Fatalf("the proof request is %+v", proofs)
	}
	// The seal opens to the code the address's hash was made from.
	sealed := scalar[string](t, p, `SELECT sealed_secret FROM identity.security_notification
	    WHERE principal_id = $1 AND event = $2`, principal.String(), EventAddressProof)
	if ref, err := refs.Open(sealed, securityref.KindNotificationProof, principal, ProofPurpose); err != nil || ref.KernelID != *issued {
		t.Fatalf("the sealed code is not the code that was issued: %v", err)
	}

	code := *issued
	// A second send while the code is good is refused, so a resend never replaces a code early.
	if _, err := a.SendProof(ctx, principal, creation); !errors.Is(err, ErrProofOutstanding) {
		t.Fatalf("a second send-proof answered %v; want ErrProofOutstanding", err)
	}
	listed, _ := a.List(ctx, principal)
	if listed[0].ProofExpiresAt == nil {
		t.Fatal("the list does not show the outstanding code's expiry")
	}

	if code != "00000000" {
		if err := a.Verify(ctx, principal, creation, "00000000"); !errors.Is(err, ErrWrongCode) {
			t.Fatalf("a wrong code answered %v", err)
		}
	}
	if err := a.Verify(ctx, principal, creation, code); err != nil {
		t.Fatalf("the right code: %v", err)
	}
	proven, _ := a.List(ctx, principal)
	if proven[0].State != "active" || proven[0].VerifiedAt == nil || proven[0].ProofExpiresAt != nil {
		t.Fatalf("after its code the address is %+v; want active, verified, no code outstanding", proven[0])
	}
	// Proving an address already held changes no recipient, so nobody is told.
	if changed := requests(t, p, principal, EventAddressChanged); len(changed) != 0 {
		t.Fatalf("proving a held address requested %d address-changed notifications", len(changed))
	}
	// Proven, it matches, compared without case.
	if match, err := a.Match(ctx, principal, "CREATION@example.test"); err != nil || !match {
		t.Fatalf("a proven address did not match: %t, %v", match, err)
	}
	// A proven address takes no new code.
	if _, err := a.SendProof(ctx, principal, creation); !errors.Is(err, ErrProven) {
		t.Fatalf("send-proof on a proven address answered %v; want ErrProven", err)
	}
}

func TestSendProofIsRefusedForAnythingButAnActiveUnprovenAddress(t *testing.T) {
	p := openPool(t)
	ctx := context.Background()
	realm := keycloak.Realm("proof-" + newID(t).String())
	principal, _ := person(t, p, realm, "held@example.test")
	a, _, _ := addressService(t, p)
	if _, err := a.SendProof(ctx, principal, newID(t)); !errors.Is(err, ErrNoSuchAddress) {
		t.Fatalf("an unknown address answered %v; want ErrNoSuchAddress", err)
	}
	// Another person's address is no such address.
	other, _ := person(t, p, realm, "other@example.test")
	otherHeld, _ := a.List(ctx, other)
	if _, err := a.SendProof(ctx, principal, otherHeld[0].AddressID); !errors.Is(err, ErrNoSuchAddress) {
		t.Fatalf("another person's address answered %v; want ErrNoSuchAddress", err)
	}
	// A pending address is proven with the code its add sent; it takes no second one.
	pending, err := a.Add(ctx, principal, "added@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SendProof(ctx, principal, pending.AddressID); !errors.Is(err, ErrProven) {
		t.Fatalf("a pending address answered %v; want ErrProven", err)
	}
}

func TestAnExpiredCodeCanBeSentAgain(t *testing.T) {
	p := openPool(t)
	ctx := context.Background()
	realm := keycloak.Realm("proof-" + newID(t).String())
	principal, _ := person(t, p, realm, "again@example.test")
	a, _, issued := addressService(t, p)
	held, _ := a.List(ctx, principal)
	if _, err := a.SendProof(ctx, principal, held[0].AddressID); err != nil {
		t.Fatal(err)
	}
	first := *issued
	a.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if _, err := a.SendProof(ctx, principal, held[0].AddressID); err != nil {
		t.Fatalf("a send after the first code expired: %v", err)
	}
	a.now = time.Now
	if first != *issued {
		if err := a.Verify(ctx, principal, held[0].AddressID, first); !errors.Is(err, ErrWrongCode) {
			t.Fatalf("the replaced code answered %v; want ErrWrongCode", err)
		}
	}
	if err := a.Verify(ctx, principal, held[0].AddressID, *issued); err != nil {
		t.Fatalf("the new code: %v", err)
	}
	if got := len(requests(t, p, principal, EventAddressProof)); got != 2 {
		t.Fatalf("%d proof requests; want one per code", got)
	}
}

func TestTheMatchAnswersFalseAlikeForEveryOtherCase(t *testing.T) {
	p := openPool(t)
	ctx := context.Background()
	realm := keycloak.Realm("match-" + newID(t).String())
	principal, _ := person(t, p, realm)
	a, _, _ := addressService(t, p)
	exec(t, p, `INSERT INTO identity.notification_address (address_id, principal_id, channel, address, origin, state, verified_at, removed_at)
	    VALUES ($1, $2, 'email', 'proven@example.test', 'added', 'active', now(), NULL),
	           ($3, $2, 'email', 'gone@example.test', 'added', 'removed', now(), now())`,
		newID(t).String(), principal.String(), newID(t).String())
	if match, err := a.Match(ctx, principal, "proven@example.test"); err != nil || !match {
		t.Fatalf("a proven address: %t, %v", match, err)
	}
	for name, c := range map[string]struct {
		principal string
		address   string
	}{
		"an address the Principal does not hold": {principal.String(), "someone@example.test"},
		"a removed address":                      {principal.String(), "gone@example.test"},
		"an unknown Principal":                   {newID(t).String(), "proven@example.test"},
	} {
		subject, err := id.Parse(c.principal)
		if err != nil {
			t.Fatal(err)
		}
		if match, err := a.Match(ctx, subject, c.address); err != nil || match {
			t.Errorf("%s: %t, %v; want false", name, match, err)
		}
	}
	// A suspended Principal matches nothing.
	exec(t, p, `UPDATE identity.principal_mapping SET state = 'suspended' WHERE principal_id = $1`, principal.String())
	if match, err := a.Match(ctx, principal, "proven@example.test"); err != nil || match {
		t.Fatalf("a suspended Principal matched: %t, %v", match, err)
	}
	if _, err := a.Match(ctx, principal, "not an address"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("a malformed address answered %v", err)
	}
}
