package provisioning_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/db/dbtest"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/identity/provisioning"
	"github.com/anshacerbia2/identity-control/internal/keycloak"
)

// TestStateMachineRejectsEveryUndeclaredTransition enumerates the full product of states and
// asserts that only the transitions in the diagram are permitted.
//
// Enumerating rather than listing the legal moves is the point. A test that checks the four
// transitions someone remembered would pass while a fifth was quietly accepted, and the
// transition that matters most — quarantined back to active, which would un-contain a
// Principal — is exactly the kind nobody writes a case for.
func TestStateMachineRejectsEveryUndeclaredTransition(t *testing.T) {
	all := []provisioning.State{
		provisioning.StatePending,
		provisioning.StateActive,
		provisioning.StateQuarantined,
		provisioning.StateRetired,
	}

	legal := map[provisioning.State]map[provisioning.State]bool{
		provisioning.StatePending: {
			provisioning.StateActive:      true,
			provisioning.StateQuarantined: true,
		},
		provisioning.StateActive: {
			provisioning.StateRetired:     true,
			provisioning.StateQuarantined: true,
		},
		provisioning.StateQuarantined: {},
		provisioning.StateRetired:     {},
	}

	for _, from := range all {
		for _, to := range all {
			want := legal[from][to]
			got := from.CanTransitionTo(to)
			if got != want {
				t.Errorf("%s -> %s: permitted = %v, want %v", from, to, got, want)
			}
		}
	}
}

// TestQuarantineAndRetiredAreTerminal states the property separately because it is the one
// with a security consequence: a Principal contained by quarantine must not be released by a
// state transition.
func TestQuarantineAndRetiredAreTerminal(t *testing.T) {
	for _, terminal := range []provisioning.State{provisioning.StateQuarantined, provisioning.StateRetired} {
		for _, target := range []provisioning.State{
			provisioning.StatePending,
			provisioning.StateActive,
			provisioning.StateQuarantined,
			provisioning.StateRetired,
		} {
			if terminal.CanTransitionTo(target) {
				t.Errorf("%s is not terminal: it permits a move to %s", terminal, target)
			}
		}
	}
}

func TestSameStateTransitionIsRefused(t *testing.T) {
	for _, state := range []provisioning.State{provisioning.StatePending, provisioning.StateActive} {
		if state.CanTransitionTo(state) {
			t.Errorf("%s permits a transition to itself; a repeated attempt must be recognised, not absorbed", state)
		}
	}
}

func TestUnknownStateIsInvalid(t *testing.T) {
	unknown := provisioning.State("suspended")
	if unknown.Valid() {
		t.Error("an undeclared state reports itself valid")
	}
	if unknown.CanTransitionTo(provisioning.StateActive) {
		t.Error("an undeclared state permits a transition")
	}
}

func mustUUID(t *testing.T) id.UUID {
	t.Helper()
	value, err := id.NewV7()
	if err != nil {
		t.Fatalf("NewV7: %v", err)
	}
	return value
}

// TestInsertPendingWritesThePendingState asserts the statement rather than the round trip,
// which is what dbtest is for. The state literal matters: a mapping written as active before
// the kernel call would make recovery skip it.
func TestInsertPendingWritesThePendingState(t *testing.T) {
	var repo provisioning.Repository
	tx := &dbtest.Tx{Tag: dbtest.CommandTag(1)}

	principalID := mustUUID(t)
	err := repo.InsertPending(context.Background(), tx, provisioning.Mapping{
		PrincipalID: principalID,
		Realm:       "scnehaux",
		Username:    "operator",
		SubjectType: keycloak.SubjectHuman,
	})
	if err != nil {
		t.Fatalf("InsertPending: %v", err)
	}

	call := tx.Only(t)
	if !strings.Contains(call.SQL, "identity.principal_mapping") {
		t.Errorf("statement does not target identity.principal_mapping: %s", call.SQL)
	}
	if !strings.Contains(call.SQL, "'pending'") {
		t.Errorf("statement does not write the pending state: %s", call.SQL)
	}
	if got := call.Args[0]; got != principalID.String() {
		t.Errorf("principal_id argument = %v, want %s", got, principalID)
	}
	// A human carries no owner, and the argument must be a SQL NULL rather than an empty
	// string, or the CHECK constraint on the table would reject the row.
	if call.Args[5] != nil {
		t.Errorf("workload_owner argument = %v, want nil for a human", call.Args[5])
	}
	// An absent email must be a SQL NULL rather than an empty string, so a later reader
	// cannot mistake "not supplied" for "supplied as blank".
	if call.Args[3] != nil {
		t.Errorf("email argument = %v, want nil when unsupplied", call.Args[3])
	}
}

func TestInsertPendingPassesWorkloadOwner(t *testing.T) {
	var repo provisioning.Repository
	tx := &dbtest.Tx{Tag: dbtest.CommandTag(1)}

	owner := mustUUID(t)
	err := repo.InsertPending(context.Background(), tx, provisioning.Mapping{
		PrincipalID:   mustUUID(t),
		Realm:         "scnehaux",
		Username:      "nightly-job",
		SubjectType:   keycloak.SubjectWorkload,
		WorkloadOwner: owner,
	})
	if err != nil {
		t.Fatalf("InsertPending: %v", err)
	}
	if got := tx.Only(t).Args[5]; got != owner.String() {
		t.Errorf("workload_owner argument = %v, want %s", got, owner)
	}
}

// TestInsertPendingReportsATakenIdentifier asserts the ON CONFLICT DO NOTHING outcome is
// surfaced rather than swallowed. Zero rows affected means the identifier already exists, and
// treating that as success would leave two callers believing they own it.
func TestInsertPendingReportsATakenIdentifier(t *testing.T) {
	var repo provisioning.Repository
	tx := &dbtest.Tx{Tag: dbtest.CommandTag(0)}

	err := repo.InsertPending(context.Background(), tx, provisioning.Mapping{
		PrincipalID: mustUUID(t),
		Realm:       "scnehaux",
		Username:    "operator",
		SubjectType: keycloak.SubjectHuman,
	})
	if !errors.Is(err, provisioning.ErrIdentifierTaken) {
		t.Fatalf("InsertPending error = %v, want ErrIdentifierTaken", err)
	}
}

func TestInsertPendingRejectsInvalidInput(t *testing.T) {
	var repo provisioning.Repository
	ctx := context.Background()

	cases := map[string]provisioning.Mapping{
		"nil principal_id":     {Realm: "scnehaux", SubjectType: keycloak.SubjectHuman},
		"unknown subject type": {PrincipalID: mustUUID(t), Realm: "scnehaux", SubjectType: "service"},
	}
	for name, mapping := range cases {
		t.Run(name, func(t *testing.T) {
			tx := &dbtest.Tx{Tag: dbtest.CommandTag(1)}
			if err := repo.InsertPending(ctx, tx, mapping); err == nil {
				t.Fatal("InsertPending accepted an invalid mapping")
			}
			if len(tx.Calls()) != 0 {
				t.Errorf("an invalid mapping reached the database: %d statements", len(tx.Calls()))
			}
		})
	}
}

// TestActivateGuardsOnThePendingState is the concurrency assertion. Two recovery workers
// observing one pending row both attempt this; without the predicate the second would
// overwrite the first worker's kernel identifier.
func TestActivateGuardsOnThePendingState(t *testing.T) {
	var repo provisioning.Repository
	tx := &dbtest.Tx{Tag: dbtest.CommandTag(1)}

	err := repo.Activate(context.Background(), tx, mustUUID(t), keycloak.UserID("kc-user-0001"))
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}

	call := tx.Only(t)
	if !strings.Contains(call.SQL, "state = 'pending'") {
		t.Errorf("Activate does not guard on the pending state: %s", call.SQL)
	}
	// Matched on the expression rather than the whole assignment: the statement pads for
	// column alignment, and an assertion that encodes the padding breaks on reformatting
	// while telling you nothing about behaviour.
	if !strings.Contains(call.SQL, "version + 1") {
		t.Errorf("Activate does not advance the version: %s", call.SQL)
	}
}

func TestActivateReportsNotFoundWhenNoRowMatched(t *testing.T) {
	var repo provisioning.Repository
	tx := &dbtest.Tx{Tag: dbtest.CommandTag(0)}

	err := repo.Activate(context.Background(), tx, mustUUID(t), keycloak.UserID("kc-user-0001"))
	if !errors.Is(err, provisioning.ErrNotFound) {
		t.Fatalf("Activate error = %v, want ErrNotFound", err)
	}
}

func TestActivateRequiresAKernelIdentifier(t *testing.T) {
	var repo provisioning.Repository
	tx := &dbtest.Tx{Tag: dbtest.CommandTag(1)}

	if err := repo.Activate(context.Background(), tx, mustUUID(t), ""); err == nil {
		t.Fatal("Activate accepted an empty kernel identifier")
	}
	if len(tx.Calls()) != 0 {
		t.Error("Activate reached the database with an empty kernel identifier")
	}
}

// TestQuarantineRequiresAReason states the property directly: a quarantined Principal is an
// incident record, and one without a reason cannot be triaged by whoever finds it.
func TestQuarantineRequiresAReason(t *testing.T) {
	var repo provisioning.Repository
	tx := &dbtest.Tx{Tag: dbtest.CommandTag(1)}

	if err := repo.Quarantine(context.Background(), tx, mustUUID(t), ""); err == nil {
		t.Fatal("Quarantine accepted an empty reason")
	}
	if len(tx.Calls()) != 0 {
		t.Error("Quarantine reached the database without a reason")
	}
}

func TestQuarantineIsReachableFromPendingAndActive(t *testing.T) {
	var repo provisioning.Repository
	tx := &dbtest.Tx{Tag: dbtest.CommandTag(1)}

	if err := repo.Quarantine(context.Background(), tx, mustUUID(t), "duplicate detected"); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}
	call := tx.Only(t)
	for _, state := range []string{"'pending'", "'active'"} {
		if !strings.Contains(call.SQL, state) {
			t.Errorf("Quarantine is not reachable from %s: %s", state, call.SQL)
		}
	}
}

// TestPendingOlderThanBoundsTheSweep asserts both bounds. The age predicate stops recovery
// racing the request it repairs; the limit stops one sweep enumerating an unbounded backlog.
func TestPendingOlderThanBoundsTheSweep(t *testing.T) {
	var repo provisioning.Repository
	tx := &dbtest.Tx{}

	if _, err := repo.PendingOlderThan(context.Background(), tx, 60_000_000_000, 50); err != nil {
		t.Fatalf("PendingOlderThan: %v", err)
	}

	call := tx.Only(t)
	if !strings.Contains(call.SQL, "state = 'pending'") {
		t.Errorf("sweep does not filter on the pending state: %s", call.SQL)
	}
	if !strings.Contains(call.SQL, "created_at <") {
		t.Errorf("sweep has no age predicate; it would race the creating request: %s", call.SQL)
	}
	if !strings.Contains(call.SQL, "LIMIT") {
		t.Errorf("sweep is unbounded: %s", call.SQL)
	}
	if call.Args[1] != 50 {
		t.Errorf("limit argument = %v, want 50", call.Args[1])
	}
}

func TestPendingOlderThanRejectsANonPositiveLimit(t *testing.T) {
	var repo provisioning.Repository
	tx := &dbtest.Tx{}

	if _, err := repo.PendingOlderThan(context.Background(), tx, 60_000_000_000, 0); err == nil {
		t.Fatal("PendingOlderThan accepted a limit of zero")
	}
	if len(tx.Calls()) != 0 {
		t.Error("an unbounded sweep reached the database")
	}
}

// TestFindRejectsAnUnparseableStoredState asserts that corruption fails loudly. A row whose
// state is not in the machine must not decode into a zero value that later reads as pending.
func TestFindRejectsAnUnparseableStoredState(t *testing.T) {
	var repo provisioning.Repository
	principalID := mustUUID(t)

	tx := &dbtest.Tx{RowValues: []any{
		principalID.String(), "kc-user-0001", "scnehaux", "operator", "", "human", "", "suspended", 1,
	}}

	if _, err := repo.Find(context.Background(), tx, principalID); err == nil {
		t.Fatal("Find accepted a stored state outside the state machine")
	}
}

func TestFindDecodesAMapping(t *testing.T) {
	var repo provisioning.Repository
	principalID := mustUUID(t)
	owner := mustUUID(t)

	tx := &dbtest.Tx{RowValues: []any{
		principalID.String(), "kc-user-0007", "scnehaux", "nightly-job", "job@example.com",
		"workload", owner.String(), "active", 3,
	}}

	mapping, err := repo.Find(context.Background(), tx, principalID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if mapping.PrincipalID != principalID {
		t.Errorf("PrincipalID = %s, want %s", mapping.PrincipalID, principalID)
	}
	if mapping.KeycloakUserID != keycloak.UserID("kc-user-0007") {
		t.Errorf("KeycloakUserID = %q", mapping.KeycloakUserID)
	}
	if mapping.WorkloadOwner != owner {
		t.Errorf("WorkloadOwner = %s, want %s", mapping.WorkloadOwner, owner)
	}
	if mapping.State != provisioning.StateActive {
		t.Errorf("State = %s, want active", mapping.State)
	}
}

func TestRepositoryRefusesANilTransaction(t *testing.T) {
	var repo provisioning.Repository
	ctx := context.Background()

	if err := repo.InsertPending(ctx, nil, provisioning.Mapping{
		PrincipalID: mustUUID(t), Realm: "scnehaux", Username: "operator",
		SubjectType: keycloak.SubjectHuman,
	}); err == nil {
		t.Error("InsertPending accepted a nil transaction")
	}
	if err := repo.Activate(ctx, nil, mustUUID(t), "kc-user-0001"); err == nil {
		t.Error("Activate accepted a nil transaction")
	}
	if err := repo.Quarantine(ctx, nil, mustUUID(t), "reason"); err == nil {
		t.Error("Quarantine accepted a nil transaction")
	}
}
