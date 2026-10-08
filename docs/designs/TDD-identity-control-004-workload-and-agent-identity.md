---
doc_meta:
  id: TDD-identity-control-004
  title: Workload and Bounded Agent Identity
  owner: Core Platform Team
  version: 1.6.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-11
  last_reviewed: 2026-10-08
  parent_sad: SAD-001
---

# Workload and Bounded Agent Identity

## Purpose

Specify the identity lifecycle for services, jobs, connectors, and governed agents: how
a workload Principal is created, who is accountable for it, what happens when that
person leaves, and how an agent acting on behalf of a human is bounded and remains
distinguishable from that human.

STD-IAM-001 §3.7 states the rules and nothing realizes them:

> Service, workload, automation, and AI-agent identities MUST use non-human credential
> profiles with explicit owner, audience, rotation, and lifecycle.
>
> Shared human credentials or long-lived static secrets are prohibited when a managed
> workload-identity mechanism is available.
>
> Workload identity MUST be distinguishable from human Principal context in audit and
> authorization flows.

## Scope

**In scope**

- Workload Principal creation and its relationship to the human Principal model.
- The accountable owner, and what happens when that owner's access ends.
- Workload Membership and how revocation reaches a workload.
- Bounded agent identity: delegation, its limits, and its audit trail.
- Distinguishability in tokens, audit, and authorization.

**Out of scope**

- The workload's protocol client registration and its credential rotation — owned by
  `TDD-identity-control-003`.
- Membership authority and the revocation transaction — owned by
  `TDD-organization-control-002`.
- Principal identifier minting — owned by `TDD-identity-control-001`, and used
  unchanged here.
- Runtime deployment and where a workload executes.

## Technical Context

**A workload is a Principal.** PAD-PLT-001 defines a Principal as a stable human,
service, workload, or governed-agent security subject, and `membership.membership`
already carries `subject_type IN ('human','workload')` against a `principal_id`. A
workload therefore takes the same identifier, the same minting path, and the same
Membership model as a human.

What differs is everything about its lifecycle:

| | Human Principal | Workload Principal |
| :-- | :-- | :-- |
| Authenticates by | Interactive ceremony, MFA, session | A signed client assertion with its own private key (`private_key_jwt`), no session |
| Accountable to | Themselves | A named human owner |
| Ends when | They leave the organization | It is retired, or its owner leaves and nobody claims it |
| Refresh tokens | Permitted | Prohibited — it re-authenticates instead |
| Step-up | Possible | Meaningless; there is nobody to prompt |

**Its Keycloak user is its client's service-account user.** A workload authenticates as its own
client with the client credentials grant, and that grant issues its token for the user Keycloak
creates with the client, the service-account user, and for no other user. The claim-source
attributes a workload's token carries are therefore that user's, and a user created with
`POST /users` would carry the workload's identity into no token at all. identity-kernel proved it
against the pinned release (`compat/workload_test.go`, identity-kernel#23), and
`TDD-identity-kernel-001` §Claim Projection records it. The human creation path in
`TDD-identity-control-001` therefore refuses a workload, and so does `:relink`.

**Where the workload may act is not decided here.** Every platform with a long record of workload
identity keeps the identity in one home and grants its access by separate bindings: a Google Cloud
service account lives in one project and is granted roles in others, an Entra application has one
home tenant and a service principal in every tenant that uses it, an AWS role lives in one account
and is assumed from others, and a Kubernetes ServiceAccount lives in one namespace and is bound by
RoleBindings elsewhere. Here the binding is a Membership, which organization-control grants and
revokes like any other, and whose grant records who made it. This service creates the identity and
keeps its owner, and needs no Membership data to do either.

The lifecycle difference is the whole problem. **Workloads outlive the people who
create them.** A connector built by an engineer who left two years ago keeps running,
keeps holding credentials, and keeps having nobody who can say whether it should. That
is the failure this design exists to prevent, and it is a lifecycle failure rather than
a cryptographic one.

## Component Design

| Component | Package | Responsibility |
| :-- | :-- | :-- |
| `WorkloadProvisioner` | `internal/workload` | Creates the workload Principal and its registration |
| `OwnershipRegistry` | `internal/workload` | Owner of record, reassignment, orphan detection |
| `AgentDelegationService` | `internal/workload` | Bounded delegation for governed agents |
| `WorkloadReconciler` | `internal/reconcile` | Orphan sweep, unused-workload detection |

**Built so far.** `WorkloadProvisioner` is built: creation, pending-workload recovery, reading a
workload, and rebuilding its client (1.5.0, §Rebuilding a Workload's Client). `OwnershipRegistry` is
built: reassignment, the lifecycle (§Suspension, Restoration, and Retirement), orphan detection and
the owner's periodic review (1.5.0). The `WorkloadReconciler` is built in `internal/workload`
(`sweep.go`), not `internal/reconcile`, because every rule it applies is the workload's: orphan
handling, unused detection and overdue reviews (1.5.0). `AgentDelegationService` is not built, and an
`agent` workload is refused until it is.

### Creation

```mermaid
sequenceDiagram
    participant C as Caller
    participant W as WorkloadProvisioner
    participant R as RegistrationService
    participant D as Control Database
    participant K as Keycloak

    C->>W: Create workload, with owner, purpose, and its public key
    W->>R: Prepare the workload-profile registration: validation, key, managed scope
    W->>D: Begin: claim the Idempotency-Key, check the owner is an active human Principal
    W->>D: Mint principal_id, reserve the registration and its key, record the workload pending
    W->>D: Commit complete local intent
    W->>R: Realize the client, holding the public key
    R->>K: Create the client; attach scnehaux-workload; detach acr
    K-->>R: Client, with its service-account user
    W->>K: Read the client's service-account user (registration credential)
    W->>K: Write principal_id, subject_type=workload, workload_owner on it (Principal credential)
    W->>D: Record the mapping to that user, activate the workload, complete the key
    W-->>C: principal_id and the registration, nothing secret
```

The workload's deployable generates its key pair and keeps the private key in its own secret
custody. The caller supplies only the public key, and nothing secret travels in either
direction (`ADR-IAM-001 §5.12`, `TDD-identity-control-003` §Client Key Records).

The workload's `principal_id` is minted the same way as a human's, a UUIDv7 in the Control
Database, and lives in the same `identity.principal_mapping` registry once its user exists. What
differs is the user: the mapping binds the `principal_id` to the client's service-account user,
written by the Principal credential, rather than to a user `PrincipalProvisioner` creates.

The workload record, its owner, and its client-registration intent are reserved in one Control
Database transaction before either remote call. Recovery can therefore finish a partially realized
workload, but can never discover a workload whose accountable owner was not durably recorded. The
mapping is written only when the service-account user exists, so the human pending-recovery path,
which creates users with `POST /users`, never sees a workload.

**The owner is an active human Principal of this realm.** That is the fact this service owns, and it
is checked when the workload is created and when it is reassigned. A workload cannot own a
workload: accountability that ends at a machine ends nowhere. Whether the owner may act in the
Tenant the workload operates in is a Tenancy fact, decided when organization-control grants the
workload its Membership, and no platform surveyed requires the owner's own membership as a
condition of creating the identity: Entra Agent ID requires a sponsor, which may be a guest, and
CIS 5.5 requires the inventory to name an owner, a purpose and a review date.

**`team_reference`** names the team or group answerable when the owner is not, as Entra's
`serviceManagementReference` and CIS 5.5's department owner do. It is optional, and Microsoft's
guidance to keep at least two owners is met by it rather than by a second owner column.

**Recovery.** Pending workloads are resumed before each registration sweep, after pending
registrations. A workload whose client exists is bound to the client's service-account user. One
whose client was refused, because an unregistered client held its `client_key`, is retired with its
registration. One whose client creation is still unresolved waits for registration recovery. The
creating request's idempotency claim is held on the workload row, so recovery completes it and a
retry of the same request replays the workload rather than waiting on it forever.

**A workload's client is never recreated alone.** An operator's reconcile that would recreate a
deleted client refuses a workload's, because a new client has a new service-account user without the
workload's identity. Rebuilding a workload's client is a workload operation (1.5.0, §Rebuilding a
Workload's Client).

## Data Model

```sql
CREATE TABLE identity.workload (
    principal_id      UUID        PRIMARY KEY,
    registration_id   UUID        NOT NULL UNIQUE REFERENCES identity.client_registration(registration_id),
    display_name      TEXT        NOT NULL,
    purpose           TEXT        NOT NULL,
    workload_type     TEXT        NOT NULL,
    owner_principal_id UUID       NOT NULL,
    team_reference    TEXT,
    owner_recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    state             TEXT        NOT NULL,
    orphaned_at       TIMESTAMPTZ,
    last_seen_at      TIMESTAMPTZ,
    created_by        UUID        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at      TIMESTAMPTZ,
    idempotency_scope TEXT        NOT NULL,
    idempotency_key   TEXT        NOT NULL,
    request_digest    TEXT        NOT NULL,
    version           BIGINT      NOT NULL DEFAULT 1,
    CONSTRAINT workload_type_check
        CHECK (workload_type IN ('service', 'job', 'connector', 'agent')),
    CONSTRAINT workload_state_check
        CHECK (state IN ('pending', 'active', 'orphaned', 'suspended', 'retired')),
    CONSTRAINT workload_named_check CHECK (btrim(display_name) <> '' AND btrim(purpose) <> ''),
    CONSTRAINT workload_owner_not_self_check CHECK (owner_principal_id <> principal_id),
    CONSTRAINT workload_orphaned_check CHECK (state <> 'orphaned' OR orphaned_at IS NOT NULL)
);

CREATE INDEX workload_by_owner ON identity.workload (owner_principal_id) WHERE state <> 'retired';
CREATE INDEX workload_orphaned ON identity.workload (orphaned_at) WHERE state = 'orphaned';

CREATE TABLE identity.workload_owner_change (
    change_id       UUID        PRIMARY KEY,
    principal_id    UUID        NOT NULL REFERENCES identity.workload(principal_id),
    previous_owner  UUID        NOT NULL,
    new_owner       UUID        NOT NULL,
    changed_by      UUID        NOT NULL,
    reason          TEXT        NOT NULL CHECK (btrim(reason) <> ''),
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

A workload is `pending` from its reservation until its identity is bound, and `retired` when its
creation was refused. The idempotency columns hold the creating request's claim so recovery can
complete it. The runtime role deletes no workload row, and `workload_owner_change` is insert-only,
so the record of who answered for a credential at a given time cannot be rewritten by whoever holds
the workload now (`grants.sql`).

```sql
CREATE TABLE identity.workload_finding (                    -- 1.5.0
    finding_id     UUID        PRIMARY KEY,
    principal_id   UUID        NOT NULL REFERENCES identity.workload(principal_id),
    finding_class  TEXT        NOT NULL CHECK (finding_class IN ('unused', 'review_overdue')),
    detected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at    TIMESTAMPTZ,
    resolution     TEXT,
    CHECK ((resolved_at IS NULL) = (resolution IS NULL)
        AND (resolution IS NULL OR resolution IN ('seen', 'reviewed', 'stopped')))
);
CREATE UNIQUE INDEX workload_finding_open ON identity.workload_finding (principal_id, finding_class)
    WHERE resolved_at IS NULL;

CREATE TABLE identity.workload_review (                     -- 1.5.0
    review_id      UUID        PRIMARY KEY,
    principal_id   UUID        NOT NULL REFERENCES identity.workload(principal_id),
    reviewed_by    UUID        NOT NULL,
    statement      TEXT        NOT NULL CHECK (btrim(statement) <> ''),
    reviewed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

A finding is kept after it resolves, and the runtime deletes none. A review is insert-only: the
record that an owner vouched for a credential at a given time is not rewritable by whoever holds the
workload later. Orphaning needs no table of its own: the workload's state and `orphaned_at` are the
record, and the age is read from them.

`purpose` is free text and is required. A workload whose purpose nobody wrote down is a
workload nobody can decide to retire, and the review that should retire it will defer
instead.

`last_seen_at` is updated from authentication events. It is what makes an unused
workload visible, and an unused workload holding a live credential is the cheapest
credential an attacker can find.

### Agent Delegation

```sql
CREATE TABLE identity.agent_delegation (
    delegation_id       UUID        PRIMARY KEY,
    agent_principal_id  UUID        NOT NULL REFERENCES identity.workload(principal_id),
    on_behalf_of        UUID        NOT NULL,
    tenant_id           UUID        NOT NULL,
    scope               TEXT[]      NOT NULL,
    granted_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    correlation_id      UUID        NOT NULL
);
```

Delegation is always time-bounded: `expires_at` is not nullable. An agent acting on
behalf of a human without an expiry is an agent that outlives the intent that created
it.

## API / Interface

```text
POST   /v1/workloads                                   built
GET    /v1/workloads/{principal_id}                    built
POST   /v1/workloads/{principal_id}:reassign           built
POST   /v1/workloads/{principal_id}:suspend           built
POST   /v1/workloads/{principal_id}:restore           built
POST   /v1/workloads/{principal_id}:retire            built
POST   /v1/workloads/{principal_id}:review            built (1.5.0), the owner's
POST   /v1/workloads/{principal_id}:rebuild           built (1.5.0)
GET    /v1/workloads:orphaned                          built (1.5.0)
GET    /v1/workloads:unused                            built (1.5.0)
GET    /v1/workloads:reviews-overdue                   built (1.5.0)
POST   /v1/workloads:sweep                             built (1.5.0)

POST   /v1/agents/{principal_id}/delegations
POST   /v1/agents/{principal_id}/delegations/{delegation_id}:revoke
```

`POST /v1/workloads` takes an `Idempotency-Key` and `display_name`, `purpose`, `workload_type`
(`service`, `job` or `connector`), `owner_principal_id`, an optional `team_reference`, `client_key`,
`application_ref`, an optional `audience`, and `public_key`, the workload's first public key as a
JWK. The creating Principal is the authenticated caller. It answers `201` with the workload, which
names its `registration_id` and carries no kernel identifier and nothing secret. An `agent` is
refused until bounded delegation is built. `:reassign` takes `{"owner_principal_id": ...}` and an
`X-Administrative-Reason`.

1.5.0 adds, every one a provider's at `aal2` but `:review`:

- **`:review`** is the owner's attestation (§Periodic Review). It takes an `X-Administrative-Reason`,
  which is recorded as the owner's statement, and answers the workload. Only the workload's current
  owner may call it, a provider included only when it is that owner; anyone else is answered `404`,
  so a caller cannot learn which workloads exist. The workload must be `active`.
- **`:rebuild`** takes an `X-Administrative-Reason` (§Rebuilding a Workload's Client) and answers the
  workload.
- **Every action requires an `Idempotency-Key` (1.6.0)**, and a retry with it is answered the
  first response (`TDD-identity-control-003` §The Idempotency-Key on Every Command). `POST
  /v1/workloads:sweep` needs none: a repeat finds the same stage.
- **`:orphaned`**, **`:unused`** and **`:reviews-overdue`** list the workloads in each condition,
  oldest first, each with its `principal_id`, `client_key`, `display_name`, owner and the instant the
  condition began: `{"workloads": [...]}`. An orphaned workload carries its `stage`, `reminder`,
  `escalated` or `suspended`.
- **`:sweep`** runs the workload sweep now, as the schedule does, and answers what it did:
  `{"orphaned", "reclaimed", "suspended", "unused", "reviews_overdue"}`.

A workload also carries `last_reviewed_at` and `review_due_at`.

### Token Shape

```json
{
  "iss": "https://identity.scnehaux.com/realms/scnehaux",
  "sub": "<protocol subject>",
  "principal_id": "019236a1-...",
  "subject_type": "workload",
  "workload_owner": "019235f1-...",
  "tenant_id": "019235f2-...",
  "aud": ["hcm-api"],
  "exp": 1786000540
}
```

`tenant_id` appears when the workload holds a Membership and asks for that Tenant in its
client-credentials request with `organization:<tenant_id>` (`ADR-IAM-006 §5.2`,
`TDD-identity-control-002` 2.0.0). `membership_version` left the token in STD-IAM-002 1.6.0. `acr` never appears: the workload's client does not hold
the kernel's built-in `acr` scope (`TDD-identity-control-003` §Profiles).

`subject_type` is what makes a workload distinguishable in audit and authorization, as
STD-IAM-001 §3.7 requires. A product enforcing a rule that applies only to humans reads
that claim rather than inferring from a naming convention.

`workload_owner` carries accountability into the token. An audit record of a workload
action names both the workload and the human answerable for it, without a lookup.

For an agent acting under delegation, the token additionally carries:

```json
{
  "subject_type": "workload",
  "workload_type": "agent",
  "act": { "principal_id": "019235f1-...", "delegation_id": "019236b2-..." }
}
```

`act` names the human the agent is acting for. The agent is the subject, and the human
is the actor behind it — never the reverse. Issuing a token whose `principal_id` is the
human's would make the agent invisible in every downstream audit record.

## Algorithms / Logic

### Orphan Handling

This is the design decision that matters, and both extremes are wrong.

Killing a workload the moment its owner's access ends turns a resignation into a
production outage, and the operators who learn that lesson start using shared service
accounts nobody owns. Never acting leaves credentials owned by nobody, which is the
state the control exists to prevent.

```text
on the owner's Principal being retired, quarantined or disabled:
    for each active workload owned by that Principal:
        set state = 'orphaned', orphaned_at = now()
        notify the owner's administrative chain and the workload's Tenant admins
        the workload keeps operating

daily sweep over orphaned workloads:
    age < 7 days     → reminder
    age >= 7 days    → escalate to the Tenant administrator
    age >= 30 days   → suspend the workload, notify, keep the record

on reassign:
    validate the new owner is an active human Principal, and not the current owner
    write the new owner on the workload's service-account user
    set owner, clear orphaned_at, state = 'active'
    record the change, with who made it and why, insert-only
    emit a privileged-administration event (once this service publishes events)
```

**The trigger is the owner's identity ending, not a Membership.** An owner who leaves one Tenant but
stays in the organization is a mover, not a leaver. Whether the workload may still act in that Tenant
is organization-control's decision about the workload's own Membership; the workload is not orphaned
by it. Entra's lifecycle workflows treat a sponsor's move the same way, by transferring and
notifying rather than disabling.

**The schedule is stricter than the platforms' defaults, and within the standard.** None of Google
Cloud, Entra or AWS disables a workload identity when its owner leaves; they flag ownerless
identities, notify co-owners and managers, and review. NIST SP 800-53 AC-2(3)(b) requires accounts to
be disabled within an organization-defined period once they are no longer associated with an
individual, and the thirty-day suspension is that period. It is reversible, so the control does not
become an outage.

The workload keeps running while orphaned. That is deliberate: the grace period buys
the reassignment that ought to happen, and the escalation makes ignoring it
progressively harder. Suspension at thirty days is the backstop, and it is reversible.

**As built (1.5.0).** The owner is a Principal of this service, so its end is read from this
service's own record rather than awaited as an event: the workload sweep, every
`IDENTITY_WORKLOAD_SWEEP_INTERVAL` and on `POST /v1/workloads:sweep`, orphans every active workload
whose owner's mapping is not `active`. `retired` and `quarantined` are the `TDD-identity-control-001` states of an owner
whose identity ended or broke, and `suspended` is the one a provider's containment leaves, the kernel
user disabled (`TDD-identity-control-005`). A day's sweep is well inside a thirty-day grace period.

- **The reminder and the escalation are alerts.** Under seven days the sweep logs a `WARN` naming
  the workload and its owner; from seven days, an `ERROR`. Telling the owner's administrative chain
  and the Tenant's administrators needs the Notification Platform, and knowing who a Tenant's
  administrators are is organization-control's, so neither is sent from here yet; the log line and
  `GET /v1/workloads:orphaned` are the signal.
- **Thirty days suspends**, through the lifecycle above, recorded `automatic` in
  `registration_state_change` with the rule as its reason (`TDD-identity-control-003` 1.34.0). It
  is reversible: a provider reassigns, then restores.
- **An owner restored before then reclaims the workload.** A provider's restore of a suspended owner
  (`TDD-identity-control-005`) makes the same person answerable again, and reassigning a workload to
  the owner it already has is refused. So an orphaned workload whose owner's mapping is `active` again
  returns to `active` at the next sweep, `orphaned_at` cleared, logged at `WARN`. A reassignment
  remains the way to move it to anyone else.

### Revocation Reaching a Workload

A workload holds no session and no refresh token, so two of the four human revocation
mechanisms do not apply. Two do:

| Mechanism | Effect |
| :-- | :-- |
| Context projection removed | The next client-credentials exchange cannot assert the revoked context |
| Consumer read model updated | An already-issued access token naming the revoked context is rejected |

Enforcement is therefore bounded by the propagation time plus the remaining access
token lifetime of class `L3`, which STD-IAM-002 §3.3 sets at nine minutes for the
`workload` audience. A workload cannot extend that by refreshing, because refresh tokens
are prohibited for the `workload` profile in `TDD-identity-control-003`.

Two earlier revisions got this wrong in opposite directions, and the reason is worth
recording: the class letters were reassigned while two rewrites of STD-IAM-002 ran in
parallel. One revision named `L3` believing it was external; a later one "corrected" it to
`L1` against the other rewrite, where `L3` was indeed external. In the standard as merged,
`L2` is the external and partner class and `L3` is the workload class, both at the lifetimes
above. `TDD-identity-experience-004` has carried the merged table correctly throughout.

**A lifetime class MUST be cited together with its audience, never by letter alone.** Citing
`L3` by itself resolved to a real class saying something else, so neither the linter nor a
reviewer had anything to catch: a reference that resolves to the wrong text fails silently,
while a dangling one at least fails.

Suspending a workload also disables its client, which stops the next exchange outright.
A compromised workload key is revoked instead: its public key is removed from the client, and
the kernel refuses it on the next request (`TDD-identity-control-003` §Client Key Rotation).

### Suspension, Restoration, and Retirement

A workload stops the way a registration does (`ADR-IAM-001 §5.13`): a suspension that can be undone,
and a retirement only after one. Its client cannot be stopped through the registration lifecycle,
which refuses a workload's client (`TDD-identity-control-003`), because the client and the
Principal stop together: deleting the client deletes its service-account user, and that user is
the workload's Principal in the kernel.

| Action | From | Workload | Its registration and client | Its Principal |
| :-- | :-- | :-- | :-- | :-- |
| `:suspend` | `active`, `orphaned` | `suspended` | suspended: the client disabled and its not-before set | unchanged |
| `:restore` | `suspended` | `active` | active: the registered keys, redirect URIs and lifespan written, the client enabled | unchanged |
| `:retire` | `suspended` | `retired` | retired: its keys removed and revoked, the client deleted | mapping `retired` |

```text
suspend(workload, reason):
    lock the workload; refuse unless active or orphaned
    suspend its registration in the same transaction        -- recorded before the kernel
    record the workload suspended
    commit, then disable the client and set its not-before  -- the sweep converges a failure

restore(workload, reason):
    lock the workload; refuse unless suspended
    refuse unless its owner is still an active human Principal: reassign first
    restore its registration, writing the client, in the same transaction
    record the workload active, its orphaned_at cleared

retire(workload, reason):
    lock the workload; refuse unless suspended
    retire its registration, deleting the client, in the same transaction
    record the Principal's mapping retired
    record the workload retired
```

- **A suspension changes the kernel after it commits**, as a registration's does: the record is
  desired state, and a kernel call that fails leaves a suspended registration the sweep disables.
  A restore and a retirement change the kernel inside the transaction that records them, so a
  failure leaves the workload suspended. Every failure errs toward the stop.
- **An access token already issued lives out its class.** The `workload` audience's `L3` lifetime
  is nine minutes (STD-IAM-002 §3.3), and a workload holds no refresh token, so a suspension stops
  the next client-credentials exchange and every token within nine minutes.
- **A restore needs an owner.** Restoring a workload whose owner has left would put a credential back
  into use that nobody answers for, which is what an orphan is. The owner is reassigned first, then
  the workload restored.
- **A retirement retires the Principal.** Its mapping moves to `retired`, the terminal state of
  `TDD-identity-control-001`, so the dangling sweep, which reads active mappings, does not report a
  Principal whose kernel user was deleted on purpose. The `principal_id` is never reissued, and every
  record naming it stays.
- **Every action requires `X-Administrative-Reason`.** The change is recorded in the registration's
  insert-only `registration_state_change`, which names who asked and why; a workload and its
  registration are one-to-one, so that history is the workload's.
- **A retirement is offered only after a suspension**, for the reason `ADR-IAM-001 §5.13` gives,
  from Google Cloud's and AWS's guidance on service accounts and access keys: a dependency nobody
  knew about breaks during the suspension, while the workload can still be restored.

### Unused Workload Detection

```text
weekly sweep:
    for each active workload where last_seen_at is older than the unused threshold:
        record an unused finding
        notify the owner
```

**As built (1.5.0).** `last_seen_at` is written by the kernel event record from each successful
`CLIENT_LOGIN` of the workload's service-account user (`TDD-identity-control-007` 1.1.0). A workload
never seen is measured from its activation, so one created and never used is found too. The check
runs in the workload sweep, daily rather than weekly: the finding is opened once, so the cadence only
decides how soon it appears. "Notify the owner" is a `WARN` naming the workload and its owner, for the
reason the orphan reminder is one. The finding resolves `seen` once the workload authenticates again,
and `stopped` once it is suspended or retired.

An unused finding is not automatic retirement. A quarterly job legitimately sits idle
for eighty-nine days. The finding puts the decision in front of the owner, who is the
only party who can make it.

Ninety days is the window Google Cloud's service account insights and Entra's unused-application
recommendation use. CIS 5.3 asks for forty-five, which would flag a quarterly job every quarter. The
order after a decision is the platforms' too: disable first, delete only after a grace period, as
Entra's fifteen-day wait and Google Cloud's thirty-day undelete window do.

### Periodic Review

Every workload is reviewed by its owner at least quarterly: whether it is still needed, whether its
purpose still holds, and whether its owner and team are right. CIS 5.5 requires the service-account
inventory to name the owner, the purpose and a review date, reviewed at least quarterly, and NIST
SP 800-53 AC-2(j) requires accounts to be reviewed at a defined frequency. An overdue review is a
finding for the owner and then the Tenant administrator, on the orphan escalation's path. The review
record and its schedule are built in 1.5.0:

- **The owner attests** with `POST /v1/workloads/{principal_id}:review`, its statement as the reason,
  and the review is recorded insert-only in `identity.workload_review`. A review confirms the three
  things hold. One that does not hold is changed by what changes it: `:reassign` for the owner, a
  provider's `:suspend` and `:retire` for a workload no longer needed. A review is an owner's word,
  recorded with who gave it, which is what CIS 5.5's review date stands for.
- **A review is due** `IDENTITY_WORKLOAD_REVIEW_INTERVAL` after the last one, or after activation.
  Past it, the sweep opens a `review_overdue` finding and logs a `WARN` for the owner; seven days past
  it (`IDENTITY_WORKLOAD_ORPHAN_ESCALATE_AFTER`), an `ERROR` for the Tenant's administrators, on the
  orphan escalation's path. A review resolves it `reviewed`, and a suspension or retirement `stopped`.
- **An overdue review suspends nothing.** CIS 5.5 and AC-2(j) ask for the review, not for an
  automatic consequence of missing it, and suspending a running workload because a form was late is
  the outage §Orphan Handling avoids. The owner who stops answering is the orphan case, which does
  suspend.

### Rebuilding a Workload's Client

A workload's client deleted in the console takes its service-account user with it, and with it the
workload's identity in the kernel: the registration sweep holds the client `missing`, and the
Principal sweep reports the mapping dangling. An operator's reconcile refuses to recreate it, because
a recreated client's new service-account user would carry no `principal_id`. `:rebuild` is the
workload's own recreation, with a reason (1.5.0):

```text
rebuild(workload, reason):
    refuse unless the workload is active or orphaned                    409
    read its client; refuse while the kernel holds it                   409
    an unknown answer is not an absent client                          503
    lock the workload and its registration
    create the client from desired state, with its active and retiring keys, and scope it
    read the new client's service-account user; write the workload's identity on it
    bind the mapping to that user, recording the move in principal_relink with who and why
    record the registration's new client; its open 'missing' finding becomes 'recreated'
    resolve the mapping's open dangling finding as 'relinked'
    commit; on any failure after the client was created, delete that client and roll back
```

- **The same `principal_id`, the same keys.** Every Membership and record naming the workload stays
  valid, and the key pairs that authenticated it before authenticate it again, and no other, as an
  operator's recreation of any other client does.
- **Not for a suspended workload.** Its client is held disabled; a suspended workload whose client is
  gone is retired, as a suspended registration whose client is gone is
  (`TDD-identity-control-003` §Suspension, Restoration, and Retirement).
- **Why the kernel is written inside the transaction.** A rebuild that committed its record and then
  failed to create the client would point the mapping at nothing; one that created the client and then
  failed to commit would leave a client no record knows. Creating inside the transaction and deleting
  the client on the way out of a failure leaves neither: a client that is created and then outlives a
  failed commit is held by the registration's `client_key`, which the next rebuild refuses until an
  operator deletes it, so a failure errs toward a stop, as every lifecycle path here does.
- **The Principal sweep does not take a rebuild in flight for a duplicate.** The new service-account
  user carries the workload's `principal_id` before the mapping is bound to it, while the old user is
  gone, which `TDD-identity-control-001` 1.13.0 reads as a rebind rather than a second user.

### Agent Delegation

```text
grant(agent, on_behalf_of, tenant, scope, duration):
    reject if duration exceeds the ceiling
    reject if the human has no active Membership in the tenant
    reject if the scope exceeds what the human holds
    reject if the scope exceeds what the agent is permitted to hold
    persist the delegation with a correlation identifier
    emit a privileged-administration event
```

The scope is the intersection of what the human holds and what the agent may hold,
never the union and never just the human's. An agent that can do everything its
principal can do is not bounded, and PAD-PLT-001 requires bounded agent identity rather
than impersonation.

A delegation is revoked when the human's Membership is revoked, on the same priority
event that revokes the human.

## Configuration

| Variable | Default | Purpose |
| :-- | :-- | :-- |
| `IDENTITY_WORKLOAD_ORPHAN_ESCALATE_AFTER` | `168h` (7 days) | First escalation, of an orphan and of an overdue review |
| `IDENTITY_WORKLOAD_ORPHAN_SUSPEND_AFTER` | `720h` (30 days) | Automatic suspension |
| `IDENTITY_WORKLOAD_UNUSED_THRESHOLD` | `2160h` (90 days) | Unused finding threshold |
| `IDENTITY_AGENT_DELEGATION_MAX_DURATION` | `24h` | Ceiling on one delegation |
| `IDENTITY_WORKLOAD_SWEEP_INTERVAL` | `24h` | Orphan, unused and review sweep cadence |
| `IDENTITY_WORKLOAD_REVIEW_INTERVAL` | `2160h` (90 days) | Periodic owner review |

They are Go durations, so the days are written in hours. The escalation must be shorter than the
suspension, and both positive; a misconfiguration is refused at startup. Every one but the delegation
ceiling is read from 1.5.0; delegation is not built.
Pending-workload recovery runs on the registration sweep's schedule
(`IDENTITY_REGISTRATION_RECONCILE_INTERVAL`) and uses `IDENTITY_PENDING_RECOVERY_AFTER`.

## Testing Strategy

### Identity Model

- A workload carries a `principal_id` minted the same way as a human's.
- Its Keycloak user is its client's service-account user: the identity is written there, the
  mapping points there, and no user is created with `POST /users`.
- Its token carries `subject_type = workload` and `workload_owner`, and no `acr`, asserted against
  a real kernel by the `deploy-dev` smoke.
- A crash after the client exists and before the identity is bound recovers from the same
  ownership and registration intents without creating a second Principal or client, and a retry
  of the creating request then replays the workload.
- A client creation that never landed is created by registration recovery and then bound.
- No Keycloak workload client exists before its local ownership intent commits.
- The human creation path and `:relink` refuse a workload.
- A workload Membership is created, verified, and revoked through the same path as a
  human Membership, distinguished only by `subject_type`.
- The `workload` client profile is refused a refresh token.

### Ownership

- Creating a workload whose owner is not an active human Principal is refused, and records nothing.
- A workload cannot own a workload, or itself.
- Revoking the owner's Membership marks every workload they own `orphaned`, and none of
  them stops working.
- Escalation fires at the configured ages.
- Suspension at thirty days is applied, is reversible, and keeps the record, recorded `automatic`.
- An owner suspended, quarantined or retired orphans the workload, which keeps working; the owner
  restored before thirty days reclaims it.
- A workload unused past the threshold is found once, and resolved when it authenticates again; a
  successful `CLIENT_LOGIN` moves `last_seen_at`.
- A review is the owner's alone, is recorded insert-only, and resolves an overdue finding; an overdue
  review suspends nothing.
- A rebuild refuses while the client exists, creates one holding the registered keys, binds the
  mapping to its service-account user under the same `principal_id`, and leaves nothing behind when
  it fails.
- Reassignment to a principal that is not an active human is refused; a reassignment the kernel
  refuses changes nothing; one that succeeds names the new owner on the record, the mapping and
  the service-account user, and records who and why.

### Revocation

- After context projection removal, a client-credentials exchange cannot assert the
  revoked context.
- Measured enforcement stays within propagation plus the class `L3` lifetime.
- Suspending a workload disables its client, and the next exchange fails.
- `:suspend` is refused for a `pending`, `suspended` or `retired` workload; `:restore` and `:retire`
  for one that is not `suspended`. A repeat of a suspension changes nothing.
- A restore writes the registered keys back and enables the client, and is refused while the owner
  is not an active human Principal.
- A retirement deletes the client, revokes its keys, and retires the Principal's mapping, which the
  dangling sweep then does not report.
- A lifecycle action without a reason is refused, and each one is recorded with who asked and why.
- The registration lifecycle still refuses a workload's client.
- Revoking a workload's key makes the next assertion signed with it fail.

### Agents

- A delegation exceeding the duration ceiling is refused.
- A delegation whose scope exceeds the human's scope is refused.
- A delegation whose scope exceeds the agent's permitted scope is refused.
- The agent's token names the agent as subject and the human in `act`, never the
  reverse.
- Revoking the human's Membership revokes every delegation granted on their behalf.

### Negative

- No workload shares a credential with a human Principal.
- An unused finding does not retire a workload automatically.
- A workload cannot be created with an empty `purpose`.

## Security Notes

The accountability chain is the control. A credential whose owner cannot be named is a
credential nobody will ever decide to revoke, and the reason long-lived service
accounts accumulate is not that anyone chose them but that nobody owned the decision to
remove them.

Carrying `workload_owner` in the token puts that chain in every audit record without a
lookup, so an investigation reading logs sees who is answerable without joining against
a registry that may itself be stale.

The orphan grace period accepts a bounded window in which a workload runs under an
owner who has left. That window is chosen against the alternative: an immediate kill
teaches operators to avoid owned workloads entirely, and shared unowned accounts are
strictly worse than a thirty-day orphan.

Agent delegation is intersection, not inheritance. An agent that holds exactly what its
principal holds is impersonation with extra logging, and the `act` claim exists so that
downstream systems can apply a different rule to an agent than to the human.

## Performance Notes

Workload creation is administrative. Client-credentials exchange happens in the kernel
and does not reach this service.

The orphan and unused sweeps are indexed queries over a population that is small
relative to human Principals, and run daily and weekly rather than continuously.

`last_seen_at` is updated from authentication events already consumed for other
purposes, so it adds a write per workload per authentication rather than a new stream.

## Operational Notes

| Signal | Warning | Critical |
| :-- | :-- | :-- |
| Orphaned workloads | any occurrence | older than the escalation threshold |
| Workloads suspended for orphan age | any occurrence | — |
| Unused workloads past threshold | any occurrence | — |
| Agent delegation refused for scope excess | any occurrence | sustained from one agent |
| Workload without a recorded purpose | — | any occurrence |

Runbooks required before production: orphaned workload reassignment, workload
credential compromise, agent delegation review, and unused workload retirement.

## Traceability

| Relationship | Target |
| :-- | :-- |
| Parent system | SAD-001 — Scnehaux Identity Runtime |
| Realizes capability | PAD-PLT-001 — machine, service, workload, and bounded agent identity |
| Governed by | ADR-IAM-001 — the kernel owns credential storage and protocol grants |
| Conforms to | STD-IAM-001 §3.7 — explicit owner, audience, rotation, lifecycle; distinguishable in audit; no shared human credentials |
| Conforms to | STD-IAM-002 §3.1, §3.2 — the `workload` audience class carries `principal_id`, `subject_type`, and `workload_owner` |
| Enterprise constraint | EAD-006 — agents receive bounded delegated authority, not unrestricted user power |
| Depends on | `TDD-identity-control-001` — the workload Principal is minted through the same path |
| Depends on | `TDD-identity-control-003` — the workload's client registration and credential rotation |
| Depends on | `TDD-organization-control-002` — workload Membership and its revocation |
| Depends on | `TDD-identity-kernel-001` §Claim Projection — a workload's claim source is its client's service-account user, and its client holds no `acr` scope |
| Conforms to | NIST SP 800-53 Rev. 5 AC-2(3)(b), AC-2(j) — disable within a defined period once unowned; review at a defined frequency |
| Conforms to | CIS Controls v8 5.5 — service-account inventory with owner, purpose and review date, reviewed at least quarterly (`STD-IAM-001` [R19]) |
| Conforms to | NIST SP 800-53 Rev. 5 AC-2(j) — review at a defined frequency (`ADR-IAM-003` [R3]) |
| Evidence | Google Cloud, Microsoft Entra, AWS IAM and Kubernetes documentation on workload-identity scope, ownership, leavers and unused identities, surveyed 2026-09-30 |
