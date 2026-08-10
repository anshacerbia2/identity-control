# Identity & Tenancy Roadmap

Execution plan for the two Go control-plane deployables and the Keycloak adoption
they depend on. Week numbers are relative to the first build week, not calendar
dates. Owners are roles, not names.

## Position

Architecture is settled and internally consistent. Every TDD resolves to an existing
parent SAD, every authority boundary traces to an EAD, and the two approved standards
(STD-IAM-001 v2.0.0, STD-GLB-002 v2.0.0) support rather than contradict the design.

What remains is not architecture. It is three things: a small set of decisions that
must precede the first migration, a proof-of-concept against a pinned Keycloak
release, and governance metadata that has fallen behind the documents it indexes.

**The proof-of-concept and the build run in parallel.** No proof-of-concept outcome
invalidates the authority schemas, the state machines, the outbox engine, or the
boundary enforcement. Every blocked item is an adapter, and adapters are the cheapest
part to change. Sequencing them would cost two weeks and buy nothing.

## Week 0 — Decisions that precede code

These are decisions, not experiments. None requires Keycloak. Together they are under
one day of work, and all four block the first migration.

| # | Decision | Why it blocks | Owner |
| :-- | :-- | :-- | :-- |
| D-1 | **Row-Level Security design** — which Tenancy tables carry RLS, what the tenant predicate binds to, how the runtime sets it per transaction | TDD-002 asserts RLS and claims STD-GLB-002 conformance, but no design specifies the policy or the context binding. The first migration cannot be written without it | Core Platform + Security |
| D-2 | **Database topology** — two instances, or two logical databases on one managed instance | TDD-002 open question 2. Credential and grant separation hold either way; this is a cost and blast-radius trade-off that the SADs must record | Core Platform + Architecture |
| D-3 | **Manifest placement** — this repository, or beside the SADs in the architecture repository | TDD-002 open question 1. Determines which pipeline enforces it | Architecture |
| D-4 | **Schema naming confirmed** — TDD-003 v0.2.0 adopted the SAD-004 layout (`membership.membership`, `tenant.tenant`, `workspace.workspace`). Confirm and freeze | Migrations encode it permanently | Core Platform |

D-1 is the largest. STD-GLB-002 requires more than switching RLS on: `FORCE ROW LEVEL
SECURITY` on every protected table, a non-owner runtime role, and **cross-tenant
denial proven by a test executed as the actual runtime role**. A test run on an owning
or administrative connection is explicitly not isolation evidence. That test does not
exist in any current TDD and belongs in the same change as the policy.

## Track A — Keycloak proof-of-concept

One engineer, one to two weeks, against a digest-pinned release. Questions run in the
order fixed by the README. Refer to them by name; the numbering is execution order,
not the numbering inside each TDD.

| Order | Question | Blocks | Failure consequence |
| :-- | :-- | :-- | :-- |
| 1 | Protocol mapper coverage | Token profile, verifier invariant | Access token uncovered is the escalation case and the only outcome that can force an extension or a standard amendment. Partial coverage of ID token, UserInfo, or introspection is a TDD-001 relaxation and needs no amendment |
| 2 | Attribute search semantics | Crash recovery in the creation path | Recovery mechanism changes; the creation path itself is unaffected |
| 3 | Attribute immutability | Realm configuration | Falls back to reconciliation detection |
| 4 | Issuer URI form | `iss` in every issued token and every evidence record | Irreversible once tokens are issued. Decide either way before the first token, not before the first line of code |
| 5 | Projected context representation | `KeycloakProjector` | Projector implementation changes; the authority model does not |
| 6 | Session removal granularity | `SessionContainer` | Determines whether revoking one Membership disturbs unrelated contexts |
| 7 | Context switch mechanism | Operator experience | Determines whether a custom extension is required, which changes upgrade burden |

**Question 1 runs first and reports by day three.** It is the only one whose bad news
changes anything beyond an adapter, and bad news is worth having early.

## Track B — Build, starting week 1

One engineer, parallel to Track A. Nothing here waits on a proof-of-concept answer.

### B1 · Repository and enforcement — week 1

Two entrypoints, three internal trees, and the checks that keep them apart. Build the
enforcement before the code it constrains; a boundary added later is a boundary
already violated.

- `cmd/identity-control`, `cmd/tenancy-control`
- `internal/identity`, `internal/tenancy`, `internal/platform`, `contracts/events`
- Import boundary analysis over the package graph, failing the build
- System ownership manifest and its validator
- CI wiring for both

**Exit:** a cross-import between the two trees fails CI, demonstrated by a deliberate
violation in a throwaway branch.

### B2 · Tenancy Database — week 1–2

Atlas migrations under ADR-GLB-004 and STD-GLB-002, run by `tenancy_migrator`.

- Schemas `organization`, `tenant`, `workspace`, `membership`, `invitation`,
  `operation`, `projection`, `platform`
- `membership.membership` with the composite foreign key into
  `workspace.workspace (tenant_id, workspace_id)`, and the `UNIQUE` constraint that
  foreign key depends on
- Partial unique index for one active Membership per subject, context, and type
- `tenant_security_version` and `membership_version`
- RLS policies per D-1, with `FORCE ROW LEVEL SECURITY`
- `tenancy_migrator` and `tenancy_runtime` roles, grant assertion in CI

**Exit:** grant assertion passes; cross-tenant denial proven as `tenancy_runtime`;
dropping the workspace `UNIQUE` constraint fails the migration test.

### B3 · Membership authority — week 2

- Membership state machine, rejecting every transition outside the diagram
- Revocation transaction: status, version increments, and the priority outbox row in
  one commit
- Suspend, restore, and their events
- Acceptance timestamp recorded so enforcement delay is measurable from a fixed origin

**Exit:** injecting a failure between the status change and the outbox write rolls
back both.

### B4 · Outbox and dispatcher — week 2–3

Built once in `internal/platform`, instantiated per deployable against that
deployable's own database.

- `platform.outbox` per database
- Dispatcher with `FOR UPDATE SKIP LOCKED`, database-backed lease, priority ordering
- Broker publication and at-least-once semantics
- Idempotent consumption

**Exit:** a lifecycle backlog of ten thousand rows does not delay a priority event
beyond its budget; two dispatcher replicas produce no duplicate effect and no starved
row.

### B5 · Projection publisher — week 3

- `projection.consumer` registry with declared freshness and stale behavior
- Snapshot generation with a high-water mark, paged, under admission control
- `GET /v1/projections/tenancy/snapshot`, `:reconcile`, consumer status
- Bootstrap contract: registry rejects a cursor with no snapshot mark

**Exit:** a consumer that has not registered receives no projection.

### B6 · Control Database and Principal identifier — week 3

- Schema `identity`, `identity.principal_mapping`, state machine
- `identity.projection_cursor` as this deployable's own consumer position
- UUIDv7 generation, idempotency key claim and replay
- `identity_migrator` and `identity_runtime` roles, grant assertion

**Exit:** a repeated `Idempotency-Key` returns the original identifier and performs no
remote call.

### B7 · Principal creation surface — week 4

- `POST /v1/principals` and the rest of the Principal API
- Keycloak calls behind a port with a fake implementation
- Pending-state recovery loop, with the search strategy left as a seam for Track A
- `keycloak_user_id` absent from every response body

**Exit:** the full creation and recovery test suite passes against the fake.

### B8 · Reconciler skeleton — week 4

- Reconciliation loop obtaining authority through
  `GET /v1/projections/tenancy/snapshot`, never a database read
- `missing`, `extra`, `mismatch` classification, with `extra` raised as a security
  finding
- Negative test: no code path in `identity-control` constructs a Tenancy Database
  connection

**Exit:** reconciliation is idempotent across repeated runs against a consistent state.

## Convergence — week 4 onward

Each item pairs a Track B seam with the Track A answer that fills it.

| Component | Waits on |
| :-- | :-- |
| `KeycloakAdminClient` and the real creation call | Questions 2, 3 |
| Protocol mapper configuration and the verifier invariant | Question 1 |
| `KeycloakProjector` | Question 5 |
| `SessionContainer` | Question 6 |
| Context switch | Question 7 |
| Realm configuration closing self-registration and federated first-login | Questions 3, 4 |

## Track C — Governance closure

Independent of both tracks. Blocks production approval, not development.

| # | Item | State |
| :-- | :-- | :-- |
| G-1 | `ADR-IAM-004` and `ADR-TEN-001` move from `proposed` to `accepted` | Everything being built rests on two unaccepted decisions |
| G-2 | `ADR-IAM-001`, `-002`, `-003` move to `superseded` | Still `accepted` in the index though STD-IAM-001 v2.0.0 has already removed their content |
| G-3 | Resolve three duplicate document IDs: `SAD-004`, `SAD-002`, `PAD-PLT-002` | In the `PAD-PLT-002` pair the superseded document is `approved` and the current one is `draft` |
| G-4 | Regenerate `04-system/INDEX.md`, `05-decisions/INDEX.md`, `03-domain/TRACEABILITY.md` | Generated 2026-08-03. The SAD index points at a file that no longer exists; the ADR index omits both governing ADRs |
| G-5 | Author the **Token & Verification Profile** standard | TDD-001 and TDD-003 both declare a dependency on it. It owns access token lifetime, which is one of the two terms in the enforcement-delay formula. Until it exists the revocation budget cannot be closed |
| G-6 | SADs record the D-2 database topology decision | SAD-001 §5.1 and SAD-004 §6.1 |

G-5 is on the critical path for any revocation claim. STD-IAM-001 §3.2 sets a
15-minute ceiling and refers to an "approved token-lifetime class" that does not yet
exist. TDD-003 works a five-minute revocation target back to a four-minute token
lifetime. Neither number is authoritative until the standard names the classes.

## Gates

**Gate B — designs leave `draft`.** All seven proof-of-concept questions answered
against the pinned release. TDD-001, TDD-002, and TDD-003 to `1.0.0`. Track B exit
criteria met through B8.

**Gate P — production approval.** Gate B, plus: G-1 through G-6 closed; restore
evidence for both databases; cross-tenant denial proven as the runtime role; measured
accept-to-enforcement delay inside budget for all four revocation mechanisms; signing
key custody and rotation rehearsed; runbooks written for revocation not enforced in
budget, priority lane backlog, projection drift, consumer rebuild, and an `extra`
reconciliation finding.

## What this plan refuses to do

- Wait for the proof-of-concept before writing authority schemas.
- Merge the two deployables to save operational cost. The Keycloak Admin credential is
  the most privileged secret in the estate; a module boundary does not contain a
  memory-disclosure or server-side-request defect, and a process boundary does.
- Let a projection become authority, in either direction.
- Report a revocation as enforced when it is only durable and queued.
- Claim a capability before a realizer and a test exist for it.
