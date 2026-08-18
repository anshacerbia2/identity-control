# Identity Control Service — Roadmap

Execution tracker for this repository only. It records which technical designs exist,
which are blocked, and what is buildable today. Architecture lives in
`scnehaux-architecture`; nothing here overrides a SAD, an ADR, or a standard.

Week numbers are relative to the first build week, not calendar dates.

## Design status

| TDD | Subject | Status |
| :-- | :-- | :-- |
| `TDD-identity-control-001` | Canonical Principal identifier and creation path | approved; implementation-gated by PoC |
| `TDD-identity-control-002` | Keycloak context projection, durable retry, session removal | approved; implementation-gated by PoC |
| `TDD-identity-control-003` | Protocol client and protected-resource registration | approved |
| `TDD-identity-control-004` | Workload and bounded agent identity | approved |
| `TDD-identity-control-005` | Account-security and investigation API mediation | approved |

Two documents inherited from the former monorepo still sit in `docs/designs` under
their old names and old premises. They are removed once their content has landed in
its new home:

| Inherited file | Disposition |
| :-- | :-- |
| `TDD-001-principal-identifier-and-creation.md` | Done. Renamed to `TDD-identity-control-001`; realm configuration became a stated dependency on `identity-kernel` rather than an instruction issued from here |
| `TDD-002-control-plane-module-boundaries.md` | Awaiting removal. Its premise was two deployables sharing one repository, which no longer holds. Database separation, runtime roles, and credential containment survive inside the designs that own them |
| `TDD-003-membership-projection-and-revocation.md` | Awaiting removal. Authority, versions, and the revocation transaction landed in `TDD-organization-control-002`; the projector, session removal, and reconciler landed in `TDD-identity-control-002` |

## Cross-repository dependency

`foundation-platform` lands first. This service imports its outbox, dispatcher, event
envelope, idempotency, and problem-details packages from day one, and reimplementing
any of them here would produce a second revocation enforcement interval while both
services reported compliance.

`identity-kernel` is a parallel track, not a predecessor. Keycloak calls in this
service sit behind a port with a fake implementation, so the full creation and
recovery suite runs before the kernel repository produces anything.

## Buildable now

Nothing in this group waits on a proof-of-concept answer or on another repository
beyond `foundation-platform`.

### Week 1 · Skeleton and Control Database

- ✅ `cmd/identity-control` entrypoint and composition root
- ✅ `foundation-platform v0.1.0` wired: pool, transaction manager, telemetry
- ✅ Atlas migrations for the `identity` schema; the `platform` schema applied from the
  shared module rather than re-authored here
- ✅ `identity.principal_mapping` with its state machine and partial unique index
- ✅ `identity.projection_cursor` as this service's own consumer position
- ✅ `identity_migrator` and `identity_runtime` roles, asserted against the catalog

**Exit:** the runtime role owns no table, holds no `SUPERUSER`, no `BYPASSRLS`, and no
DDL privilege, proven by assertion rather than by review.

**Met.** `internal/controldb` asserts it against `pg_roles`, `pg_tables`,
`information_schema.schemata`, and `has_schema_privilege` — seven tests, run in CI with
`REQUIRE_INTEGRATION=1` so a database that never came up fails the build instead of
skipping. The suite reads the catalog rather than the SQL that built it, because the
privilege this criterion guards against is one arriving from somewhere else: a restored
dump, a hand-run `GRANT`, a role that predates these files.

#### Findings recorded while building it

| Finding | Consequence |
| :-- | :-- |
| Atlas in database scope planned `DROP SCHEMA "public" CASCADE`, and would have planned the same for `platform` | Both urls carry `search_path=identity`. The `identity` schema object is created by `identity-migrate -stage=pre`, because a schema-scoped plan may not modify the schema it is scoped to |
| `GRANT ... ON ALL TABLES IN SCHEMA` over an empty schema is a no-op, not an error | `grants.sql` opens with a guard that raises when its objects are absent. Without it the stage reported success and granted nothing, and the failure surfaced as a runtime that could not read its own tables |
| `atlas migrate lint` is Atlas Pro only since v0.38 | ADR-GLB-004 names it as the destructive gate, so the mandated mechanism cannot run on the free CLI. CI runs `atlas migrate validate`, which is free and checks directory integrity, plus a text-level destructive gate standing in for the analyzer. **This is debt.** Resolving it means an Atlas Pro login with a CI token, or amending ADR-GLB-004 |
| `TDD-identity-control-001` specifies both `keycloak_user_id UNIQUE` and a partial unique index on `(realm, keycloak_user_id)` | The first is strictly stronger, so the second adds nothing. Both are implemented as specified; the redundancy is recorded here rather than resolved in the schema |
| Atlas requires the target schema to exist on the dev server before any schema-scoped command | CI creates it on the throwaway dev container before Atlas runs. Absent, the first Atlas step fails with `schema "identity" was not found`, which reads like a broken migration |

### Week 2 · Principal creation path

- ✅ UUIDv7 generation and idempotency key claim
- ✅ `POST /v1/principals`, with the rest of the Principal surface still to land
- ✅ Keycloak behind a port, with a fake covering create, search, and disable, and the real
  Admin REST client implementing it
- ✅ Pending-state recovery loop, with the search strategy left as a seam
- ✅ `keycloak_user_id` absent from every response body, asserted at the type level and over
  the wire

**Exit:** a repeated `Idempotency-Key` returns the original identifier and performs no
remote call; process termination between the remote call and the local commit recovers
without creating a second Principal.

**Met.** Both are tests. The second runs end to end: the kernel create succeeds, the
activation commit fails, recovery finds the user and adopts it, and the assertion is that
`CreateUser` ran exactly once across both phases.

**The proof-of-concept question did not gate this.** Week 2 was recorded as
implementation-gated on whether Keycloak attribute search is exact-match. It is not: the
answer changes what the kernel returns for a query rather than what this service does about
it. `FindByPrincipalID` returns a slice, both the port and the real client filter to exact
equality, and the recovery algorithm already branches on none, one, and more than one. A
`SearchSemantics` switch in the fake runs the same assertions under the pessimistic reading.

#### Deliberately absent: authentication

`POST /v1/principals` is wired and **fails closed with 401**. No token verifier exists yet,
so no request carries a caller scope and every mutation is refused.

A development mode trusting a header would have made the route usable today and is not
offered. A permissive authentication path that exists in one environment is a permissive path
that reaches production, and `EAD-006 §8` requires a security-control failure to fail closed.
The startup log states the reduced capability so an operator is never left guessing why a
request is refused.

Verifying a token means fetching JWKS, checking `PS256`, and applying the whole
`STD-IAM-002 §3.5` checklist including the rule that `principal_id` must be present for an
internal audience. That is its own increment.

#### Findings recorded while building it

| Finding | Consequence |
| :-- | :-- |
| `identity.principal_mapping` stored no username, so the recovery retry branch was unwritable | The row now carries the creation payload. Without it, a create failing after the key was claimed left that key in-progress permanently, and the caller retrying with the same key would receive `ErrInProgress` forever with no path out. Recorded as a departure in TDD-identity-control-001 |
| `RecoverPending` originally took a `CreateRequest` | A sweep resolves many mappings from different requests, so one caller's username would have been applied to all of them. It now reads the payload from each row |
| TDD-identity-control-004 assigned a workload lifetime class `L3` | `L3` is the external class and its claim profile omits `workload_owner`, which would make the accountability chain unreadable at the verifier. Corrected to `L1` |
| foundation-platform's problem registry carries no in-progress type | A request duplicating one still in flight maps to `state-transition-refused`, which returns the correct 409 with a slightly wrong name. The registry is compiled and deliberately prevents a handler inventing a type, so this wants a `request-in-progress` entry upstream |
| A transport failure on a create cannot be distinguished from a lost response | The Admin client classes every statusless mutation as `ErrAmbiguous` and every statusless read as `ErrUnavailable`. Being wrong toward ambiguous costs one extra search; being wrong the other way creates a second Principal |

### Week 3 · Event translation and consumption

- Publication of `com.scnehaux.identity.*` through the shared outbox
- Consumption of `com.scnehaux.organization.membership.*` and `...tenant.*`
- Deduplication guard on every consumed event
- Reconciler skeleton reading authority through the published snapshot contract, never
  through a database connection

**Exit:** no code path in this service constructs an Organization Database connection,
asserted by test.

## Waiting on the Keycloak proof-of-concept

Each item names the question that unblocks it. All of them are adapters, which is why
none of them blocks the work above.

| Component | Blocked by |
| :-- | :-- |
| `KeycloakAdminClient` create and search | Attribute search semantics — is `q=scnehaux_principal_id:{id}` exact-match, and how does it paginate |
| Pending-state recovery strategy | Attribute search semantics |
| `KeycloakProjector` | Projected context representation — Organizations, Groups, or user attributes |
| `SessionContainer` | Session removal granularity — per Principal and Tenant context, or per Principal only |

The remaining proof-of-concept questions — protocol mapper coverage, attribute
immutability, issuer URI form, context switch mechanism — are answered in
`identity-kernel` and change realm configuration rather than code here.

## Not this service

Recorded so scope creep is visible rather than convenient:

- Authentication, token issuance, session engine, credential storage — Keycloak.
- Organization, Tenant, Workspace, Membership authority — `organization-control`.
- Product authorization — the owning Product domain.
- Enterprise evidence retention — Audit & Evidence.

## Gates

**Design gate.** Every TDD in the status table reaches `1.0.0`, with each open
proof-of-concept question answered against the pinned Keycloak release.

**Production gate.** The design gate, plus: restore evidence for the Control Database,
measured accept-to-enforcement delay inside budget for projection removal and session
removal, Keycloak administration credential rotation rehearsed, and runbooks written
for unmapped-Principal triage, duplicate-identifier containment, pending-mapping
recovery, and projection drift repair.
