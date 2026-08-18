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

Pinned at `v0.2.1`. `v0.2.0` shipped a platform migration set that could only be applied
once; see the findings table under Week 2½.

`identity-kernel` is a parallel track, not a predecessor. Keycloak calls in this
service sit behind a port with a fake implementation, so the full creation and
recovery suite runs before the kernel repository produces anything.

That said, the realm shape is no longer hypothetical here. `scripts/dev-keycloak.ps1` encodes
what `ADR-IAM-001` and `STD-IAM-002` require of a realm — the PS256 key, the declared
attributes, the narrow service-account roles, the protocol mappers — and `identity-kernel`
should be read as the authority on all of it. Two of those settings are not merely
recommended: without them the verifier rejects every token, silently in one case.

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

#### Authentication

✅ Landed. `foundation-platform/verify` performs the `STD-IAM-002 §3.5` checklist and this
service supplies the one rule the shared module is forbidden from naming: `principal_id` must
be present for an internal audience, expressed as a `verify.ClaimRequirement`. The verifier
refuses to be constructed without one.

No development mode trusting a header was ever offered. A permissive authentication path that
exists in one environment is a permissive path that reaches production, and `EAD-006 §8`
requires a security-control failure to fail closed.

The caller scope is `"principal:" + principal_id`, so an idempotency key is always claimed
under an authenticated caller rather than globally.

#### Findings recorded while building it

| Finding | Consequence |
| :-- | :-- |
| `identity.principal_mapping` stored no username, so the recovery retry branch was unwritable | The row now carries the creation payload. Without it, a create failing after the key was claimed left that key in-progress permanently, and the caller retrying with the same key would receive `ErrInProgress` forever with no path out. Recorded as a departure in TDD-identity-control-001 |
| `RecoverPending` originally took a `CreateRequest` | A sweep resolves many mappings from different requests, so one caller's username would have been applied to all of them. It now reads the payload from each row |
| TDD-identity-control-004 assigned a workload lifetime class `L3` | `L3` is the external class and its claim profile omits `workload_owner`, which would make the accountability chain unreadable at the verifier. Corrected to `L1` |
| foundation-platform's problem registry carries no in-progress type | A request duplicating one still in flight maps to `state-transition-refused`, which returns the correct 409 with a slightly wrong name. The registry is compiled and deliberately prevents a handler inventing a type, so this wants a `request-in-progress` entry upstream |
| A transport failure on a create cannot be distinguished from a lost response | The Admin client classes every statusless mutation as `ErrAmbiguous` and every statusless read as `ErrUnavailable`. Being wrong toward ambiguous costs one extra search; being wrong the other way creates a second Principal |

### Week 2½ · Running it

The service now runs locally against a real PostgreSQL and a real Keycloak 26.7.1, and
`docs/run.md` is the whole procedure. `scripts/dev-keycloak.ps1`, `scripts/dev-database.ps1`,
and `scripts/dev-smoke.ps1` are idempotent and read every secret from the environment, so
nothing sensitive is in the repository.

The smoke suite asserts governance properties rather than a happy path: an unauthenticated
mutation is refused, the probes answer without a credential, only `PS256` is accepted, a
replayed `Idempotency-Key` returns the same identifier with no second kernel call, a workload
without an accountable owner is refused, and a client-supplied `keycloak_user_id` is refused.

#### What running it found that no test could

| Finding | Consequence |
| :-- | :-- |
| `chain(routes)` applied the authentication middleware to `/healthz` and `/readyz` | Every orchestrator probe answered 401, so the replica would never have entered service. `Routes` now returns a `Surface` with two handlers and the composition root mounts each behind the chain it requires. Two fields rather than a list of exempt paths: an exemption list is edited by whoever adds a route, and the failure mode of forgetting is an unauthenticated mutation |
| Probes were also inside the API's in-flight budget | A readiness check shed by an overloaded API removes a replica that is still healthy, which is how load shedding turns overload into an outage. The probe chain has its own limiter and no authentication |
| The `identity_runtime` role could `UPDATE` and `DELETE` `identity.atlas_schema_revisions` | Atlas landed its revision table inside the schema `grants.sql` grants DML on, so the application could rewrite migration history and a later `atlas migrate apply` would re-run or skip migrations from rows it had changed. Fixed with `revisions_schema = "atlas"`; asserted by `TestRuntimeRoleCannotRewriteMigrationHistory` |
| A fresh Keycloak realm signs with a 2048-bit RS256 key | The verifier permits exactly one algorithm, so every token was rejected. `dev-keycloak.ps1` adds an `rsa-generated` PS256 / 3072-bit provider. FAPI 2.0 prohibits RS256 and `ADR-IAM-002` follows it |
| Keycloak 24+ discards user attributes the user profile does not declare, without an error | The create call succeeds, `scnehaux_principal_id` never lands, and the symptom appears three steps later as a token with no `principal_id`. The three attributes are declared with `edit` restricted to admin, rather than solved by enabling unmanaged attributes, so a user cannot set their own `principal_id` through the account console |
| foundation-platform's platform migration set was not re-runnable | Every deployment after the first aborted on `column "scope" ... already exists`. `identity-migrate` applies the whole set on every invocation because the shared module ships no revision table, and its package comment already claimed idempotency. Fixed upstream in `foundation-platform v0.2.1` with an integration test that applies the set three times |

### Week 3 · Event translation and consumption

- Publication of `com.scnehaux.identity.*` through the shared outbox
- Consumption of `com.scnehaux.organization.membership.*` and `...tenant.*`
- Deduplication guard on every consumed event
- Reconciler skeleton reading authority through the published snapshot contract, never
  through a database connection

**Exit:** no code path in this service constructs an Organization Database connection,
asserted by test.

## Open governance question: the first Principal

**The first Principal in a realm cannot be created through the only sanctioned path.**

`TDD-identity-control-001` closes every Principal creation path except `POST /v1/principals`,
and `ADR-ORG-001 §5.3` makes this service the sole authority over the identifier. That endpoint
requires an authenticated caller, and authentication requires a token carrying a `principal_id`,
and a `principal_id` is issued only by that endpoint. The cycle has no entry point.

This is not a harness inconvenience. A fresh production realm has the same problem, and the
answer cannot be "someone runs an INSERT", because an identifier that entered the canonical
registry without a recorded decision is exactly what `ADR-ORG-001` exists to prevent.

`scripts/dev-keycloak.ps1` and `scripts/dev-database.ps1 -SeedBootstrapPrincipal` currently mint
and record one out-of-band, and both say plainly that this is the prohibited path. Acceptable on
a loopback harness; not a production procedure.

What the estate needs is a designed bootstrap. The shape is a decision for `ADR-IAM-001` rather
than for this repository, and the two candidates are:

- **A break-glass identity**, provisioned with the realm, holding a reserved `principal_id`, and
  usable only to create the first real operator. Its use is an alert rather than a log line.
- **An operator-initiated first-Principal ceremony** — a one-shot command on the deployable
  itself, refusing to run when `identity.principal_mapping` is non-empty, and writing an audit
  record naming the human who ran it.

The second is closer to the estate's posture, because it keeps creation inside the authority
that owns the identifier instead of creating a credential that can create Principals forever.
Neither is decided, and nothing downstream of this repository should assume one.

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

Two of them have provisional answers now, from running against Keycloak 26.7.1. They are
recorded as evidence for `identity-kernel` to confirm, not as decisions taken here:

- **Protocol mapper coverage.** An `oidc-usermodel-attribute-mapper` projects
  `scnehaux_principal_id` and `scnehaux_subject_type` into the access token, and an
  `oidc-audience-mapper` is required for `aud` — Keycloak does not add a second service's
  audience on its own.
- **Attribute immutability.** The user profile controls it. An attribute declared with `edit`
  restricted to `admin` cannot be written by the user it belongs to, which is the property
  `principal_id` needs. An *undeclared* attribute is discarded outright, so the declaration is
  mandatory rather than a hardening step.

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

**Also a production blocker: the first-Principal bootstrap is decided and implemented.**
Without it, standing up a production realm requires the out-of-band `INSERT` that
`ADR-ORG-001` prohibits, and the shortcut taken once under deployment pressure is the one
that stays.
