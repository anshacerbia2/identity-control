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
| TDD-identity-control-004 named a workload lifetime class, then a later revision "corrected" it | Both were wrong, in opposite directions. The class letters were reassigned while two rewrites of STD-IAM-002 ran in parallel: in the standard as merged, `L2` is external and `L3` is workload. This design now states both. The lesson is recorded there: **a lifetime class must be cited with its audience, never by letter alone** — a bare letter resolves to a real class saying something else, so nothing catches it |
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

### Week 2¾ · The bootstrap ceremony

✅ **Closed.** The first-Principal gap recorded here was a real design defect, not a harness
inconvenience: `TDD-identity-control-001` closes every creation path except `POST /v1/principals`,
that endpoint requires a caller holding a `principal_id`, and only that endpoint issues one. A
fresh production realm had no entry point.

`ADR-IAM-001 §5.11` decided the shape — a single-use ceremony on the deployable — and rejected the
standing break-glass identity as `Alternative F`. The reasoning that settled it: a break-glass
identity creates a credential that can create Principals *forever*, in exchange for solving a
problem that occurs once, and because it must exist before the service does it can only be placed
by the out-of-band write the architecture prohibits. The problem would have been relocated rather
than solved.

`cmd/identity-bootstrap` implements it, and every guarantee is structural rather than procedural:

| Guarantee | Mechanism |
| :-- | :-- |
| Succeeds at most once per Control Database | `id = 1` under a primary key on `identity.bootstrap_ceremony`. Two concurrent ceremonies produce one Principal; the loser is refused by a constraint rather than by a race it might win |
| Refuses a populated registry | Emptiness asserted in the claiming transaction, in the same statement that reads the row back, so the count cannot be from a stale snapshot |
| The operator and reason are immutable | `grants.sql` revokes `UPDATE`, `DELETE`, and `TRUNCATE` on that table from the runtime role. A resumed ceremony reads the record and reports the *original* operator, so a second attempt cannot rewrite who ran the first |
| Survives a crash without a second Principal | The idempotency key lives in the row, so a resumed ceremony replays the original claim through `Provisioner.Create` |
| Holds no credential | The kernel user is created with `UPDATE_PASSWORD` outstanding, so the first human interaction establishes the credential |
| Creates nothing special | The identifier is a UUIDv7 through the ordinary path. A reserved or well-known identifier for the first Principal would be a value an attacker knows in every estate |

The scope it claims under is `ceremony:bootstrap`. Every API caller's scope is
`principal:<uuid>`, so the namespaces are disjoint and an authenticated caller can neither replay
nor consume the ceremony's claim. Asserted by test.

**The harness no longer does the prohibited thing.** `dev-keycloak.ps1` creates no user and
`dev-database.ps1` lost its `-SeedBootstrapPrincipal` switch; `scripts/dev-bootstrap.ps1` runs the
real ceremony. Verified from a dropped database and an emptied realm: the ceremony succeeded, a
second run was refused showing the record, a `-resume` with the wrong operator was refused, a
`-resume` with the right one returned the same `principal_id` with no second kernel user, and
`UPDATE` on the record was refused by PostgreSQL.

#### One finding this produced

Deriving the required action from the subject type exposed a latent gap in the ordinary path too.
A human Principal created through `POST /v1/principals` previously had no credential and no
required action, so the user existed and could never authenticate — with nothing in the system
saying so. `CreateUserRequest.RequiredActions()` now applies to every creation path: a human owes
a credential, a workload does not, because a workload authenticates by client credential and a
password action would block it on a flow it never uses.

### Week 2⅞ · Conformance against the merged standards

The merged governance layer was read end to end against what is built, artifact by artifact:
PAD-PLT-001, PAD-PLT-002, ADR-IAM-001, ADR-IAM-002, ADR-ORG-001, STD-IAM-001, STD-IAM-002,
SAD-001, SAD-002, SAD-004, SAD-012, and every TDD in the six service repositories.

**The two PADs and ADR-ORG-001 were already coherent** — authority boundaries, invariants, and the
ontology agree with each other and with the implementation. STD-IAM-001 and STD-IAM-002 cross-cite
correctly. What follows is everything that did not.

#### The audience class was wrong, and it decided four things at once

The local realm classified this service as `internal` with a fifteen-minute token. It is neither.
Creating a Principal is irreversible and belongs to no Tenant, which is the `privileged` class in
the `provider-scope` form. Getting the class right fixed four things together:

| Consequence | Before | After |
| :-- | :-- | :-- |
| Token lifetime | 900s, cited as class `L2` — the external and partner class | 240s, class `L0`, pinned on the realm and on the client |
| `tenant_id` | absent, recorded as a deferred non-conformance | prohibited, and the verifier rejects a token carrying it |
| `acr` / `auth_time` | absent | mandatory, and absence is a rejection |
| `provider_scope` | did not exist | mandatory, and only a registered value is accepted |

The `tenant_id` row is the one worth noting. It read as an implementation gap to defer until an
Organization authority existed. It was a misclassification: for a provider-scope token the claim
is `MUST NOT`, so classifying correctly removed the non-conformance rather than postponing it.

#### STD-IAM-002 could not be implemented as written

`privileged` was defined as covering cross-tenant operations while §3.2 required `tenant_id` and
"exactly one active Tenant context". A provider action has no Tenant, so the class was
unsatisfiable for the operations it was written for. §3.1.1 now splits the two scope forms and
§3.2 makes the version claims conditional on `tenant_id` in every class. Bumped to v1.2.0.

#### Nothing prohibited the grant the harness was using

Four places here cited "STD-IAM-001 §3.2 forbids direct access grant outside development". That
prohibition did not exist — §3.2 required Authorization Code with PKCE for public browser and
native clients and was silent on the Resource Owner Password Credentials grant for a confidential
one. The citation was invented, and the hole was real: a confidential client could have enabled
ROPC in production and passed every stated rule.

STD-IAM-001 §3.2 now prohibits the grant for every client, and v2.1.0 records why it is
structural: the client receives and forwards the password, which §3.1 forbids it from holding, and
MFA, WebAuthn, step-up, and every abuse control sit outside that path.

Then the interesting part. The prohibited grant **could not have produced a conformant token**:
`auth_time` is mandatory for `privileged`, and the kernel records an authentication instant only
for an authentication ceremony. A direct grant has none, so the claim was structurally absent, not
misconfigured. `scripts/dev-token.ps1` drives Authorization Code with PKCE `S256` without a
browser instead, so the harness no longer depends on a prohibited grant at all.

#### SAD-001 declared no revocation contract

PAD-PLT-001 invariant 9 names six revocation classes and STD-IAM-001 §3.4 requires each to declare
its enforcing mechanisms and a measurable maximum enforcement delay. SAD-001 mentioned revocation
twice, in passing. SAD-004 had done this properly for the Organization side, so the gap was
one-sided rather than an estate-wide omission.

§7.7 now carries the table, derived rather than chosen: `propagation_budget +
remaining_access_token_lifetime`, worst class rather than typical. It also states the ordering that
is load-bearing — projected context removed before kernel sessions, because a refresh landing
between the two mints a token asserting the context just revoked — and §7.7.1 names the three
mechanisms that are declared and not yet built, where the delay is unbounded rather than merely
longer.

#### Two silent misconfigurations in the harness

| Finding | Why it was invisible |
| :-- | :-- |
| The PS256 key provider was attached to the realm **name** instead of the realm **id** | Keycloak 26 generates the realm id as a UUID. The create returned 201, the component was readable at `?parent=<name>`, and the realm kept signing with its default 2048-bit key. The verifier then refused every token with "signing material is unavailable" because §3.2.2 requires 3072 bits. `dev-keycloak.ps1` now asserts the published key width instead of trusting the call |
| `Upsert-Client` only created, never updated | Every client configuration change after the first run was silently not applied. A setup script that reports success while applying nothing is worse than one that fails |

#### Open question: who may hold a provider scope

`provider_scope` is mandatory and the verifier accepts exactly one registered value, so the claim
is enforced. Granting it is not. No artifact says which Principal may hold
`provider:identity-control`, where that grant is recorded, or who reviews it — and this service has
authentication without authorization, so nothing here can decide it either. The harness sets the
attribute in its dev-only step and says so, which keeps the gap visible rather than buried in a
plausible-looking mapper. It wants a decision in ADR-IAM-001 §5.6, alongside the authorization
boundary that section already governs.

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

**The first-Principal bootstrap blocker is cleared.** `ADR-IAM-001 §5.11` decided it and
`cmd/identity-bootstrap` implements it, so standing up a production realm no longer requires the
out-of-band `INSERT` that `ADR-ORG-001` prohibits. What remains for the production gate is
operational rather than architectural: the ceremony needs a runbook naming who is authorized to
perform it and where the record is reviewed, since the evidence is worthless if nobody reads it.
