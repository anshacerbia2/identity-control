# Identity Control Service — Roadmap

Execution tracker for this repository only. It records which technical designs exist,
which are blocked, and what is buildable today. Architecture lives in
`scnehaux-architecture`; nothing here overrides a SAD, an ADR, or a standard.

Week numbers are relative to the first build week, not calendar dates.

## Design status

| TDD | Subject | Status |
| :-- | :-- | :-- |
| `TDD-identity-control-001` | Canonical Principal identifier and creation path | approved; every proof-of-concept question it depended on is answered |
| `TDD-identity-control-002` | Keycloak context projection, durable retry, session removal | approved; implementation-gated by PoC |
| `TDD-identity-control-003` | Protocol client and protected-resource registration | approved |
| `TDD-identity-control-004` | Workload and bounded agent identity | approved |
| `TDD-identity-control-005` | Account-security and investigation API mediation | approved |
| `TDD-identity-control-006` | Provider authority from Organization's records: delivery intake, local projection, freshness, the per-request decision that replaces `provider_scope`, and the ceremony grant | built: intake and projection, bootstrap and freshness (`cmd/identity-provider-bootstrap`, the frontier poll), the per-request decision (`providerauthority.Decider`; `provider_scope` refused) and the ceremony grant with its insert-only retirement. The kernel's `provider_scope` mapper is removed in identity-kernel |

Three documents were inherited from the former monorepo. All three are gone from `docs/designs`,
and their content lives here:

| Inherited file | Disposition |
| :-- | :-- |
| `TDD-001-principal-identifier-and-creation.md` | Renamed to `TDD-identity-control-001`; realm configuration became a stated dependency on `identity-kernel` rather than an instruction issued from here |
| `TDD-002-control-plane-module-boundaries.md` | Removed. Its premise was two deployables sharing one repository, which no longer holds. Database separation, runtime roles, and credential containment survive inside the designs that own them |
| `TDD-003-membership-projection-and-revocation.md` | Removed. Authority, versions, and the revocation transaction landed in `TDD-organization-control-002`; the projector, session removal, and reconciler landed in `TDD-identity-control-002` |

## Cross-repository dependency

`foundation-platform` lands first. This service imports its outbox, dispatcher, event
envelope, idempotency, and problem-details packages from day one, and reimplementing
any of them here would produce a second revocation enforcement interval while both
services reported compliance.

Pinned at `v0.2.2`. `v0.2.0` shipped a platform migration set that could only be applied
once — see the findings table under Week 2½ — and `v0.2.2` added the `request-in-progress`
problem type this service needed.

`identity-kernel` is a parallel track, not a predecessor. Keycloak calls in this
service sit behind a port with a fake implementation, so the full creation and
recovery suite runs before the kernel repository produces anything.

The realm shape is `identity-kernel`'s. Its `realm/` declares what `ADR-IAM-001` and `STD-IAM-002`
require of a realm: the PS256 key, the declared attributes, and the claim scopes, including
`scnehaux-provider`, which this service's callers need. Its `compat/` asserts them. This
repository registers only its own clients against that realm, through `scripts/dev-keycloak.ps1`
locally and `deploy/dev/create-kernel-clients.sh` on the development server.

Two of those settings are not merely recommended: without them the verifier rejects every token,
silently in one case.

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
| foundation-platform's problem registry carried no in-progress type | ✅ Closed upstream in `v0.2.2`. A duplicate in-flight request mapped to `state-transition-refused`: the right 409 with the opposite advice, since a refused transition means no retry will help and this one means the retry is what will. The registry is compiled precisely so a handler cannot invent a type, which is why it had to be fixed there rather than worked around here |
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

The `provider_scope` row is superseded. `TDD-identity-control-006` reads provider authority from
this service's projection of Organization's grants for each request, so the claim is no longer
issued and a token carrying it is refused (`STD-IAM-002 §3.1.1`).

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

#### Resolved: who may hold a provider scope

Recorded as an open question, then answered by reading the artifacts rather than by deciding
anything new. `PAD-PLT-002 §3.1` already places provider cross-tenant scope in the Tenancy
Administration context and `ADR-ORG-001 §5.1` already makes organization-administrative roles the
Organization Platform's sole authority. The grant therefore travels the projection path
`ADR-ORG-001 §5.4` fixes for Membership — it is not this platform's to create.

The harness had been setting the kernel attribute directly, which would have made the kernel a
second authority for a fact Organization owns. `ADR-IAM-001 §5.6` now records the rule and the one
exception: the bootstrap ceremony grants exactly one scope to exactly one Principal, because §5.11
runs before any Organization authority can exist and a first Principal holding no scope could not
reach the API that issues every later one — the ceremony would produce an identity that can do
nothing.

The bound is structural rather than procedural. `CeremonyProviderScope` is a fixed constant, not a
parameter, because a ceremony that could be asked for an arbitrary scope would be a way to mint
provider authority bounded only by what the operator typed. `validateCreate` refuses the field on
any request whose caller scope is not the ceremony's, so a handler that started setting it fails
rather than quietly granting. And the port refuses it on a workload outright: `STD-IAM-002 §3.2`
prohibits the claim there, and a workload authenticating by client credential presents no `acr` for
`PAD-PLT-002 §3.3` invariant 22 to evaluate.

Verified in the live realm: `bootstrap-operator` carries `provider:identity-control` and the two
Principals created through the API carry none.

### Week 3 · Event translation and consumption

- Publication of `com.scnehaux.identity.*` through the shared outbox
- Consumption of `com.scnehaux.organization.membership.*` and `...tenant.*`
- Deduplication guard on every consumed event
- Reconciler skeleton reading authority through the published snapshot contract, never
  through a database connection

**Exit:** no code path in this service constructs an Organization Database connection,
asserted by test.

## Proof B · Keycloak drift

✅ Done 2026-09-28: all seven steps, proven on every `deploy-dev` run. `organization-control` backlog item 10.
It was labelled P2 in RESPONSE-7 to RESPONSE-10 and listed with the P1 backlog in RESPONSE-23.

**The claim to prove** (RESPONSE-4 §4): drift between reviewed desired state and live Keycloak can
be detected, classified, reconciled, and shown to converge. This service is not merely a
controlled proxy to the Admin API. The first two scenarios:

| Scenario | Policy |
| :-- | :-- |
| Access token lifespan on one client changed in the console | auto-reconcile |
| Redirect URI on one client changed in the console | detect and block |

Acceptance criteria, also from RESPONSE-4 §4:

- A reconciler runs on a schedule, and its last run is observable.
- Drift is told apart from a sanctioned change through Keycloak admin events, with a time-bound
  exception. A class of change with no attribution is never auto-reconciled.
- An unreachable Keycloak yields `unresolved`, neither a failure nor a success.
- Convergence time is recorded as evidence.
- The principal portability test rides along: blank a mapping's `keycloak_user_id`, provision
  again, and require `principal_id` and its Memberships to be intact. The blanking is done by
  `:relink` (decision 4), because TDD-001 has the database refuse an active mapping without a
  user.

**What exists** (surveyed 2026-09-27):

- `identity-kernel`'s `realm-apply` records the applied git revision in the realm and refuses to
  apply over console drift (exit 2). It covers realm settings, keys, client scopes and the user
  profile only. It never reads clients, runs only at deploy, and never reconciles on its own.
  Its packages are under `internal/`, so this module cannot import them.
- TDD-003 designs client registration, and none of it is built:
  - the `identity.client_registration` desired-state table (redirect URIs, lifetime class);
  - `GET /v1/registrations:drift` and `POST /v1/registrations:reconcile`;
  - a drift algorithm and a 1h interval;
  - the `identity-control-registration` credential with `manage-clients` and `view-clients`.
- TDD-002 designs `identity.drift_finding`, and it is not built.

**What is missing:**

- Clients are not declared anywhere. The two scenario targets sit on `identity-control-caller`,
  which imperative scripts create (`deploy/dev/create-kernel-clients.sh`,
  `scripts/dev-keycloak.ps1`): redirect URI `http://127.0.0.1:8099/callback`,
  `access.token.lifespan` 240.
- ✅ This service had no scheduler, no reconciler, and no last-run record. The registration sweep
  now runs on a schedule and records each run in `identity.reconcile_run` (step 4).
  `identity.projection_cursor.last_reconciled_at` is the Membership projection's and is still
  unwritten.
- Its Keycloak credential holds `manage-users` and `view-users` only. It cannot read or change
  clients, and cannot read admin events, which need `view-events`.
- ✅ Admin events were not enabled in `identity-kernel`'s realm definition. They now are, with
  representation and 7-day retention (identity-kernel #16).
- The mapping state machine has no way back from `active`. A blanked `keycloak_user_id` on an
  active row is picked up by nothing, so the portability test needs a designed transition.
  Designed as `:relink` (decision 4), not built.

**Decided 2026-09-28:**

1. **Desired state lives in the Control Database**, written through the registration API, not in
   a reviewed file in git. The reasoning is in TDD-003 §Technical Context. A client's access
   token lifespan is derived from the lifetime classes of its audience, not stored.
2. **A redirect URI changed in the console is blocked, not restored.** The client is disabled,
   the changed value kept, and only an operator's reconcile lifts it, because silently restoring
   a redirect URI hides a possible takeover (TDD-003 §Drift Reconciliation).
3. **The registration credential on the development server comes from a new one-time script.**
   The script creates `identity-control-registration` only, refuses when it exists, and whoever
   operates the server runs it once. `create-kernel-clients.sh` and `dev-keycloak.ps1` are not
   run there again.
4. **Portability goes through `POST /v1/principals/{principal_id}:relink`.** It takes a reason,
   and returns an active mapping whose Keycloak user is gone to `pending`, for recovery to
   provision again. The sweep only reports a dangling mapping and never relinks it, since a
   user deleted on purpose must not come back by itself. The database refuses an active mapping
   without a Keycloak user (TDD-001 §Data Model).

**Order, one PR each:**

1. ✅ Enable admin events in `identity-kernel`'s realm definition (identity-kernel #16).
2. ✅ Edit TDD-003 and TDD-001 with the decisions above.
3. ✅ Add the registration, run, finding and exception tables, and the registration credential with
   its one-time development script. The runtime role deletes no row of the four tables and
   updates no exception. `deploy-dev` creates the client with the script the server's operator
   runs, refuses a second run, and asserts the credential split against a live kernel.
4. ✅ Build the reconciler: interval, last run, findings, lifespan repair, redirect-URI block,
   exception through admin events, `unresolved`. `internal/reconcile` sweeps on
   `IDENTITY_REGISTRATION_RECONCILE_INTERVAL` (1h) with the registration credential. One replica
   sweeps at a time. `GET /v1/registrations:drift` reports the last run and the open findings.
   `POST /v1/registrations:reconcile` sweeps now, and with a reason applies desired state to named
   blocked or unattributed findings. `POST /v1/registrations/{id}/drift-exceptions` grants up to 24
   hours, and `GET` on the same path lists them, expired ones included. Two field classes are compared: `token_lifespan` and `redirect_uris`. An absent client
   is reported, not recreated, and no client is treated as unmanaged until step 5 registers them
   (TDD-003 §Drift Reconciliation).
5. ✅ Build the registration API: `POST /v1/registrations` (with an Idempotency-Key),
   `GET /v1/registrations/{id}`, and `GET /v1/registrations`, a cursor-paged list, added for the
   identity-experience admin console (TDD-003 1.8.0). `internal/registration` records desired state as a pending row,
   creates the client, attaches the audience class's managed scope, and activates it. Pending
   rows are recovered before each sweep. An absent client is held as a `missing` finding and
   recreated only by an operator's reconcile (RESPONSE-27, D5). Found while building
   step 4: the drift proof needs a registered client, and nothing wrote one. Scope, and what it
   leaves (TDD-003 §Validation, §Drift Reconciliation):
   - Only the `public` and `resource` profiles were built at first, which are enough for the
     drift proof. `confidential` and `workload` followed with client key registration, below.
   - The kernel declares no `scnehaux-workload` or tenant-scope privileged scope. Registrations
     of those classes are refused, and TDD-003's scope names now follow the kernel's.
   - A key an unregistered Keycloak client holds is refused, never adopted.
   - Disabling unmanaged clients came later, with adoption (below).
6. ✅ Add a Proof B end-to-end job in `deploy-dev.yml` against a real Keycloak: both scenarios, the
   exception, Keycloak down, and convergence time. `scripts/dev-proof-b.ps1` registers a public
   client, then changes it through the Admin API as the console administrator, so every change
   carries its admin event. The first passing run, 2026-09-28:

   | Scenario | Outcome | Evidence |
   | :-- | :-- | :-- |
   | Schedule | a run started unprompted | interval 20 s in CI |
   | Lifespan changed in the console | repaired, attributed to the administrator | converged 0.07 s after the change |
   | Takeover redirect URI in the console | client disabled, URI kept, lifted only by an operator's reconcile | blocked 0.04 s after the change |
   | Lifespan change under a 40 s exception | left in place, then repaired | converged 2.19 s after the exception expired |
   | Keycloak stopped | `unresolved` while down | converged 0.57 s after it answered again |
   | Client deleted in the console | held as `missing`; no sweep recreates it; an operator's reconcile does | the principal's D5 fix, RESPONSE-27 |
   | User deleted in the console (step 7) | reported, then relinked by an operator | same `principal_id`, one new user |

   These times are for a sweep the script requests right after each change. Left to the
   schedule, a divergence waits up to one `IDENTITY_REGISTRATION_RECONCILE_INTERVAL`, 1 hour by
   default. The job also found two defects:
   - A restarted Keycloak refuses the token the Admin client had cached, and the client kept
     presenting it until it expired. It now drops the token and retries once on a 401.
   - A repair converges inside the sweep that made it, so no route showed it. The drift route
     now reports the last run's findings, and `GET /v1/registrations/{id}/findings` a client's
     history.
7. ✅ Add `:relink`, the dangling-mapping finding, and the portability test.
   - `POST /v1/principals/{id}:relink` takes an `X-Administrative-Reason`. It asks the kernel to
     confirm the user is gone: an unknown answer is refused, and an existing user answers `409`.
     It then returns the mapping to pending, records who and why in the insert-only
     `identity.principal_relink`, and recovery recreates a user with the same `principal_id`.
     The database now refuses an active mapping without a user.
   - The scheduled sweep records a dangling mapping in `identity.principal_finding` and never
     relinks it. It also runs pending Principal recovery, which nothing had scheduled before.
   - Proof B scenario 5, first passing run: the console administrator deletes the user, the
     sweep reports the mapping and recreates nothing, a relink without a reason is refused, the
     relink with one leaves the Principal active with exactly one new user carrying the same
     `principal_id`, and a second relink is refused.
   - The Memberships half of the criterion holds by construction, not by this job:
     `organization-control` holds Memberships by `principal_id`, and a relink writes identity
     tables only. The job does not run `organization-control`, so no cross-service test observes
     it.
**Found while building, and not part of Proof B:**

- ✅ **Client key registration:** confidential and workload registration by public key (`private_key_jwt`), TDD-003 1.11.0 §Client Key Records, §Client Key Rotation.
  - Client secrets were the first design. On 2026-09-29 they were replaced, because the pinned Keycloak can overlap two secrets only through a preview feature. `ADR-IAM-001 §5.12` and `STD-IAM-001 §3.2` record the decision.
  - `identity-kernel`'s compat suite proved the key mechanism against 26.7.4 (identity-kernel#18): two keys overlap, a removed key is refused on the next request, and a replayed assertion is refused.
  - Built: `identity.client_key`, whose rows the runtime can neither delete nor rewrite beyond a key's state and dates; `POST /v1/registrations` with `public_key` for the `confidential` and `workload` profiles; `POST|GET /v1/registrations/{id}/keys` and `.../keys/{key_id}:revoke`; and scheduled removal of a retiring key when its overlap ends and of any key when its lifetime ends, before each sweep. A private key is refused by validation and by the database, and never echoed.
  - A `workload` registration needed the kernel's `scnehaux-workload` scope, declared in identity-kernel#23. It also detaches Keycloak's built-in `acr` scope, which the realm attaches to every new client and which puts `acr=1` in a workload's token (identity-kernel compat run 36739171569; TDD-003 1.12.0).
  - ✅ The `client_keys` drift class (TDD-003 1.14.0): a JWKS, key or authenticator changed in the console disables the client and is recorded `blocked`, attributed or not, and only an operator's reconcile puts back exactly the active and retiring keys. A divergence is confirmed under the registration's row lock first, so this service's own rotation in flight is never taken for drift. No drift exception covers it.
  - ✅ Proof B scenario 7 proves it against the real kernel with a workload: key A authenticates, a rotation to B keeps both working, revoking A refuses it on the next request, a key C added in the console blocks the client, and the operator's reconcile leaves exactly B.
  - ✅ The key expiry warning (TDD-003 1.18.0 §Key Expiry Warnings): `GET /v1/registrations:expiring-keys` reports every active keyed registration whose active key ends within 14 days (`warning`) or 3 days (`critical`), or which holds no key the kernel accepts (`no_key`), and the scheduled pass logs each at `WARN` or `ERROR` before the sweep. A retiring key alone, after its active key was revoked mid-rotation, counts by its overlap end. Not yet a metric: this service exports no OpenTelemetry yet, and the warning becomes a gauge when it does.
- ✅ **Adoption and unmanaged clients** (ADR-IAM-001 §5.12, SAD-001, TDD-003 1.15.0; decided 2026-09-30 on Terraform import, CloudFormation resource import and Crossplane's observe-first import).
  - `POST /v1/registrations:adopt` brings a client a bootstrap script created under registration. It plans first (`dry_run`), refuses a client whose redirect URIs or keys differ from the declaration or that authenticates with a secret or a JWKS URL, converges a repairable difference only when named, and records the adoption insert-only in `identity.registration_adoption`. Only `confidential` is adopted.
  - The sweep records every Keycloak client no registration describes as `unmanaged`. The kernel's built-in clients and this service's two Admin API clients are exempt. `IDENTITY_UNMANAGED_CLIENTS` is `report` by default and `disable` once an estate's bootstrap clients are adopted; production runs `disable`.
  - The `deploy-dev` smoke adopts `identity-control-caller` with the key it already holds, so its sweeps converge; Proof B scenario 8 records a console-created client `unmanaged` and converges it once deleted.
  - **On the development server:** adopt `identity-experience-bff` with its public key (`deploy/dev/README.md` §Adopting the BFF), then set `IDENTITY_UNMANAGED_CLIENTS=disable`.
  - An adopted client is not released afterwards (ADR-IAM-001 §5.13, Alternative J): it stops like any registration, below. A declared audience that names this service's own Admin API client cannot be registered, so the caller is adopted with an empty audience; audience mappers are not compared.
- ✅ **The token profile** (STD-IAM-002 §3.2 and §3.2.1, TDD-003 1.17.0 §Profiles; identity-kernel compat runs 36775603547 and the claim closure).
  - Every client but a resource is registered with the `access.token.header.type.rfc9068` attribute, so its access tokens carry `typ` `at+jwt`, and a `client_id` mapper naming its `client_key`, which RFC 9068 §2.2 requires and the kernel writes only into a service-account token.
  - Its default and optional client scopes are closed sets: `basic`, `acr` (not for a workload) and its managed audience scope, and `scnehaux-profile` as an optional scope for a confidential client. A built-in `profile`, `email`, `roles` or `web-origins` scope is detached. A workload holds `service_account`, which the kernel attaches again on every update; identity-kernel declares it with its `client_id` mapper alone. No access token carries personal data, roles, or a workload's address.
  - The sweep compares `audience_scope` and `token_format`, both repaired. An adoption names them in `converge` for a client a script made before the profile; the smoke adopts the caller so.
  - **On the development server:** the clients registered or adopted before this differ in both classes at the first sweep. With no admin event to attribute the difference to, each finding is `unattributed`; apply the registered state once for each, from the Admin Portal or `POST /v1/registrations:reconcile`.
  - The verifier's `at+jwt` check is the next item.
- ✅ **The caller's token is typed `at+jwt`** (STD-IAM-002 §3.5 step 5, TDD-001 1.7.0 §Caller Token; foundation-platform `v0.2.13`). `IDENTITY_TOKEN_TYPE` is `report` by default: a token typed `JWT` is accepted and logged with its `azp`. `enforce` refuses it with 401. **On the development server:** watch the log for `not typed at+jwt` after the callers' clients carry the token profile, then set `IDENTITY_TOKEN_TYPE=enforce`.
- ✅ **Suspension, restoration, and retirement** (ADR-IAM-001 §5.13, STD-IAM-001 §3.4, SAD-001, TDD-003 1.16.0; decided 2026-09-30 on identity-kernel compat run 36765561606, NIST SP 800-61r3 RS.MI-01/02, and the disable-before-delete practice of Google Cloud and AWS IAM).
  - `POST /v1/registrations/{id}:suspend` records the registration suspended, then disables its client and sets the not-before that ends the refresh tokens it was issued: the kernel accepts a disabled client's refresh tokens again once it is enabled. The sweep holds a suspended client disabled with its not-before (the `suspension` field class), attributed or not.
  - `:restore` writes the registered redirect URIs, keys and lifespan back, enables the client, and resolves the registration's open findings, in one transaction that a kernel failure rolls back. A restore of an active registration changes nothing, so it never lifts a block.
  - `:retire` follows a suspension (a resource retires directly, once no active or suspended registration names it in its audience). It removes the keys, deletes the kernel client, revokes the key rows, keeps the record, and frees the `client_key`. A retired registration's open findings converge at the next sweep.
  - Every action takes an `X-Administrative-Reason` and is recorded insert-only in `identity.registration_state_change`. An operator's reconcile and a recreation refuse a suspended registration. A workload's client is refused: deleting a client deletes its service-account user, so the workload lifecycle stops it.
  - Proof B scenario 9 runs it against the kernel: a console re-enable of a suspended client is repaired with its not-before, a restore enables it, an active client's retirement is refused, and a retired client's `client_key` registers again.
  - The workload lifecycle's own suspension, restoration and retirement are built (TDD-004 1.4.0, below). The Admin Portal actions follow in identity-experience.
- **The rest of the Principal sweep:** its unmapped, orphan and duplicate branches (TDD-001 §Reconciliation Sweep) are not built. Only the dangling branch and pending recovery run.
- ✅ **Workload identity, first slice** (TDD-004 1.3.0): `POST /v1/workloads`, `GET /v1/workloads/{id}` and `:reassign`, with `identity.workload` and the insert-only `identity.workload_owner_change`.
  - A workload's Keycloak user is its client's service-account user, the one a client credentials token is issued for (identity-kernel#23). The workload path creates the client, writes `principal_id`, `subject_type=workload` and `workload_owner` on that user with the Principal credential, and binds the mapping to it. `POST /v1/principals` and `:relink` now refuse a workload, which on the old path would have carried its identity into no token.
  - The owner is an active human Principal. Where the workload may act is its Membership, granted by organization-control like any binding. This follows how Google Cloud, Entra, AWS and Kubernetes scope workload identities, and needs no Membership data here (decided 2026-09-30).
  - Pending workloads are recovered before each sweep, after pending registrations, and the creating request's key is completed by recovery.
  - The `deploy-dev` smoke creates a workload and authenticates as it with its own key: its token carries `principal_id`, `subject_type=workload` and `workload_owner`, and no `acr` and no refresh token (first passing run 36746826573, 2026-09-30).
  - Not built yet: orphan handling (on the owner's Principal being retired, quarantined or disabled; NIST AC-2(3)(b)), unused detection (90 days), the quarterly owner review (CIS 5.5), rebuilding a workload's client after a console deletion, and agent delegation. `identity-experience`'s admin form that creates a workload through `POST /v1/principals` must move to `POST /v1/workloads`.
- ✅ **Registration ownership, first slice** (ADR-IAM-003; TDD-003 1.19.0 §Registration Ownership; TDD-001 1.8.0 §Caller Token): `identity.registration_owner`, granted and revoked by a provider with a reason, insert-only but for its revocation columns.
  - An owner is an active human Principal, counted only while its mapping is active, so a Principal retired or quarantined confers nothing at the next request. In production (`IDENTITY_ENVIRONMENT`, `production` by default) a registration keeps at least two owners.
  - A token without `provider_scope` is an owner's, the `resource-scoped` form of STD-IAM-002 §3.1.1: a person, with `acr` and `auth_time`. Every route is wrapped in `providerOnly` or `owned`, and a test fails on an unwrapped one: an owner reads, rotates and revokes keys of, and suspends and restores, a registration it owns, answers 404 for any other, and 403 on every provider route before anything is read. `GET /v1/registrations:mine` lists what the caller owns.
  - The Developer Console uses these routes: identity-experience#20 and #21 list what a person owns, and let an owner rotate and revoke keys and suspend and restore its client.
- ✅ **Registration changes, redirect URIs** (ADR-IAM-003 §5.2; TDD-003 1.20.0 §Registration Changes): `identity.registration_change`, and `POST`/`GET /v1/registrations/{id}/changes`, `:approve`, `:reject`, `:withdraw`, and the approval queue `GET /v1/registrations:changes`.
  - A change names the whole new set of redirect URIs and the `expected_version` it was read at. A stale version is a version conflict. Each URI is validated as registration validates it.
  - In non-production it applies at once. In production it waits until a provider other than its proposer approves it. A check constraint holds that in the database too: a change that required approval is never recorded applied by its proposer (NIST AC-5).
  - An approval writes desired state and the kernel client in one transaction under the row lock, as a restore does, so the sweep finds nothing to block. A kernel failure leaves the proposal open.
  - A proposal is pinned to the version it was made against: one whose registration moved is recorded superseded when approved. There is one open change per registration, and the same proposal retried returns it.
  - An owner proposes and withdraws on a registration it owns. Approving, rejecting and the queue are a provider's, and an owner is refused before anything is read.
  - Changes waiting past three days log at WARN, and past seven at ERROR, before each sweep.
  - The Developer Console proposes and withdraws, and the Admin Portal approves and rejects, in identity-experience#22.
  - Audience changes, the `audience` kind of a change (TDD-identity-control-003 1.26.0): an owner adds only resources it owns and always removes, a provider adds any registered resource, approved in production by another provider. The apply makes the client's audience mappers exactly the declared set, a hand-made one removed, and re-derives the lifespan. It is how callers move to `identity-control-api` (STD-IAM-002 §3.1).
  - The ceremony registers `identity-control-api`, this service's own resource (ADR-IAM-001 §5.11 rule 5, TDD-identity-control-001 1.11.0), named by `IDENTITY_TOKEN_AUDIENCE`, so a fresh stack's first caller has a resource to name. The dev caller's audience mapper names it, and a server whose ceremony ran before moves by resuming the ceremony and changing its callers' audience (`deploy/dev/README.md`).
  - Not built yet: lifetime-class changes, which change every client whose audience names the resource, and the drift sweep comparing audience mappers.
- ✅ **Application developer standing, non-production creation** (ADR-IAM-003 §5.3; TDD-003 1.21.0 §Application Developers): `identity.application_developer`, and `GET`/`POST /v1/application-developers` and `:revoke`, a provider's.
  - The standing is granted and revoked by a provider with a reason. It is held only by an active human Principal, counted only while the mapping is active, and insert-only but for its revocation columns.
  - `POST /v1/registrations` admits a caller holding the standing. A caller without it is refused before the body is read. Such a caller registers only:
    - in non-production;
    - a public, confidential or resource profile;
    - the `internal` or `external` class. `privileged` carries the provider-scope claim surface, and a workload goes through `/v1/workloads`.
    - an audience naming only resources it owns.
  - It becomes the registration's first owner in the same transaction. The standing is read again there, so one revoked between the two reads creates nothing.
  - `GET /v1/registrations:standing` answers any caller with its own standing and the environment, so a console offers registration only where the API accepts it.
  - identity-experience#23 grants the standing in the Admin Portal and registers from the Developer Console.
- ✅ **Production registration by request** (ADR-IAM-003 §5.3; TDD-003 1.23.0 §Registration Requests): `identity.registration_request`, and `POST /v1/registration-requests`, `GET` (the provider's approval queue), `:mine`, `:approve`, `:reject`, `:withdraw`.
  - In production an application developer requests a registration, naming at least two owners, with a reason. The request is held to the developer's bounds and validated as registration validates. A private key is refused, and the stored key is its public members only.
  - A provider other than the proposer approves it; a check constraint holds that in the database too. The approval registers the document as the proposer's, under the request as its Idempotency-Key. The approval, the owners' grants and the reservation commit together, and an owner who stopped being an active person refuses the approval.
  - One open request per client_key, and the same request retried returns it. Only the proposer withdraws.
  - Outside production nothing is requested: a developer registers directly. In production a developer no longer registers directly.
  - Decided 2026-10-02 (ADR-IAM-003 §5.3, §5.7; TDD-003 1.24.0): a provider still registers directly, as Entra's Application Administrator does. Each direct production registration, through registration, the workload path or adoption, logs a WARN with its path, client and registrant.
  - Backlog, needing its own decision (ADR-IAM-003 §5.7): eligible provider authority. A provider grant would be activated for a bounded time with another provider's approval, as Entra PIM's "Require approval to activate". It changes how organization-control and this service hold provider grants (ADR-ORG-001 §5.11), and is what puts a second person in front of everything a provider does, not only registration.
  - The screens are identity-experience#24.
- ✅ **Workload lifecycle** (TDD-004 1.4.0 §Suspension, Restoration, and Retirement): `POST /v1/workloads/{id}:suspend`, `:restore` and `:retire`, each with a reason.
  - The client and the Principal stop together: the workload lifecycle holds the workload's row lock and changes its registration in the same transaction, through the registration package's `…WorkloadWithin` seams, because the registration lifecycle still refuses a workload's client.
  - A suspension commits, then disables the client and sets its not-before. A restore is refused while the owner is not an active human Principal (reassign first), and writes the client back inside its transaction. A retirement, only after a suspension, deletes the client, revokes its keys, and retires the Principal's mapping, so the dangling sweep does not report the deleted service-account user.
  - Each change is recorded in the registration's insert-only `registration_state_change`, naming who asked and why.
- **Kernel scopes:** `identity-kernel` declares `scnehaux-workload` (identity-kernel#23). It still has to declare a tenant-scope privileged scope before registrations of that class can exist, and that waits on the context projection.

## Account security and investigation (TDD-identity-control-005)

Built in the order TDD-005 §Build Order states, one PR per slice:

- ✅ **1 · Administrative reads.** `GET /v1/principals:search?q=`, `GET /v1/principals/{principal_id}` and its `/sessions`, `/authenticators`, `/federation-links` and `/findings`, all provider-only.
  - Search is a prefix lookup on the username or email this service holds, never a listing: fewer than `IDENTITY_ADMIN_SEARCH_MIN_LENGTH` characters that are not wildcards is refused, a wildcard is literal, and a page holds at most `IDENTITY_ADMIN_SEARCH_PAGE_SIZE`.
  - Sessions, authenticators and federation links are read from the kernel through the Admin API's user sub-resources, with the Principal credential's `view-users`. No IP address, no credential secret or data, and no kernel identifier leaves the service.
  - An authenticator carries a `security_ref`: its kernel identifier sealed with AES-256-GCM (RFC 5116), bound to the kind, the subject Principal and the revocation purpose, for `IDENTITY_SECURITY_REF_TTL`. The key ring is `IDENTITY_SECURITY_REF_KEY_FILE`, made on a server by `deploy/dev/create-security-ref-key.sh`.
  - Every served read writes one row to the insert-only `identity.privileged_access` (NIST SP 800-53 AU-3, AU-9): actor, subject, action, route, query, result count, correlation and whether the provider authority was emergency. A read whose record does not commit is not served, and a refused or failed read records nothing.
- ✅ **2 · Containment** (TDD-005 2.2.0 §Containment as Built). `POST /v1/principals/{id}:suspend`, `:restore`, `/sessions:terminate-all`, `/authenticators/{security_ref}:revoke`, and `GET /v1/security-operations/{id}`. All are provider-only, for human Principals.
  - Each command carries an `Idempotency-Key`, an `X-Administrative-Reason`, and `expected_version`, which `GET /v1/principals/{id}` serves as `security_version`. Each needs an authentication within `IDENTITY_STEP_UP_MAX_AGE`; an older one is answered `401 insufficient_user_authentication` (RFC 9470).
  - A provider cannot act on its own Principal. A workload is refused with the `/v1/workloads` route.
  - **Acceptance.** It is one transaction: the idempotency lookup first, then the mapping (`active ⇄ suspended`), the version and sequence in `security_subject_state`, and the operation.
  - **Execution.** A lease. A `SKIP LOCKED` claim takes an operation only when every earlier operation of the same Principal is final, writes an attempt row, and commits before the kernel calls. A second transaction writes the outcome, with the `privileged_access` row when it is final.
  - **Retries and parking.** A transient failure is retried with full-jitter backoff. After `IDENTITY_SECURITY_MAX_ATTEMPTS`, or after a permanent failure, the operation is parked as `unresolved`, logged as `security operation unresolved`, and blocks that Principal's later commands.
  - **Kernel calls.** `suspend` disables the user and logs it out. A disable alone only pauses the sessions (identity-kernel compat run 37125613572). `restore` enables the user. Every call is read back before the operation counts as applied.
  - **Revocation.** It refuses the last first factor (`last_authenticator`). On this realm that is the password, so a compromised password is contained by suspension.
  - Inline within `IDENTITY_SECURITY_COMMAND_BUDGET`, a command answers `200` with the final operation. Otherwise it answers `202` with `Location`. The executor runs every `IDENTITY_SECURITY_EXECUTOR_INTERVAL`.
  - ✅ **Operating the executor** (TDD-005 2.5.0, STD-GLB-011 §3.9 and §3.15).
    - `GET /v1/security-operations:unresolved` lists parked operations.
    - `POST /v1/security-operations/{id}:redrive` gives one a new attempt budget (`redriven_at`), with `aal2`, freshness and a reason. It is evidenced, keeps the operation's correlation, and nothing abandons one.
    - The executor's accepted, attempts, wait, duration, lease-lost, unresolved and re-drive metrics go over OTLP to `OTEL_EXPORTER_OTLP_ENDPOINT`, as organization-control's do.
- ✅ **3a · Self-service sessions and authenticators** (TDD-005 2.3.0 §Self-Service as Built). The self routes are `GET /v1/me/sessions`, `POST /v1/me/sessions/{security_ref}:terminate`, `POST /v1/me/sessions:terminate-all`, `GET /v1/me/authenticators`, `POST /v1/me/authenticators/{security_ref}:remove`, and `GET /v1/me/security-operations/{id}`.
  - **Route class `self`** (`selfOnly`). The subject is the token's `principal_id`, and the route test requires the wrapper.
  - **Reads.** They are not evidenced. Each object carries a reference sealed for a self purpose, which opens on no administrative route. A session is marked `current` by the token's `sid`; identity-kernel compat run 37137921752 proves that `sid` is the listed session identifier.
  - **Commands.**
    - Each carries an Idempotency-Key and no reason or version. It records and advances the subject's `security_version`, and shares one sequence with administrative commands.
    - Only an `active` Principal may command. `:remove` needs step-up and keeps the last first factor.
    - Each final state is evidenced with the actor equal to the subject.
- **3b · Consents.** `GET /v1/me/consents` and `:withdraw` wait for identity-kernel's compat proof of the consent listing and revocation, and for a registered client that asks for consent.
- ✅ **Provider routes at two factors** (ADR-IAM-004; TDD-005 2.4.0 §Step-Up).
  - Every `providerOnly` route requires `acr` `aal2`, reads included, under NIST SP 800-53 IA-2(1). `/v1/me/authenticators/{ref}:remove` requires `aal2` and freshness.
  - A shortfall is answered with RFC 9470's challenge carrying `acr_values="aal2"`, plus `max_age` for a command.
  - `IDENTITY_ASSURANCE=report` serves a lower token and logs it, only while a server's kernel lacks identity-kernel's level mapping.
  - `scripts/dev-token.ps1` takes `-AcrValues aal2 -Otp`.
  - On a development server, `-EnrollTotpFile` binds a second TOTP for the bootstrap operator at `aal2`, using one code from the owner, and `-TotpSecretFile` computes codes from it (ADR-IAM-004 §5.5; identity-kernel compat proves `kc_action=CONFIGURE_TOTP`).
  - The CI stack enforces it. The smoke and Proof B enroll the bootstrap operator's TOTP on their first sign-in (`-OperatorTotpFile`), then sign in at `aal2` with codes computed from it. Each code is used once, as the realm's OTP policy requires.
- **4 · Enrollment and the assurance floor.** The kernel's levels exist (identity-kernel TDD-001 §Authentication Levels); enrollment through this API and WebAuthn are next.

## Waiting on the Keycloak proof-of-concept

Each item names the question that unblocks it. All of them are adapters, which is why
none of them blocks the work above.

| Component | Blocked by |
| :-- | :-- |
| ~~`KeycloakAdminClient` create and search~~ | ✅ Unblocked. Attribute search is exact, case-insensitive, and pages without loss (`identity-kernel` question 2). `FindByPrincipalID` now reads every page |
| ~~Pending-state recovery strategy~~ | ✅ Unblocked by the same answer. Recovery branches on the count as designed |
| `KeycloakProjector` | Projected context representation — Organizations, Groups, or user attributes |
| `SessionContainer` | Session removal granularity — per Principal and Tenant context, or per Principal only |

The remaining proof-of-concept questions — protocol mapper coverage, attribute
immutability, issuer URI form, context switch mechanism — are answered in
`identity-kernel` and change realm configuration rather than code here.

`identity-kernel` has since answered two of them against the digest-pinned 26.7.4, in
compat runs 36105049194 and 36106484382:

- **Protocol mapper coverage: confirmed.** All four surfaces carry the claims. An
  `oidc-audience-mapper` is still required for `aud`, and introspection is
  audience-restricted.
- **Attribute immutability: corrected.** The provisional answer said "the user profile
  controls it", which is true of the user only.
  - An administrator's edit is applied.
  - No declarative profile gives write-once: an attribute nobody may edit is silently
    dropped at creation.
  - Against administrators, immutability rests on who holds `manage-users` plus reconciler
    detection. TDD-identity-control-001 records it.
  - An undeclared attribute is still discarded outright, so the declaration remains
    mandatory.

## Development server

✅ [`deploy/dev/`](deploy/dev/README.md) runs this service beside `identity-kernel`'s development
Keycloak. CI brings up the same stack end to end against the kernel's `main`:

- the realm is applied;
- this service's clients are registered;
- the Control Database is migrated;
- the bootstrap ceremony is performed, and a second ceremony is refused;
- the smoke suite runs with a provider-scope token from the kernel's login form.

What it runs:

- **Two images from one Dockerfile.** Both are digest-pinned (SAD-001 §7.6), and every base carries
  the tag it was resolved from beside it:
  - the service, on distroless as a non-root user;
  - the migration job, on the Postgres image. It runs the same four-source pipeline as
    `scripts/dev-database.ps1`.
- **Its own Control Database** (EAD-003). It reaches Keycloak over the kernel's
  `scnehaux-identity-api` network, which carries Keycloak alone.
- **Two clients, registered by `create-kernel-clients.sh`:**
  - The Admin API client holds `manage-users` and `view-users` and nothing else, as this repository's
    TDD-001 states.
  - The development caller uses Authorization Code with PKCE and the kernel's `scnehaux-provider`
    scope, with a 240-second token (class `L0`).

The realm itself is `identity-kernel`'s. Nothing here writes a scope, attribute, or key.

Two decisions are recorded here:

- **Client registration uses its own credential. Decided on 2026-09-26.** `TDD-identity-control-003`
  registers protocol clients through the Admin API, which needs `manage-clients`. It gets a separate
  Keycloak client, `identity-control-registration`, holding `manage-clients`, `view-clients` and
  `view-events` only, so the Principal path keeps its narrow set and TDD-001 and TDD-002 stay true.
  Recorded in TDD-003's Security Notes. `deploy/dev/create-registration-client.sh` creates it, and
  `scripts/dev-credential-split.ps1` asserts in `deploy-dev` that neither credential can do the
  other's work.
- **Container images have no enterprise standard.** SAD-004 says only "compiled as an OCI image".
  The images here follow the kernel's precedent: pinned digests, distroless, non-root. Scanning the
  built image for vulnerabilities, which SAD-001 §7.6 requires, is not yet in CI. Both are
  production-gate items.

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

✅ **This service's own Keycloak clients authenticate with keys**, development included. That
covers `identity-control`, `identity-control-registration`, and the development caller.
`STD-IAM-001 §3.2` allows no client secret in any shared environment.

- `internal/keycloak` signs an RFC 7523 assertion (PS256, the key's RFC 7638 thumbprint as
  `kid`) and reads its audience from the realm's discovery. Client-secret support is removed.
- The scripts make the keys with identity-kernel's `client-key` tool, and the kernel holds only the
  public halves.
- `deploy-dev` runs the whole stack on keys: the credential split, the smoke test, and Proof B.

**The first-Principal bootstrap blocker is cleared.** `ADR-IAM-001 §5.11` decided it and
`cmd/identity-bootstrap` implements it, so standing up a production realm no longer requires the
out-of-band `INSERT` that `ADR-ORG-001` prohibits. What remains for the production gate is
operational rather than architectural: the ceremony needs a runbook naming who is authorized to
perform it and where the record is reviewed, since the evidence is worthless if nobody reads it.
