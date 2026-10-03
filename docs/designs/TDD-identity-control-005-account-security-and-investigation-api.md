---
doc_meta:
  id: TDD-identity-control-005
  title: Account Security and Investigation API Mediation
  owner: Core Platform Team
  version: 2.3.1
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-14
  last_reviewed: 2026-10-03
  parent_sad: SAD-001
---

# Account Security and Investigation API Mediation

## Purpose

Define the Identity Control API used by account-security and identity-administration
experiences to inspect and change sessions, authenticators, consents, federation links,
reconciliation findings, and Principal containment state.

The kernel remains the physical authority for sessions, credentials, consents, and
federation links. Identity Control supplies enterprise authorization, canonical
Principal resolution, last-authenticator guards, idempotency, evidence, and a stable
API that does not expose Keycloak identifiers or unsupported kernel interfaces.

## Scope

**In scope**

- Self-service session, authenticator, and consent operations.
- Privileged Principal search, security-state inspection, suspension, restoration,
  retirement, session termination, and authenticator revocation.
- Mapping canonical `principal_id` values to kernel objects without exposing kernel
  identifiers.
- Step-up requirements, self-action boundaries, reason capture, idempotency, retry,
  and evidence publication.
- Read access to reconciler findings and enterprise audit events.

**Out of scope**

- Authentication ceremonies and authenticator material, which remain in Keycloak.
- Browser session and CSRF handling, owned by `identity-experience`.
- Principal creation and retirement state rules, owned by
  `TDD-identity-control-001` and mediated here.
- Enterprise evidence retention, owned by Audit and Evidence.
- Organization, Tenant, Workspace, and Membership authority.

## Technical Context

SAD-002 requires the BFF to proxy every `/api/v1/*` request to Identity Control and
requires the API to reauthorize every command. The experience designs already define
the user-facing routes; this document defines their upstream contract.

Three identifiers must remain separate:

| Identifier | Visibility | Purpose |
| :-- | :-- | :-- |
| `principal_id` | Enterprise API | Stable subject identity |
| `security_ref` | One API response and subsequent command | Opaque reference to one session, authenticator, consent, or federation link |
| Keycloak object identifier | Identity Control and kernel adapter only | Supported Admin API operation |

Security references are authenticated, encrypted handles. They bind object type,
canonical Principal, kernel identifier, realm, issued time, and expiry. A handle for
one Principal or object type cannot be replayed against another route.

They are sealed with AEAD_AES_256_GCM (RFC 5116), which gives the plaintext confidentiality and
"a way to check its integrity and authenticity", and the same check for "some Associated Data"
[R5]. The associated data is the object type, the subject `principal_id` and the route, so a handle
opened for another of those fails authentication instead of decrypting. The key ring carries a
`kid` per key, and a retired key stays for one TTL so a handle sealed before a rotation still
opens.

## What Changed in 2.0.0

Version 1.0.0 predates five decisions this design now follows:

| Decision | Where it is decided | What changes here |
| :-- | :-- | :-- |
| A provider is a Principal this service's projection of Organization's grants names, for each request | ADR-ORG-002 §5.3, `TDD-identity-control-006` | Every administrative route is a provider's. The "investigation capability" of 1.0.0 is that decision |
| A caller's token names `identity-control-api`, is a person's, and carries no `provider_scope` | STD-IAM-002 §3.1, `TDD-identity-control-001` §Caller Token | `/v1/me/*` serves any person, as themselves. A workload's token is refused |
| An administrative reason is the `X-Administrative-Reason` header, visible US-ASCII | STD-GLB-001 §Request Header Values | Reason is a header on every route, not a body field |
| Containment is reversible, and distinct from the reconciler's integrity hold | §Containment Is Reversible, `TDD-identity-control-001` 1.12.0 | `:quarantine` and `:release` become `:suspend` and `:restore` |
| The enterprise Audit platform does not exist yet | PAD-PLT-007 | Evidence is an insert-only table here (§Evidence). `GET …/events` waits for the Audit API |

**Route classes.** Every route is exactly one of three, and a test fails on a route that is none:
`self` (any person, acting on the Principal in its token), `providerOnly` (the provider decision of
`TDD-identity-control-006`, with each emergency use reported), and `owned` (a registration owner,
`TDD-identity-control-003`). The self-action boundary still holds inside `providerOnly`: a provider
cannot suspend, restore, or revoke an authenticator of, the Principal in its own token.

**Build order**, each slice shippable alone:

1. Administrative reads: search, one Principal, its sessions, authenticators and federation links,
   and privileged-read evidence. These need `security_ref` and the kernel adapter.
2. Containment: suspend, restore, terminate all sessions, and revoke one authenticator, through the
   durable operation executor.
3. Self-service: `/v1/me/sessions`, `/v1/me/authenticators` and `/v1/me/consents`.
4. Enrollment, and the last-authenticator guard's assurance floor, once the kernel defines levels of
   authentication (§Step-Up).

## Self-Service as Built (2.3.0)

Slice 3 is built in two parts. **3a**, built here, is a person's own sessions and authenticators.
**3b** is consents. It waits for two things: identity-kernel's compat suite has to prove the consent
listing and revocation, which needs a client that asks for consent, and a registered client has to
require consent at all. Until then, `GET /v1/me/consents` is not served.

**Route class `self`.**
- The subject is the `principal_id` in the token, and no path segment names it.
- Any person's token is accepted, provider or not. A workload's token is already refused by the
  claim rule.
- Self reads write no `privileged_access` row: a person reading their own security state discloses
  nothing to anyone (`TDD-identity-experience-003` §Testing Strategy, Privileged Reads).

```text
GET   /v1/me/sessions
POST  /v1/me/sessions/{security_ref}:terminate
POST  /v1/me/sessions:terminate-all
GET   /v1/me/authenticators
POST  /v1/me/authenticators/{security_ref}:remove
GET   /v1/me/security-operations/{operation_id}
```

**Reads.**
- Each session and authenticator carries a `security_ref` sealed for the caller.
  - A session's is sealed for `self.session.terminate`.
  - An authenticator's is sealed for `self.authenticator.remove`.
  - Neither opens on the administrative routes, which use other purposes.
- A session also carries `current: true` when its identifier equals the token's `sid`. STD-IAM-002
  §3.2 admits `sid` in the access token as "the session identifier OpenID Connect logout defines"
  [R16]. identity-kernel's compat suite proves that `sid` is the identifier the Admin API lists the
  session under.

**Commands.**

| Operation | Calls, each read back |
| :-- | :-- |
| `session.terminate` | `DELETE /admin/realms/{realm}/sessions/{session}`, Keycloak's "Remove a specific user session" [R14]. It is applied once the session is absent from the user's list, including when it was already absent |
| `sessions.terminate-all` | As the administrative one. It ends the caller's current session as well |
| `authenticator.remove` | As `authenticator.revoke`, with the same last-first-factor guard |

- **What a self command carries.** It carries an `Idempotency-Key` and nothing else: no reason and
  no `expected_version`. §Data Model already makes the reason "absent for ordinary self-service
  operations". The operation records the subject's version at acceptance as `expected_version`, and
  advances it as every command does.
  - An administrator's next command therefore names a newer `security_version`. That is the point:
    the record changed.
  - Self and administrative commands share one sequence per Principal, so they run in the order they
    were accepted.
- **State.** The Principal must be `active`. A suspended person's token can outlive the suspension by
  at most its lifetime, and a command from it is refused with `409`.
- **Step-up.** `:remove` requires `auth_time` within `IDENTITY_STEP_UP_MAX_AGE`, as §Step-Up says for
  authenticator changes. Ending a session never does: it removes access, it does not gain any.
- **Evidence.** The final state writes its `privileged_access` row, as every command's does (§Evidence),
  with the actor and the subject the same Principal and `emergency` false.
- **Following a `202`.** `GET /v1/security-operations/{operation_id}` stays `providerOnly`. A person
  follows their own command at `GET /v1/me/security-operations/{operation_id}`, which answers only
  for an operation whose subject is the caller and is `404` for any other. This keeps every route in
  one class.
- **What ending a session does not reach.** It ends the Keycloak session and its refresh token.
  An access token already issued from that session stays valid until its `exp`: at most 240 seconds
  for this service's `L0` callers (STD-IAM-002 §3.3). Every resource server verifies the token
  locally (STD-IAM-002), and none asks the kernel whether the session is still alive. This is the
  same window §Containment as Built states for a suspension. The development server observed it on
  2026-10-03: the ended session's access token was still accepted, and its refresh token was refused.
- **A handle differs on every read.** Each seal draws a fresh nonce and its own expiry (§Technical
  Context), so the same session or authenticator gets a new `security_ref` each time it is listed.
  A handle is used within its TTL. It is not an identifier to keep or compare.
- **After `terminate-all`.** The BFF ends its own session as well (`TDD-identity-experience-001`), because
  the Keycloak session behind it is gone.

## Containment as Built (2.2.0)

Slice 2 builds `:suspend`, `:restore`, `sessions:terminate-all`, `authenticators/{security_ref}:revoke`
and `GET /v1/security-operations/{operation_id}`. This section records what the sections below left
open, and each decision's source.

**Subjects.** These routes act on human Principals. A workload is suspended and restored through
`TDD-identity-control-004`, whose lifecycle stops the client and the Principal together, so a
workload here is refused with `409` and the route to use. `:retire` is not in the slice, and waits for
human retirement in `TDD-identity-control-001`.

**The version a command names.** `expected_version` is `security_subject_state.version`.
`GET /v1/principals/{principal_id}` serves it as `security_version`, `1` before any command, as the
column's default. A command that names another version is refused with `409` `version-conflict`
before anything is written. STD-GLB-004 §3.11 asks that a mutation of a versioned aggregate "carry/compare the
... aggregate version needed to prevent an older delivery from overwriting a newer accepted state"
[R12].

**Idempotency.** The key is unique per actor, `UNIQUE (actor_principal_id, idempotency_key)`, and the
operation keeps `request_digest`, a SHA-256 over the operation type, subject, reference, expected
version and reason.
- The same key with the same request returns the same operation in its current state, and never
  repeats an effect.
- The same key with another request is refused with `409` `idempotency-key-conflict`, foundation-platform's registered type.
  The idempotency-key draft says a key "MUST NOT be reused with another request with a different
  request payload" [R7].

**State.** The acceptance transaction checks the mapping state and changes it.
- `:suspend` takes a mapping from `active` to `suspended`.
- `:restore` takes it back from `suspended` to `active`.
- Both increment `principal_mapping.version`.
- Any other state is refused with `409` `state-transition-refused`, as is a mapping with no kernel
  user.
- `sessions:terminate-all` and `:revoke` accept a Principal that is `active` or `suspended`. A
  credential can be revoked while its Principal is contained.
- `:restore` is also refused while any unresolved `principal_finding` names the Principal. The one
  finding class, `dangling`, means the kernel user is gone.

**A repeated key first.** The idempotency key is looked up before any check that the operation's
own effect could change. A repeated request finds its operation and returns it, even though that
operation moved the version and the mapping state it was checked against.

**Refusal order.** For a new key, each refusal below happens before anything is written:
1. Provider authority (`403`).
2. The self-action boundary (`403`).
3. `Idempotency-Key`, `X-Administrative-Reason` and `expected_version` (`400`).
4. Step-up (`401`, §Step-Up).
5. The subject (`404`, or `409` for a workload or a disallowed state).
6. The version (`409`).
7. The same key with another request (`409`), found by the first lookup.

A `security_ref` that does not open for this subject and purpose is `404`. The codec reports one error
for every reason a handle fails, so the response cannot tell a caller which check failed.

**Step-up.** The authentication middleware carries the token's `auth_time` and `acr` in the request
context. A command is refused once `now - auth_time` exceeds `IDENTITY_STEP_UP_MAX_AGE`. The
operation's `assurance` records `acr=<acr>;auth_time=<RFC 3339>`. The BFF must treat this `401` as a
re-authentication request, not as an expired session.

**Execution.** STD-GLB-011 governs the executor, because it is a background job.
- **Acceptance is durable.** The operation is inserted in the transaction that changes the owner
  state, as §3.3 requires: acceptance must be "transactionally coordinated with the owner state that
  requires the Job" [R11].
- **Claim.** A worker claims a due operation in a short transaction:
  `SELECT … FOR UPDATE SKIP LOCKED`. PostgreSQL documents SKIP LOCKED as a way "to avoid lock contention with multiple consumers
  accessing a queue-like table" [R8].
- **Sequence.** The claim takes an operation only when no earlier `subject_sequence` of the same
  Principal is `pending`, `retrying` or `unresolved`. Commands on one Principal run in the order
  they were accepted.
- **Lease.** The claim moves `next_attempt_at` forward by `IDENTITY_SECURITY_OPERATION_LEASE` and
  commits before any kernel call. No transaction is held across a remote call. A worker that dies
  leaves the operation claimable again when the lease ends. This is Amazon SQS's visibility timeout,
  where "if you don't delete it before the timeout expires, the message becomes visible again in the
  queue" [R9]. STD-GLB-011 §3.4 asks that "lease expiry/recovery semantics MUST be deterministic"
  [R11].
- **Attempts.** Each claim inserts a row in the insert-only `security_operation_attempt`, numbered
  from 1. The operation is the job and the row is the attempt, so the two identifiers stay distinct,
  as §3.4 asks [R11].
- **Backoff.** A transient failure (kernel unavailable, timeout, `5xx`) is retried after a full-jitter
  delay, `random(0, min(30s, 1s × 2^attempt))`. That is AWS's formula
  `sleep = random(0, min(cap, base * 2 ** attempt))`: "The solution isn't to remove backoff. It's to
  add jitter" [R10].
- **Dead letter.** A permanent failure (`403`, or `404` for the user) is not retried, as STD-GLB-011
  §3.6 requires. After `IDENTITY_SECURITY_MAX_ATTEMPTS`, or after a permanent failure, the operation
  becomes `unresolved`.
  - It is logged at ERROR as `security operation unresolved`, the alert signal.
  - It blocks later operations of the same Principal until an operator resolves it. STD-GLB-004
    §3.10 says "DLQ/parking is not disposal" [R12].
- **Inline execution.** The request that accepted a command runs one claim-and-execute of it within
  `IDENTITY_SECURITY_COMMAND_BUDGET`. If it is final, the response is `200` with the operation.
  Otherwise the response is `202` with `Location: /v1/security-operations/{operation_id}`.
  RFC 9110 says a 202 representation "ought to describe the request's current status and point to
  (or embed) a status monitor" [R13].
- **Background executor.** It claims due operations every `IDENTITY_SECURITY_EXECUTOR_INTERVAL`,
  using the service's own Admin API client, which is a non-human identity as STD-GLB-011 §3.2 asks.

**Each command's kernel calls.** Every call is idempotent. An operation is applied only once its
read-back agrees.

| Operation | Calls | Applied when |
| :-- | :-- | :-- |
| `suspend` | `PUT /users/{id}` with `enabled: false`, then `POST /users/{id}/logout` | The user reads back disabled and its session list is empty |
| `restore` | `PUT /users/{id}` with `enabled: true`. No session is restored | The user reads back enabled |
| `sessions.terminate-all` | `POST /users/{id}/logout` | The session list is empty |
| `authenticator.revoke` | Re-read the credentials, then `DELETE /users/{id}/credentials/{credentialId}` | The credential is absent. It is also applied if it was already absent |

Keycloak's own descriptions of these endpoints are "Remove all user sessions associated with the
user" and "Remove a credential for a user" [R14]. `authenticator.revoke` re-reads the credentials
before deleting (§Authenticator Guard). A refusal is final, not retried.

**What "usable" means.** The guard counts first factors, the credentials that can begin a sign-in.
The realm uses Keycloak's built-in browser flow, whose "first execution is the Username Password
Form … It is marked as required, so the user must enter a valid username and password" [R15]. A
passkey (`webauthn-passwordless`) is the other first factor Keycloak offers, once a flow admits it.
- Revoking a first factor is refused, with `result_code` `last_authenticator`, when no other first
  factor would remain.
- Revoking a second factor (`otp`, `webauthn`) or a recovery code is never refused by the guard.

So on this realm a password cannot be revoked. A compromised password is contained by suspension
until the self-service slices bring a reset.

The operation stores the sealed reference, never the kernel identifier. The handle's TTL bounds how
long a browser may use it, so the executor opens a stored handle without the expiry check. The
handle was already checked when the command was accepted, and its kind, subject and purpose binding
still hold.

**Evidence.** The transaction that marks an operation `applied` or `refused` also writes its
`privileged_access` row.
- `action` is the operation type, and `outcome` is `applied` or `refused`.
- The row records the reason and the correlation identifier.
- `emergency` is the actor's basis at acceptance, which the operation keeps.

A refusal before acceptance writes no row. The request log records it, with its status and
correlation identifier.

**Reads of an operation.** `GET /v1/security-operations/{operation_id}` is `providerOnly` in this
slice. It returns the operation's identifier, subject, type, state, attempts, result code and times,
and never the reference or an error's text.

**Package.** The reference codec built in slice 1 is `internal/securityref`, not
`internal/securitystate`. It is a pure AEAD codec that both the read path and the commands use.

## Component Design

| Component | Package | Responsibility |
| :-- | :-- | :-- |
| `SecurityStateService` | `internal/securitystate` | Self and administrative read models |
| `SecurityCommandService` | `internal/securitystate` | Authorization, command validation, idempotency, and durable acceptance |
| `SecurityOperationExecutor` | `internal/securitystate` | Serialized supported Admin API side effects and retry |
| `SecurityReferenceCodec` | `internal/securitystate` | Seals and opens short-lived opaque object references |
| `PrincipalSearchService` | `internal/investigation` | Bounded, evidenced search |
| `EvidenceReader` | `internal/investigation` | Reconciler findings and Audit API reads |
| `KeycloakSecurityClient` | `internal/keycloak` | Typed supported Admin REST and OIDC action adapter |

The adapter uses supported interfaces only:

| Capability | Kernel interface |
| :-- | :-- |
| List a user's sessions | Admin REST user-session listing |
| Terminate one session | Admin REST session deletion |
| Terminate all sessions | Admin REST user logout |
| List or remove authenticators | Admin REST credential listing and deletion |
| Begin enrollment | OIDC application-initiated action rendered by the kernel |
| List or withdraw consent | Admin REST user-consent listing and revocation |
| List federation links | Admin REST federated-identity listing |
| Suspend or restore | Admin REST user disable or enable |

No account-console private endpoint, Keycloak database access, or credential-material
read is permitted.

## Data Model

Identity Control does not copy live session, authenticator, consent, or federation-link
state. It stores only command durability and local findings.

```sql
CREATE TABLE identity.security_subject_state (
    principal_id       UUID        PRIMARY KEY
        REFERENCES identity.principal_mapping(principal_id),
    version            BIGINT      NOT NULL DEFAULT 1,
    next_sequence      BIGINT      NOT NULL DEFAULT 1,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE identity.security_operation (
    operation_id       UUID        PRIMARY KEY,
    principal_id       UUID        NOT NULL
        REFERENCES identity.security_subject_state(principal_id),
    subject_sequence   BIGINT      NOT NULL,
    actor_principal_id UUID        NOT NULL,
    idempotency_key    TEXT        NOT NULL,
    request_digest     TEXT        NOT NULL,
    operation_type     TEXT        NOT NULL,
    sealed_object_ref  TEXT,
    expected_version   BIGINT      NOT NULL,
    reason             TEXT,
    correlation_id     TEXT        NOT NULL,
    assurance          TEXT        NOT NULL,
    emergency          BOOLEAN     NOT NULL,
    state              TEXT        NOT NULL DEFAULT 'pending',
    attempts           INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    result_code        TEXT,
    last_error_class   TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at         TIMESTAMPTZ,
    CONSTRAINT security_operation_state_check
        CHECK (state IN ('pending', 'retrying', 'applied', 'refused', 'unresolved')),
    CONSTRAINT security_operation_type_check
        CHECK (operation_type IN ('suspend', 'restore', 'sessions.terminate-all', 'authenticator.revoke',
                                  'session.terminate', 'authenticator.remove')),
    UNIQUE (principal_id, subject_sequence),
    UNIQUE (actor_principal_id, idempotency_key)
);

CREATE INDEX security_operation_claim
    ON identity.security_operation (next_attempt_at, created_at)
    WHERE state IN ('pending', 'retrying');

-- One row per claim: the operation is the job, the row its attempt (STD-GLB-011 §3.4). Insert-only
-- but for its own finish, which the attempt's worker writes once.
CREATE TABLE identity.security_operation_attempt (
    operation_id  UUID        NOT NULL REFERENCES identity.security_operation(operation_id),
    attempt       INTEGER     NOT NULL,
    claimed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_until   TIMESTAMPTZ NOT NULL,
    finished_at   TIMESTAMPTZ,
    outcome       TEXT,        -- applied, refused, retry, unresolved
    error_class   TEXT,
    PRIMARY KEY (operation_id, attempt)
);
```

The command transaction locks `security_subject_state`, checks `expected_version`,
allocates `subject_sequence`, increments the version, and inserts the operation. This
serializes security mutations for one Principal and makes accepted work recoverable
before a remote call. `reason` is mandatory for administrative mutations and absent
for ordinary self-service operations.

## API / Interface

The BFF removes the `/api` prefix when forwarding. These are Identity Control routes:

```text
GET   /v1/me/sessions
POST  /v1/me/sessions/{security_ref}:terminate
POST  /v1/me/sessions:terminate-all
GET   /v1/me/authenticators
POST  /v1/me/authenticators:enroll
POST  /v1/me/authenticators/{security_ref}:remove
GET   /v1/me/consents
POST  /v1/me/consents/{security_ref}:withdraw

GET   /v1/principals:search
GET   /v1/principals/{principal_id}
GET   /v1/principals/{principal_id}/sessions
GET   /v1/principals/{principal_id}/authenticators
GET   /v1/principals/{principal_id}/federation-links
GET   /v1/principals/{principal_id}/findings
POST  /v1/principals/{principal_id}:suspend
POST  /v1/principals/{principal_id}:restore
POST  /v1/principals/{principal_id}:retire
POST  /v1/principals/{principal_id}/sessions:terminate-all
POST  /v1/principals/{principal_id}/authenticators/{security_ref}:revoke

GET   /v1/security-operations/{operation_id}
```

Every mutation requires `Idempotency-Key`. Administrative mutations additionally require
`expected_version` in the body and `X-Administrative-Reason`, visible US-ASCII
(STD-GLB-001 §Request Header Values). The correlation identifier is the one the request
middleware assigns or accepts, and it is recorded on the operation. `GET
/v1/principals/{principal_id}/events` is not offered until the Audit API exists. Until then the
evidence is the insert-only record this service keeps (§Evidence). A command returns its final
result when execution completes inside the request budget; otherwise it returns
`202 Accepted` with an operation URL. Repeating the same idempotency key returns the
same operation and never repeats a completed side effect.

An assurance refusal follows RFC 9470 (§Step-Up).
Enrollment success returns an allowlisted kernel action identifier and redirect target;
the BFF drives the OIDC action. Identity Control never accepts or returns authenticator
material.

## Algorithms / Logic

### Read Authorization and Disclosure

```text
self read:
    derive principal_id from the verified token
    resolve the mapping internally
    read kernel state and return normalized, paged records

administrative read:
    require the matching investigation capability
    reject an empty or wildcard-only search and enforce minimum specificity
    emit a privileged-read event with actor, query, subject, result count, and purpose
```

Session responses expose when the session started, when it was last used, the clients
it holds, and whether it is the caller's own. They do not expose raw IP addresses,
user-agent strings, or kernel session identifiers. 1.0.0 also listed device class and
approximate location. The kernel's session record holds neither, and deriving a location
would need a geolocation source this estate does not have, so both are left out rather
than guessed. Authenticator responses expose type, label, creation time,
last use, and policy-relevant factor class, never credential data.

### Durable Command Execution

```text
accept(command):
    authorize actor and operation
    validate assurance, self-action boundary, reason, and expected version
    seal or validate the object reference against subject and route
    transactionally append the next subject operation and increment subject version
    execute inline within the request budget or let the executor claim it

execute(operation):
    claim only the next unapplied sequence for the subject
    read current kernel state
    re-evaluate state-dependent guards
    perform one idempotent or read-back-verifiable Admin API action
    mark applied or refused and publish the evidence event atomically
```

The executor retries three times with bounded exponential backoff. An ambiguous remote
result is read back before retry. A command that remains unresolved enters the local
consumer DLQ state and alerts; a suspension or session-termination command is never
discarded.

### Authenticator Guard

Enrollment and removal require fresh step-up. Immediately before removal, the executor
re-reads usable authenticators and the Principal's assurance policy. It refuses when
the target is the last usable authenticator or removal would fall below the policy
floor. Subject sequencing prevents two concurrent removals from both validating
against the same pre-removal count.

### Session and Consent Semantics

`terminate-all` includes the session that issued the request. After success, the BFF
destroys its own session. Consent withdrawal prevents the next grant but does not claim
to revoke an already-issued access token; the response includes the registered token
lifetime bound for presentation by the experience.

### Containment Is Reversible

```text
suspend(principal, reason, expected_version):            provider only, not the caller's own
    record desired state: active -> suspended, version + 1, in the operation's transaction
    disable the kernel user                               Admin REST user update, enabled = false
    end every session                                     Admin REST user logout
    complete only when both are read back

restore(principal, reason, expected_version):            provider only, not the caller's own
    refuse while an unresolved critical finding names the Principal
    record suspended -> active, enable the kernel user; no session is restored
```

This is how Microsoft Entra contains a compromised account: clear **Account enabled**, then
**Revoke sessions** [R1], which "invalidates all the refresh tokens issued to applications for a
user (and session cookies in a user's browser)" [R2]. It is reversible by design. Okta's
suspension keeps what the user holds: "Suspended users' app and group memberships are maintained
and are reinstated when the user is unsuspended" [R3]. A suspension here keeps Memberships,
ownerships and grants, and stops only sign-in.

**Not the integrity hold.** 1.0.0 called this quarantine. `TDD-identity-control-001`'s
`quarantined` is the reconciler's hold on a mapping whose invariants are broken, left only by a
relink or a retirement. Making it reversible by an administrator would let a decision about an
incident lift a hold about integrity. So containment is its own state, `suspended`
(`TDD-identity-control-001` 1.12.0).

**What a suspension does not reach.** An access token issued before it stays valid until it
expires. That is at most 240 seconds for this service's `L0` callers, and the lifetime class bounds
it for others (STD-IAM-002 §3.3). This is the same window Entra describes: "For applications using
access tokens, the user loses access when the access token expires" [R1].

Retirement delegates the irreversible state transition to `TDD-identity-control-001`. It
requires the caller to confirm the canonical identifier. The active Membership count 1.0.0
promised before acceptance waits for Organization Control to serve it to a provider, and until
then the confirmation states that the count was not read.

### Step-Up

A command that needs fresh authentication answers as RFC 9470 defines: `401` with
`WWW-Authenticate: Bearer error="insufficient_user_authentication"` and `max_age`, the "allowable
elapsed time in seconds since the last active authentication event" [R4], beside the problem
document. Every administrative mutation, and authenticator enrollment and removal, requires
`auth_time` within `IDENTITY_STEP_UP_MAX_AGE`.

The challenge's `acr_values`, "the authentication context class reference values in order of
preference" [R4], are not sent yet. The realm maps no level of authentication, so every login is
`acr` `1` and there is no stronger class to ask for. Requiring MFA for these commands waits for
identity-kernel to define levels and a step-up flow. Until then freshness is the whole requirement,
and that is the gap the last slice closes.

### Evidence

Every administrative read and every command writes one row to `identity.privileged_access`, in the
transaction that serves or records it:

```sql
CREATE TABLE identity.privileged_access (
    access_id            UUID        PRIMARY KEY,
    actor_principal_id   UUID        NOT NULL,
    subject_principal_id UUID,
    action               TEXT        NOT NULL,   -- search, read.sessions, suspend, ...
    route                TEXT        NOT NULL,
    reason               TEXT,
    query                TEXT,                   -- a search's text, as typed
    result_count         INTEGER,
    outcome              TEXT        NOT NULL,   -- served, applied, refused
    correlation_id       TEXT        NOT NULL,
    emergency            BOOLEAN     NOT NULL,   -- the provider decision's basis was emergency
    recorded_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

The row holds what an audit record must establish: "What type of event occurred; When the event
occurred; Where the event occurred; Source of the event; Outcome of the event; and Identity of any
individuals, subjects, or objects/entities associated with the event" (NIST SP 800-53 AU-3 [R6]).
It holds no kernel identifier and no sealed reference. The runtime role may insert and select it,
and holds no `UPDATE`, `DELETE` or `TRUNCATE`, because audit information is protected "from
unauthorized access, modification, and deletion" (AU-9 [R6]). Organization Control keeps its own
`audit.privileged_access` the same way.

**Why a table and not, as 2.0.0 said, outbox events.** An outbox event is retained only "while any
of its deliveries is unpublished or dead-lettered" (ADR-GLB-018 §5.3). With no consumer subscribed,
none is owed, so the events would be pruned with their partition before the Audit platform exists
to read them. A log line is no better, because nothing protects it from modification. Once the
Audit platform consumes this service, each row is also appended to the outbox in the same
transaction, and the table stays the local record.

## Configuration

| Variable | Default | Purpose |
| :-- | :-- | :-- |
| `IDENTITY_SECURITY_REF_KEY_FILE` | required | The key ring that seals references: one or two 32-byte keys, each with a `kid`, the first used to seal |
| `IDENTITY_SECURITY_REF_TTL` | `10m` | Opaque object-reference lifetime |
| `IDENTITY_STEP_UP_MAX_AGE` | `5m` | Freshness every administrative mutation and authenticator change requires |
| `IDENTITY_SECURITY_COMMAND_BUDGET` | `2s` | Inline execution wait before returning 202 |
| `IDENTITY_SECURITY_ATTEMPT_TIMEOUT` | `500ms` | One supported Admin API attempt |
| `IDENTITY_SECURITY_MAX_ATTEMPTS` | `3` | Attempts before unresolved state |
| `IDENTITY_SECURITY_OPERATION_LEASE` | `10s` | How long a claim hides an operation from other workers. Longer than one attempt's calls: `suspend` makes four, at `IDENTITY_SECURITY_ATTEMPT_TIMEOUT` each |
| `IDENTITY_SECURITY_EXECUTOR_INTERVAL` | `1s` | How often the background executor claims due operations |
| `IDENTITY_ADMIN_SEARCH_MIN_LENGTH` | `3` | Minimum search specificity |
| `IDENTITY_ADMIN_SEARCH_PAGE_SIZE` | `25` | Maximum results per page |
| `IDENTITY_AUDIT_QUERY_TIMEOUT` | `1s` | Enterprise evidence read budget |

Reference encryption keys and the Keycloak administration credential come from the
approved secret manager and have independent rotation schedules.

## Testing Strategy

### Contract

- Every Identity Experience 002 and 003 route maps to one upstream route in this
  document, including federation links and retirement.
- `/me` derives the Principal from the verified token and ignores subject identifiers
  supplied by the browser.
- Every list is paged and no search endpoint accepts an empty or wildcard-only query.
- A kernel identifier, raw IP address, user-agent string, token, or credential never
  appears in an API response.

### Commands and Recovery

- Repeating an idempotency key produces one operation and at most one remote effect.
- A crash after remote success but before local completion is resolved by read-back.
- Two concurrent authenticator removals are sequenced; the second is refused when the
  first leaves one usable factor.
- A request that outlives the inline budget returns 202 and later reaches a final state.
- Three failed priority containment attempts enter unresolved state and alert without
  losing the operation.

### Authorization

- Enrollment and authenticator removal without fresh required assurance are refused.
- A provider cannot suspend, restore, or revoke an authenticator of, themselves.
- A route outside `self`, `providerOnly` and `owned` fails the route test.
- Every administrative read and mutation emits attributable evidence.
- Administrative mutation without reason, version, correlation, or idempotency key is
  refused before any kernel call.

### Kernel Compatibility

- The pinned Keycloak release passes session list/delete, user logout, credential
  list/delete, consent list/revoke, federation-link list, user enable/disable, and OIDC
  application-initiated-action tests through supported interfaces.
- The compatibility suite proves no adapter call reaches a private account-console
  endpoint or the Keycloak database.

## Security Notes

The API is a policy mediation boundary, not a second identity kernel. It stores no
credential material and does not copy volatile kernel security state. Opaque references
prevent browser-visible Keycloak identifiers from becoming ambient authority, and their
subject/type binding prevents confused-deputy reuse across routes.

Privileged reads are evidenced because session, authenticator, federation, and finding
state are useful reconnaissance. Evidence publication contains canonical Principals,
reason, assurance, correlation, and outcome; it excludes sealed references and kernel
identifiers.

## Performance Notes

Reads are paged pass-through projections with one canonical mapping lookup and one
bounded kernel call. The p95 target is 500 ms excluding an unavailable Audit query.
Mutations persist locally before remote execution and return 202 instead of holding a
connection beyond two seconds.

Search always has a specificity floor and page ceiling, so its response size is fixed
independently of Principal population. Rate controls are keyed by acting Principal.

## Operational Notes

| Signal | Warning | Critical |
| :-- | :-- | :-- |
| Security operation age | above 5 seconds | above 30 seconds for containment |
| Unresolved containment operation | none | any occurrence |
| Authenticator removal after recent enrollment | any occurrence | sustained for one Principal |
| Privileged search rate | above configured baseline | ten times baseline |
| Opaque reference decode failure | above baseline | sustained from one actor |
| Audit evidence dependency unavailable | above 1 minute | above 15 minutes |

Runbooks required before production: unresolved containment, locked-out Principal,
suspected directory enumeration, security-reference key rotation, and Audit query
degradation.

## Traceability

| Relationship | Target |
| :-- | :-- |
| Parent system | SAD-001 - Scnehaux Identity Runtime |
| Realizes capability | PAD-PLT-001 - identity administration, account security, and investigation |
| Governed by | ADR-IAM-001 - supported Keycloak interfaces and Control Service mediation |
| Conforms to | STD-IAM-001 sections 3.1 and 3.9 - authenticator policy and BFF authorization boundary |
| Conforms to | STD-GLB-004 - durable external side-effect operation and bounded retry |
| Conforms to | STD-GLB-011 - background job lease, attempts, backoff and dead letter |
| Extends | `TDD-identity-control-001` - Principal containment and retirement state |
| Depends on | `TDD-identity-control-003` - consent client and token-lifetime registration |
| Consumed by | `TDD-identity-experience-002` - self-service account security |
| Consumed by | `TDD-identity-experience-003` - administration and investigation |

## References

| Ref | Source |
| :-- | :-- |
| R1 | Microsoft, *Revoke user access in an emergency in Microsoft Entra ID*, <https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access>, accessed 2026-10-03: "In Properties, clear Account enabled … select Revoke sessions"; "For applications using access tokens, the user loses access when the access token expires." |
| R2 | Microsoft Graph, *user: revokeSignInSessions*, <https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions>, accessed 2026-10-03: "Invalidates all the refresh tokens issued to applications for a user (and session cookies in a user's browser)." |
| R3 | Okta, *Suspend and unsuspend users*, <https://help.okta.com/en-us/content/topics/users-groups-profiles/usgp-suspend.htm>, accessed 2026-10-03: "Suspended users' app and group memberships are maintained and are reinstated when the user is unsuspended." |
| R4 | IETF RFC 9470, *OAuth 2.0 Step Up Authentication Challenge Protocol*, §3, <https://www.rfc-editor.org/rfc/rfc9470>: `insufficient_user_authentication`; `acr_values`; `max_age`. |
| R5 | IETF RFC 5116, *An Interface and Algorithms for Authenticated Encryption*, <https://www.rfc-editor.org/rfc/rfc5116>: AEAD checks the integrity and authenticity of the plaintext and of the associated data; §5.2 defines AEAD_AES_256_GCM. |
| R6 | NIST SP 800-53 Rev. 5, *AU-3 Content of Audit Records* and *AU-9 Protection of Audit Information*, from NIST's OSCAL catalog <https://github.com/usnistgov/oscal-content/blob/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json>, accessed 2026-10-03: AU-3 as quoted in §Evidence; AU-9 a. "Protect audit information and audit logging tools from unauthorized access, modification, and deletion". |
| R7 | IETF, *The Idempotency-Key HTTP Header Field*, draft-ietf-httpapi-idempotency-key-header-07, <https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-idempotency-key-header>, accessed 2026-10-03: "The idempotency key MUST be unique and MUST NOT be reused with another request with a different request payload." |
| R8 | PostgreSQL, *SELECT, The Locking Clause*, <https://www.postgresql.org/docs/current/sql-select.html>, accessed 2026-10-03: "Skipping locked rows provides an inconsistent view of the data, so this is not suitable for general purpose work, but can be used to avoid lock contention with multiple consumers accessing a queue-like table." |
| R9 | Amazon Web Services, *Amazon SQS visibility timeout*, <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html>, accessed 2026-10-03: "If you don't delete it before the timeout expires, the message becomes visible again in the queue and can be retrieved by another consumer." |
| R10 | Marc Brooker, *Exponential Backoff And Jitter*, AWS Architecture Blog, 2015-03-04, <https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/>: "The solution isn't to remove backoff. It's to add jitter."; Full Jitter "sleep = random(0, min(cap, base * 2 ** attempt))". |
| R11 | STD-GLB-011 1.1.0, *Enterprise Background Job Execution Standard*, §3.2–§3.6, §3.9. |
| R12 | STD-GLB-004 3.0.1, *Enterprise Event-Driven Architecture & Messaging Standard*, §3.10 and §3.11. |
| R13 | IETF RFC 9110, *HTTP Semantics*, §15.3.3, <https://www.rfc-editor.org/rfc/rfc9110#section-15.3.3>: "The representation sent with this response ought to describe the request's current status and point to (or embed) a status monitor". |
| R14 | Keycloak, *Admin REST API* (OpenAPI, `docs-api/latest`), <https://www.keycloak.org/docs-api/latest/rest-api/index.html>, accessed 2026-10-03: `POST /admin/realms/{realm}/users/{user-id}/logout` "Remove all user sessions associated with the user"; `DELETE /admin/realms/{realm}/users/{user-id}/credentials/{credentialId}` "Remove a credential for a user"; `PUT /admin/realms/{realm}/users/{user-id}` "Update the user". The pinned kernel, 26.7.5, is proved by identity-kernel's compat suite (§Kernel Compatibility). |
| R15 | Keycloak, *Server Administration Guide*, Authentication flows, the built-in browser flow, <https://www.keycloak.org/docs/latest/server_admin/index.html>, accessed 2026-10-03: "The first execution is the Username Password Form, an authentication type that renders the username and password page. It is marked as required, so the user must enter a valid username and password." |
| R16 | STD-IAM-002 1.4.0, *Token and Verification Profile*, §3.2: the kernel writes `sid` into its access tokens, "the session identifier OpenID Connect logout defines". |
