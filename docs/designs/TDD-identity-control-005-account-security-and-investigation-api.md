---
doc_meta:
  id: TDD-identity-control-005
  title: Account Security and Investigation API Mediation
  owner: Core Platform Team
  version: 1.0.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-14
  last_reviewed: 2026-08-14
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
- Privileged Principal search, security-state inspection, quarantine, release,
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
| Quarantine or release | Admin REST user disable or enable |

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
    operation_type     TEXT        NOT NULL,
    sealed_object_ref  TEXT,
    expected_version   BIGINT      NOT NULL,
    reason             TEXT,
    correlation_id     UUID        NOT NULL,
    assurance          TEXT        NOT NULL,
    state              TEXT        NOT NULL DEFAULT 'pending',
    attempts           INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    result_code        TEXT,
    last_error_class   TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at         TIMESTAMPTZ,
    CONSTRAINT security_operation_state_check
        CHECK (state IN ('pending', 'retrying', 'applied', 'refused', 'unresolved')),
    UNIQUE (principal_id, subject_sequence),
    UNIQUE (actor_principal_id, idempotency_key)
);

CREATE INDEX security_operation_claim
    ON identity.security_operation (next_attempt_at, created_at)
    WHERE state IN ('pending', 'retrying');
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
GET   /v1/principals/{principal_id}/events
POST  /v1/principals/{principal_id}:quarantine
POST  /v1/principals/{principal_id}:release
POST  /v1/principals/{principal_id}:retire
POST  /v1/principals/{principal_id}/sessions:terminate-all
POST  /v1/principals/{principal_id}/authenticators/{security_ref}:revoke

GET   /v1/security-operations/{operation_id}
```

Every mutation requires `Idempotency-Key`. Administrative mutations additionally
require `expected_version`, `reason`, and `correlation_id`. A command returns its final
result when execution completes inside the request budget; otherwise it returns
`202 Accepted` with an operation URL. Repeating the same idempotency key returns the
same operation and never repeats a completed side effect.

An assurance refusal uses Problem Details with `required_acr` and `max_auth_age`.
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

Session responses expose device class, approximate location, first seen, last seen,
and current-session state. They do not expose raw IP addresses, user-agent strings, or
kernel session identifiers. Authenticator responses expose type, label, creation time,
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
consumer DLQ state and alerts; a quarantine or session-termination command is never
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

### Containment and Self-Action Boundary

An administrator cannot quarantine or release their own Principal. Quarantine first
records desired state, then disables the kernel user and terminates all sessions; it is
not complete until both checkpoints are verified. Release requires no unresolved
critical identity finding, enables the user, and restores no prior session.

Retirement delegates the irreversible state transition to
`TDD-identity-control-001`. It requires the caller to confirm the canonical identifier
and returns the active Membership count supplied by the Organization authority before
acceptance.

## Configuration

| Variable | Default | Purpose |
| :-- | :-- | :-- |
| `IDENTITY_SECURITY_REF_TTL` | `10m` | Opaque object-reference lifetime |
| `IDENTITY_SECURITY_COMMAND_BUDGET` | `2s` | Inline execution wait before returning 202 |
| `IDENTITY_SECURITY_ATTEMPT_TIMEOUT` | `500ms` | One supported Admin API attempt |
| `IDENTITY_SECURITY_MAX_ATTEMPTS` | `3` | Attempts before unresolved state |
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
- An administrator cannot quarantine or release themselves.
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
| Extends | `TDD-identity-control-001` - Principal containment and retirement state |
| Depends on | `TDD-identity-control-003` - consent client and token-lifetime registration |
| Consumed by | `TDD-identity-experience-002` - self-service account security |
| Consumed by | `TDD-identity-experience-003` - administration and investigation |
