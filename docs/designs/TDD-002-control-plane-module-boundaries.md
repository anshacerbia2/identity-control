---
doc_meta:
  id: TDD-002
  title: Deployable and Module Boundaries
  owner: Core Platform Team
  version: 0.3.0
  status: draft
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-08-10
  last_reviewed: 2026-08-10
  parent_sad:
    - SAD-001
    - SAD-004
---

# Deployable and Module Boundaries

## Purpose

Specify how two independently deployable systems — the Identity Control Service
(SAD-001) and the Organization & Tenancy Control application (SAD-004) — share one
repository without their domains merging, and how that separation is enforced by
machine rather than by review discipline.

A shared repository is chosen because one team owns both systems, the toolchain is
identical, and cross-system contract changes are easier to keep consistent in one
place. A shared repository is not a shared system. The compiler will not stop
`internal/tenancy` from importing `internal/identity`; nothing about the Go module
graph reflects the fact that these are separate deployables with separate databases,
separate credentials, and separate SADs. This design supplies that missing
enforcement.

The preceding custom identity implementation failed on exactly this axis. Its domain
boundaries were documented and unenforced, and they eroded until Tenant, Membership,
credential, and business permission state shared one aggregate.

## Scope

**In scope**

- Repository layout and the two deployable entrypoints.
- Import rules between the two system trees and the shared substrate.
- Database and credential separation between the two systems.
- The only permitted forms of cross-system communication.
- Automated enforcement: import analysis, grant assertion, credential isolation tests.
- Conditions that would justify splitting the repository.

**Out of scope**

- The Principal creation path — owned by
  [TDD-001](TDD-001-principal-identifier-and-creation.md).
- Projection and revocation mechanics — owned by
  [TDD-003](TDD-003-membership-projection-and-revocation.md).
- Keycloak internal architecture and its upgrade lifecycle — owned by SAD-001.
- Administration user interface composition — owned by SAD-002.

## Technical Context

Two systems, two deployables, two databases, one repository:

| System | Deployable | Database | Holds |
| :-- | :-- | :-- | :-- |
| Identity Control Service (SAD-001) | `cmd/identity-control` | Control Database | Keycloak Admin credential, desired state, application-to-client mappings, projection cursors, drift findings, canonical event outbox |
| Organization & Tenancy Control (SAD-004) | `cmd/tenancy-control` | Tenancy Database | Organization, Tenant, Workspace, Membership authority, invitation, offboarding, projection registry, outbox |

The Keycloak Admin credential is the most privileged secret in the estate. It lives in
one deployable and one address space. A defect in the Tenancy HTTP surface cannot
reach it, because the process holding it is not the process serving that surface.
This is the primary reason the two remain separate deployables rather than modules of
one binary: a module boundary does not contain a memory-disclosure or
server-side-request defect, and a process boundary does.

[ADR-TEN-001 §5.4](../../../scnehaux-architecture/05-decisions/organization-tenancy/ADR-TEN-001-separate-tenancy-authority-and-keycloak-projection.md)
fixes the direction of travel: Organization & Tenancy never writes to Keycloak.
Membership state reaches Keycloak only as
`Tenancy → canonical event → Identity Control Service → Keycloak Admin API`. That path
crosses a system boundary, so it crosses the broker.

## Component Design

### Repository Layout

```text
cmd/
├── identity-control/         Entrypoint for SAD-001 Identity Control Service
└── tenancy-control/          Entrypoint for SAD-004 Organization & Tenancy Control

internal/
├── identity/                 System: SAD-001 · Domain: PAD-PLT-001
│   ├── provisioning/         Principal minting and Keycloak creation path
│   ├── registration/         Application → protocol client/resource orchestration
│   ├── projection/           Membership → Keycloak projection application
│   ├── reconcile/            Desired-state drift detection and repair
│   └── keycloak/             Supported Admin REST API client
│
├── tenancy/                  System: SAD-004 · Domain: PAD-PLT-002
│   ├── organization/         Organization registry
│   ├── tenant/               Tenant lifecycle and security version
│   ├── workspace/            Workspace lifecycle
│   ├── membership/           Membership, validity, administrative roles
│   ├── invitation/           Invitation intent and onboarding correlation
│   ├── context/              Operating-context eligibility and verification
│   └── offboarding/          Obligation tracking and retirement
│
└── platform/                 Owned by neither system
    ├── outbox/               Outbox table access and dispatcher
    ├── idempotency/          Idempotency key claim and replay
    ├── httpapi/              Routing, middleware, error serialization
    ├── db/                   Pool construction, transaction manager
    ├── event/                Enterprise event envelope
    └── observability/        Telemetry, tracing, structured logging

contracts/
└── events/                   Versioned event schemas published by either system
```

`platform/` holds technical substrate with no business meaning. A type that encodes a
domain concept does not belong there; placement in `platform/` is not a mechanism for
sharing state between the two systems.

### Import Rules

```text
cmd/identity-control  → internal/identity, internal/platform
cmd/tenancy-control   → internal/tenancy,  internal/platform

internal/identity     → internal/platform, contracts/events
internal/tenancy      → internal/platform, contracts/events

internal/identity     ✗ internal/tenancy
internal/tenancy      ✗ internal/identity
internal/platform     ✗ internal/identity, internal/tenancy
```

There is no exception. Unlike a module boundary inside one process, there is no
legitimate case for one system's code to reference the other's: they do not share a
process, a database, or a transaction. A cross-import is always a defect.

### Cross-System Communication

Exactly one form is permitted between the two systems:

| Form | Mechanism | Used for |
| :-- | :-- | :-- |
| Versioned domain event | Producer writes an outbox row in the same transaction as its state change; the dispatcher publishes to the broker; the consumer applies idempotently | All state propagation, including Membership → Keycloak projection |

Synchronous calls between the two systems are prohibited on every path. Where a
consumer requires an authoritative answer that a projection cannot supply, it calls
the provider's **published HTTP contract** — the same contract any other consumer
uses, subject to the same authorization and the same rate limits. It receives no
privileged interface by virtue of sharing a repository.

Shared Go types across the boundary exist only in `contracts/events`, and only as
serialization structures generated from or validated against the published schema.
A domain aggregate never crosses.

## Data Model

### Database Separation

Two databases, not two schemas in one database. Each system owns its own instance or
its own logical database with no shared connectivity:

| Database | Schemas | Owned by |
| :-- | :-- | :-- |
| Control Database | `identity` | Identity Control Service |
| Tenancy Database | `organization`, `tenant`, `workspace`, `membership`, `invitation`, `operation`, `projection` | Organization & Tenancy Control |
| — | `platform` (in each database, independently) | The owning system of that database |

`platform` exists in both databases and holds that system's own outbox, inbox,
idempotency keys, and migration state. The two `platform` schemas are unrelated and
never joined; the name is a convention, not a shared store.

No table in one database carries a foreign key into the other. Cross-system references
store opaque identifiers and are validated through the provider's published contract,
never through a database constraint. This is what keeps the two systems separable and
independently restorable.

### Roles per Database

```sql
-- In each database, independently.
CREATE ROLE <system>_migrator;              -- migration job only, owns the tables
CREATE ROLE <system>_runtime NOLOGIN;       -- application runtime

-- The runtime role is not a superuser, does not hold BYPASSRLS,
-- does not own any table, and holds no DDL privilege.
GRANT USAGE ON SCHEMA <schemas> TO <system>_runtime;
```

Neither runtime role has any credential, network route, or grant reaching the other
database. Database credentials are scoped per deployable in the secret manager, so a
compromise of one deployable's configuration does not yield the other's connection
string.

Row-Level Security applies to tenant-scoped tables in the Tenancy Database as defense
in depth, with `FORCE ROW LEVEL SECURITY` and a non-owner runtime role per
STD-GLB-002. Application authorization remains mandatory.

### Outbox

Each system owns its own outbox in its own `platform` schema:

```sql
CREATE TABLE platform.outbox (
    id              BIGSERIAL   PRIMARY KEY,
    event_type      TEXT        NOT NULL,
    aggregate_id    UUID        NOT NULL,
    priority        SMALLINT    NOT NULL DEFAULT 100,
    payload         JSONB       NOT NULL,
    envelope        JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at    TIMESTAMPTZ,
    attempts        INTEGER     NOT NULL DEFAULT 0
);

CREATE INDEX outbox_unpublished
    ON platform.outbox (priority, id) WHERE published_at IS NULL;
```

Writing the outbox row inside the same transaction as the domain mutation is what
makes propagation reliable. A system that mutates state and publishes in two
transactions is a defect, and is covered by the tests in this design.

`id` is a `BIGSERIAL` and **is** exposed beyond its owning system: consumers receive it
as a snapshot high-water mark and report it back as their position, which is what
makes bootstrap and resumption work. The sequential-identifier prohibition in
STD-GLB-002 does not apply, because that clause governs externally visible **entity
identifiers**, and a stream position identifies no entity. It is a cursor into an
ordered log.

The volume disclosure the clause guards against is real but contained: the value is
released only to consumers registered with the publisher, all of which are internal
systems inside the same trust boundary. It is never returned on an unauthenticated
path and never used to address an entity.

## API / Interface

### System Ownership Manifest

One entry per deployable, validated in CI:

```yaml
deployables:
  - name: identity-control
    system: SAD-001
    authoritative_domain: PAD-PLT-001
    accountable_owner: core-platform-team
    entrypoint: cmd/identity-control
    tree: internal/identity
    database: control
    schemas: [identity, platform]
    holds_credentials: [keycloak-admin]
    owns:
      - principal identifier and creation path
      - protocol client and resource registration
      - Keycloak desired state and drift reconciliation
      - Membership projection application into Keycloak

  - name: tenancy-control
    system: SAD-004
    authoritative_domain: PAD-PLT-002
    accountable_owner: core-platform-team
    entrypoint: cmd/tenancy-control
    tree: internal/tenancy
    database: tenancy
    schemas: [organization, tenant, workspace, membership, invitation, operation, projection, platform]
    holds_credentials: []
    owns:
      - organization
      - tenant
      - workspace
      - membership
      - operating context
      - invitation and offboarding
```

Every deployable declares exactly one system, one authoritative domain, one tree, and
one database. CI rejects a manifest in which two deployables claim the same tree,
database, or authoritative domain.

### Published Contracts

Neither system exposes a Go interface to the other. Each publishes:

- a versioned HTTP contract for authoritative queries and administrative commands;
- versioned domain events under `contracts/events`.

A consumer inside this repository uses the same published contract as a consumer
outside it. This is the property that keeps the systems independently deployable and
makes repository separation, if it ever becomes necessary, a packaging change rather
than a redesign.

## Algorithms / Logic

### Import Boundary Analysis

Enforcement parses the Go import graph rather than matching text:

```text
For every package under internal/ and cmd/:
    tree := first path segment after internal/, or the cmd target

    for every import in the package:
        if the import resolves to the other system's tree:
            fail with the offending file, line, and import path

        if the package is under internal/platform
        and the import resolves to either system tree:
            fail

    for every cmd target:
        if it imports both system trees:
            fail
```

The check runs in CI and fails the build. It uses the package graph, so an import
introduced through an alias, a blank identifier, or a test file is detected on the
same basis as a direct one.

### Grant and Credential Assertion

A second check runs against the integration environment and asserts, per database:

```sql
SELECT grantee, table_schema, privilege_type
FROM information_schema.role_table_grants
WHERE grantee LIKE '%_runtime';
```

The assertion fails when a runtime role owns a table, holds `SUPERUSER` or
`BYPASSRLS`, holds any DDL privilege, or appears in the other system's database.

A third check asserts credential isolation: the `identity-control` deployable resolves
the Keycloak Admin credential and does not resolve the Tenancy database credential;
the `tenancy-control` deployable resolves neither. Grants and secret bindings drift
through migrations and deployment changes; asserting them each build is what keeps the
boundary real over time.

### Cross-System Propagation

```text
tenancy-control commits Membership change
    → outbox row written in the same transaction
    → tenancy dispatcher claims the row under a database-backed lease
    → published to the broker
    → identity-control consumes idempotently
    → applies the projection through the Keycloak Admin API
```

Dispatchers claim rows with `FOR UPDATE SKIP LOCKED` so replicas do not contend, and
process higher-priority rows first. Consumers are idempotent because delivery is
at-least-once.

### Repository Split Triggers

The repository is split into two when any one of the following becomes true:

1. The two systems acquire different accountable owners.
2. Their release cadences diverge and one blocks the other.
3. Access to one system's source must be restricted from the other's contributors.
4. Build or test duration for the shared repository blocks either system's delivery.
5. A third system needs one tree and not the other.

A split is a packaging change: the two trees, two databases, two entrypoints, and
published contracts already exist. No schema migration and no aggregate redesign is
required, which is the property these boundary rules exist to preserve.

## Configuration

Each deployable reads only its own configuration. No variable is shared.

| Variable | Deployable | Purpose |
| :-- | :-- | :-- |
| `IDENTITY_DB_DSN` | identity-control | Control Database, `identity_runtime` role |
| `IDENTITY_KEYCLOAK_BASE_URL` | identity-control | Admin API base URL |
| `IDENTITY_KEYCLOAK_CLIENT_ID` | identity-control | Service account used for administration |
| `IDENTITY_OUTBOX_DISPATCH_INTERVAL` | identity-control | Dispatcher poll interval |
| `TENANCY_DB_DSN` | tenancy-control | Tenancy Database, `tenancy_runtime` role |
| `TENANCY_OUTBOX_DISPATCH_INTERVAL` | tenancy-control | Dispatcher poll interval |
| `TENANCY_OUTBOX_BATCH_SIZE` | tenancy-control | Rows claimed per dispatch cycle |
| `BROKER_URL` | both | Event broker endpoint, with per-deployable credentials |

Migrations run as the `_migrator` role of the relevant database in a job separate from
the application process. The runtime roles hold no DDL privilege, so a defect in
application code cannot alter its own schema.

## Testing Strategy

### Architecture

- Import boundary analysis passes for every package under `internal/` and `cmd/`.
- No `cmd` target imports both system trees.
- `internal/platform` imports neither system tree.
- The system ownership manifest validates: one system, one domain, one tree, and one
  database per deployable, with no duplicates across deployables.

### Database and Credential

- Grant assertion passes for both databases.
- Neither runtime role owns a table, holds `SUPERUSER`, holds `BYPASSRLS`, or holds
  DDL privilege.
- The `identity_runtime` role has no privilege in the Tenancy Database, and
  `tenancy_runtime` has none in the Control Database.
- The `tenancy-control` deployable cannot resolve the Keycloak Admin credential.
- No foreign key crosses the two databases.

### Behavioral

- A domain mutation and its outbox row commit atomically; injecting a failure after
  the mutation and before the outbox write rolls back both.
- Each dispatcher delivers priority rows ahead of standard rows.
- Duplicate delivery of the same event produces one effect.
- Two dispatcher replicas processing concurrently produce no duplicated effect and no
  starved row.
- A Membership change in `tenancy-control` reaches `identity-control` through the
  broker and produces exactly one projection call.

### Split Rehearsal

Both deployables are built and run from separate checkouts containing only their own
tree plus `internal/platform` and `contracts/events`. The full test suite passes. A
failure identifies a coupling that would otherwise surface during a repository split.

## Security Notes

The Keycloak Admin credential is resolved by one deployable. A server-side request
forgery, memory disclosure, or remote execution defect reachable from the Tenancy HTTP
surface does not reach it, because that surface runs in a different process with a
different secret binding. This containment is the primary justification for two
deployables and is asserted by test rather than assumed.

Separate databases with separate credentials mean a SQL injection or logic flaw in
either system cannot read or write the other's data, independently of whether the
application-level boundary held.

Neither runtime role can alter its schema, so a compromised application process cannot
grant itself additional privilege without also compromising the migration job.

## Performance Notes

Cross-system propagation carries a broker hop that an in-process call would not. That
cost is accepted deliberately: it is the same hop that would exist after a repository
or organizational split, so projection latency measured today remains valid later.

Each deployable sizes its own pool. Administrative bulk operations in `tenancy-control`
cannot exhaust connections required by identity provisioning, because they are
connections to different databases.

## Operational Notes

Telemetry labels every span, metric, and log line with `deployable` and `system` so
load, latency, and error rates are attributable per system. Correlation identifiers
propagate across the broker so a Membership change and its resulting projection call
appear on one trace.

Alerts on outbox backlog and dispatcher lease age are per deployable. A backlog in one
indicates a local dispatcher or handler defect; a backlog in both indicates a broker
condition.

Each deployable has its own runbook set. Neither runbook instructs an operator to
connect to the other system's database.

## Traceability

| Relationship | Target |
| :-- | :-- |
| Parent system | SAD-001 — Scnehaux Identity Runtime (Identity Control Service container) |
| Parent system | SAD-004 — Scnehaux Organization & Tenancy Control |
| Realizes capability | PAD-PLT-001 — Identity & Access Platform |
| Realizes capability | PAD-PLT-002 — Organization & Tenancy Platform |
| Governed by | ADR-TEN-001 — Separate Tenancy Authority and Keycloak Projection |
| Governed by | ADR-IAM-004 — Adopt Keycloak Identity Kernel |
| Governed by | ADR-GLB-003 — Transactional Outbox |
| Governed by | ADR-GLB-007 — Domain-Driven Design Boundaries |
| Conforms to | STD-GLB-002 — `FORCE ROW LEVEL SECURITY`, non-owner runtime role, no `SUPERUSER`/`BYPASSRLS` |
| Enterprise constraint | EAD-003 — private domain persistence; zero unauthorized cross-domain access |
| Enterprise constraint | EAD-002 — logical domain, software system, and deployable are separate |
| Related design | TDD-001 — principal identifier and creation path |
| Related design | TDD-003 — membership projection and revocation |

### Open Questions

1. Whether the system ownership manifest lives in this repository or in the
   architecture repository beside the SADs. The validation rule is identical in both
   placements; the choice determines which pipeline enforces it.
2. Whether the two databases are separate instances or separate logical databases on
   one managed instance in the initial deployment. Credential and grant separation
   hold in both cases; the choice is a cost and blast-radius trade-off recorded in the
   SADs.
