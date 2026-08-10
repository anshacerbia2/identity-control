# Scnehaux Identity Platform — Implementation Repository

Monorepo for the two Go control-plane deployables of the Scnehaux Enterprise Cloud
identity and tenancy foundation.

**A shared repository is not a shared system.** The two deployables have separate
SADs, separate databases, separate credentials, and separate accountable domains.
Their boundaries are enforced by CI, not by convention — see
[TDD-002](docs/designs/TDD-002-control-plane-module-boundaries.md).

## Deployables

| Deployable | System | Domain | Database | Holds |
| :-- | :-- | :-- | :-- | :-- |
| `cmd/identity-control` | SAD-001 Identity Runtime | PAD-PLT-001 | Control | Keycloak Admin credential, mappings, cursors, drift, outbox |
| `cmd/tenancy-control` | SAD-004 Organization & Tenancy Control | PAD-PLT-002 | Tenancy | Organization, Tenant, Workspace, Membership authority, outbox |

Two further components of the architecture are built and operated elsewhere: the
Keycloak Identity Kernel (also SAD-001) and the Administration Experience (SAD-002).

## Governance Lineage

Strategic and system-level architecture is owned by the
[scnehaux-architecture](../scnehaux-architecture) repository. This repository owns
only Technical Design Documents and source code.

```text
EAD-001 … EAD-006        Enterprise architecture
    ↓
PAD-PLT-001              Identity & Access Platform
PAD-PLT-002              Organization & Tenancy Platform
    ↓
SAD-001                  Identity Runtime  (Keycloak Kernel + Identity Control Service)
SAD-004                  Organization & Tenancy Control
    ↓
TDD-001 … TDD-003        Technical designs      (this repository, docs/designs)
    ↓
Source code
```

Root artifacts never link downward into this repository. Every TDD names its parent
SAD in `parent_sad`, and that name resolves to exactly one existing SAD document.

## Layout

| Path | Contents |
| :-- | :-- |
| `cmd/identity-control/` | Entrypoint, SAD-001 |
| `cmd/tenancy-control/` | Entrypoint, SAD-004 |
| `internal/identity/` | Identity Control Service tree — imports `platform` only |
| `internal/tenancy/` | Organization & Tenancy tree — imports `platform` only |
| `internal/platform/` | Shared technical substrate — imports neither system tree |
| `contracts/events/` | Versioned event schemas exchanged between the two systems |
| `docs/designs/` | Technical Design Documents |

`internal/identity` and `internal/tenancy` never import each other. The compiler will
not stop it; the import boundary check in CI will.

## Current Designs

| TDD | Parent | Subject | Status |
| :-- | :-- | :-- | :-- |
| [TDD-001](docs/designs/TDD-001-principal-identifier-and-creation.md) | SAD-001 | Canonical Principal identifier and creation path | draft |
| [TDD-002](docs/designs/TDD-002-control-plane-module-boundaries.md) | SAD-001, SAD-004 | Deployable and module boundaries | draft |
| [TDD-003](docs/designs/TDD-003-membership-projection-and-revocation.md) | SAD-004 | Membership projection and revocation propagation | draft |

Numbering is a flat sequence. A TDD number is an identifier, not a reading order and
not a priority.

## Proof-of-Concept Questions

Designs marked `draft` implement decisions accepted at architecture level but not yet
proven against a pinned Keycloak release. **Refer to these questions by name, never by
number** — the numbering below is an execution order, not the numbering used inside
each TDD.

Run in this order. The first question is the only one whose failure forces an
extension or a standard amendment, so it runs first.

| Order | Question | TDD | Failure consequence |
| :-- | :-- | :-- | :-- |
| 1 | **Protocol mapper coverage** — which token surfaces can carry `principal_id`: access token, ID token, UserInfo, introspection | TDD-001 | Access token uncovered is the escalation case. Partial coverage of the other three is pre-decided and needs no amendment |
| 2 | **Attribute search semantics** — is `q=scnehaux_principal_id:{id}` exact-match, and how does it paginate | TDD-001 | Recovery mechanism changes; creation path unaffected |
| 3 | **Attribute immutability** — can declarative user profile prevent edits to `scnehaux_principal_id` | TDD-001 | Falls back to reconciliation detection |
| 4 | **Issuer URI form** — can `/realms/{name}` be removed from `iss`, or is the path shape retained deliberately | TDD-001 | Irreversible once tokens are issued; decide either way before the first token |
| 5 | **Projected context representation** — Keycloak Organizations, Groups, or user attributes | TDD-003 | Projector implementation changes; authority model unaffected |
| 6 | **Session removal granularity** — per Principal and Tenant context, or per Principal only | TDD-003 | Determines whether revoking one Membership disturbs unrelated contexts |
| 7 | **Context switch mechanism** — new authorization request on the existing SSO session, Standard Token Exchange, or refresh with context, judged against the nine criteria in TDD-003 | TDD-003 | Determines whether a custom extension is required, which changes upgrade burden |

Two further questions are decisions rather than experiments and do not need Keycloak:
manifest placement and whether the two databases are separate instances or separate
logical databases ([TDD-002](docs/designs/TDD-002-control-plane-module-boundaries.md)).

## Parallel Tracks

The proof-of-concept and the build run at the same time. No outcome above invalidates
the authority schemas, the outbox engine, the state machines, or the boundary
enforcement — every blocked item is an adapter, and adapters are the cheapest part to
change.

```text
Track A   Keycloak proof-of-concept, questions 1–7 in order
Track B   Tenancy schema, Membership state machine, revocation transaction,
          outbox and dispatcher, import boundary check, grant assertion
                         ↓
          converge when the Keycloak projector is written
```
