# Identity Control Service

Go control-plane service for the Scnehaux Identity & Access Platform. It is one of the
two containers that realize **SAD-001 Scnehaux Identity Runtime**; the other is
Keycloak itself, built and operated from `identity-kernel`.

## What this service owns

- Minting the canonical `principal_id` and performing the only authorized Principal
  creation call against the Keycloak Admin API.
- Registering protocol clients and protected resources from Software Catalog
  references.
- Applying Membership context projection into Keycloak, and removing Keycloak sessions
  when a Membership is revoked.
- Detecting drift between Scnehaux desired state and Keycloak runtime state, and
  reconciling it.
- Translating Keycloak events into canonical Scnehaux events.

## What it does not own

It authenticates nobody, issues no token, stores no credential, and runs no session
engine. Those belong to the Keycloak kernel. It is also not authoritative for
Organization, Tenant, Workspace, or Membership — that authority lives in
`organization-control`, and this service consumes it as a projection.

This service holds the **Keycloak Admin credential**, which is the most privileged
secret in the estate. That is the reason it runs as its own process rather than as a
module beside the Organization control plane: a module boundary does not contain a
server-side-request or memory-disclosure defect, and a process boundary does.

## Repository map

The identity and organization foundation spans six repositories.

| Repository | Role | System |
| :-- | :-- | :-- |
| `identity-kernel` | Keycloak extensions, realm configuration, login theme, image build | SAD-001 |
| **`identity-control`** | **This service** | **SAD-001** |
| `organization-control` | Organization, Tenant, Workspace, Membership authority | SAD-004 |
| `foundation-platform` | Shared Go substrate: outbox, envelope, idempotency, problem details | library |
| `identity-experience` | Account security and identity administration UI with its BFF | SAD-002 |
| `organization-experience` | Organization administration UI with its BFF | SAD-012 |

Cross-system state moves only through versioned domain events on the broker. There is
no synchronous call between this service and `organization-control`; where an
authoritative answer is required, this service calls the published HTTP contract that
every other consumer uses.

## Governance lineage

Strategic and system architecture is owned by the
[scnehaux-architecture](https://github.com/anshacerbia2/scnehaux-architecture)
repository. This repository owns Technical Design Documents and source code only.

```text
EAD-001 … EAD-006     Enterprise architecture
    ↓
PAD-PLT-001           Identity & Access Platform
    ↓
SAD-001               Scnehaux Identity Runtime
    ↓
TDD-identity-control-*    Technical designs   (docs/designs)
    ↓
Source code
```

Every TDD names its parent SAD in `parent_sad`, and that name resolves to exactly one
existing SAD document. Root artifacts never link downward into this repository.

## Layout

| Path | Contents |
| :-- | :-- |
| `cmd/identity-control/` | Deployable entrypoint and composition root |
| `internal/provisioning/` | Principal minting and the Keycloak creation path |
| `internal/registration/` | Application to protocol client and resource orchestration |
| `internal/projection/` | Membership projection and Keycloak session removal |
| `internal/reconcile/` | Desired-state drift detection and repair |
| `internal/keycloak/` | Typed client over the supported Admin REST API |
| `docs/designs/` | Technical Design Documents |

The shared substrate — outbox, dispatcher, event envelope, idempotency, HTTP problem
details, telemetry — is imported from `foundation-platform` rather than reimplemented
here. Two divergent copies of the dispatcher would produce two different revocation
enforcement intervals while both systems reported compliance.

## Designs

| TDD | Subject | Status |
| :-- | :-- | :-- |
| `TDD-identity-control-001` | Canonical Principal identifier and creation path | approved; Keycloak PoC pending |
| `TDD-identity-control-002` | Keycloak context projection, durable retry, session removal | approved; Keycloak PoC pending |
| `TDD-identity-control-003` | Protocol client and protected-resource registration | approved |
| `TDD-identity-control-004` | Workload and bounded agent identity | approved |
| `TDD-identity-control-005` | Account-security and investigation API mediation | approved |

Numbering is a flat sequence within this repository. A number is an identifier, not a
reading order and not a priority.

## Status

Approved designs may still carry an explicit implementation gate against the pinned
Keycloak release. Every such proof-of-concept is listed in the TDD that depends on it;
an unverified adapter is not treated as implementation-ready code.
