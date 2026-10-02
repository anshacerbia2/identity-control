---
doc_meta:
  id: TDD-identity-control-006
  title: Provider Authority from Organization's Records
  owner: Core Platform Team
  version: 1.0.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-10-02
  last_reviewed: 2026-10-02
  parent_sad: SAD-001
---

# Provider Authority from Organization's Records

## Purpose

State how this service decides that a caller is a provider. Under `ADR-ORG-002 §5.3` it reads its
own projection of the `provider:identity-control` grants and activations that Organization Control
records, by the token's `principal_id`, for each request. It no longer reads a `provider_scope`
claim, and no such claim is issued (`STD-IAM-002 §3.1.1`).

## Scope

In scope:

- registering as an Organization projection consumer of the four provider grant event types;
- the delivery intake, and the local projection it writes;
- bootstrap from Organization's provider authority snapshot, and progress reports;
- freshness, and what each kind of authority does when the projection is stale;
- the per-request provider decision that replaces the claim;
- the ceremony's local emergency grant, and its retirement.

Out of scope:

- granting, activating and approving, which happen in Organization Control
  (`TDD-organization-control-001` §Provider Activation);
- how a registration owner is recognized, which stays `TDD-identity-control-003` §Registration
  Ownership.

## Technical Context

Organization Control publishes each transition of a `provider:identity-control` grant as one event
carrying the grant's whole state and a `grant_version` (`TDD-organization-control-001` §Provider
Authority Projection):

```text
com.scnehaux.organization.provider.lifecycle.granted    standard lane
com.scnehaux.organization.provider.lifecycle.activated  standard lane
com.scnehaux.organization.provider.security.ended       priority lane
com.scnehaux.organization.provider.security.revoked     priority lane
```

It runs this consumer's dispatcher in its own process and posts each delivery to this service's
acceptance API, authenticated as Organization Control's workload with a kernel access token
(`ADR-GLB-018 §5.4`). This service holds no credential to Organization's database. It calls
Organization Control as its own workload for the snapshot, the frontier and progress reports, with
foundation-platform's `clientauth` (`TDD-foundation-platform-002` §Workload Client Credentials).

**Why each mechanism, and where it comes from.**

- **Decided at the resource, from its own record.** The token says who the caller is, and this
  service evaluates the grant it holds, as Google Cloud IAM and Kubernetes evaluate the policy the
  resource holds (`ADR-IAM-001` R34, R35). A claim would outlive an activation ended early until the
  token expired (`STD-IAM-002 §3.1.1`).
- **Duplicates are expected, and recognized by event id.** A relay "might publish a message more
  than once … a message consumer must be idempotent" [R1]. Stripe's guidance for the same shape is to
  guard "against duplicated event receipts by logging the event IDs you've processed, and then not
  processing already-logged events" [R2]. That is `inbox.Guard`.
- **Order is not guaranteed, so a version decides.** Stripe "doesn't guarantee the delivery of
  events in the order that they're generated", and tells a consumer not to depend on it [R2]. Every
  event carries the grant's whole state and its `grant_version`, and a lower version is discarded.
- **Bootstrap is list, then watch.** A Kubernetes client lists, then "make[s] a follow-up watch
  request" from the returned `resourceVersion` [R3]. Here the snapshot is the list, its mark is the
  version, and deliveries owed since the registration are the watch.
- **An activation ends on its own clock.** Entra PIM: "once activated, the user can use the role for
  a preconfigured period of time before they need to activate again" (`ADR-ORG-002` R1). The end is
  in the record, so this service evaluates it without waiting for an event.

## Component Design

| Component | Responsibility |
| :-- | :-- |
| `POST /v1/deliveries` | The acceptance API. Admits Organization Control's workload alone, applies each provider event in one transaction with its inbox guard, and answers with the application receipt marker. |
| `providerauthority.Projection` | The local tables, version-guarded application, and the snapshot replacement. |
| `providerauthority.Freshness` | Polls Organization Control's frontier for this consumer and holds the last observation, so no request waits on the network. |
| `providerauthority.Decide` | The per-request decision: provider, or not, and why. |
| `cmd/identity-provider-bootstrap` | Takes the provider authority snapshot, replaces the projection, and records the bootstrap mark with Organization Control. |

### Registration with Organization Control

An operator registers this service once, as a provider of `provider:organization-control`:

```json
POST /v1/projections/consumers
{
  "consumer_id": "identity-control",
  "principal_id": "<this service's workload principal_id>",
  "projection_version": "v1",
  "max_accepted_age_seconds": 60,
  "stale_behavior": "fail_closed",
  "event_types": [
    "com.scnehaux.organization.provider.lifecycle.granted",
    "com.scnehaux.organization.provider.lifecycle.activated",
    "com.scnehaux.organization.provider.security.ended",
    "com.scnehaux.organization.provider.security.revoked"
  ]
}
```

and names `identity-control=https://<this service>/v1/deliveries` in Organization Control's
`ORGANIZATION_DELIVERY_TARGETS`. The declaration is `ADR-ORG-002 §5.3`'s: a 60-second budget, and
`fail_closed`, which refuses activations past the budget. Emergency grants are the declared
exception, honored while stale, so an Organization outage leaves the break-glass path working.

## Data Model

```sql
CREATE TABLE identity.provider_grant (
    grant_id           UUID        PRIMARY KEY,
    principal_id       UUID        NOT NULL,
    kind               TEXT        NOT NULL CHECK (kind IN ('eligible', 'emergency')),
    grant_status       TEXT        NOT NULL CHECK (grant_status IN ('active', 'revoked')),
    grant_version      BIGINT      NOT NULL CHECK (grant_version > 0),
    activation_id      UUID,
    activation_ends_at TIMESTAMPTZ,
    applied_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT provider_grant_activation_complete
        CHECK ((activation_id IS NULL) = (activation_ends_at IS NULL)),
    CONSTRAINT provider_grant_revoked_inactive
        CHECK (grant_status = 'active' OR activation_id IS NULL)
);
CREATE INDEX provider_grant_principal ON identity.provider_grant (principal_id)
    WHERE grant_status = 'active';

CREATE TABLE identity.provider_projection (
    id               INTEGER     PRIMARY KEY CHECK (id = 1),
    snapshot_mark    BIGINT      NOT NULL,
    bootstrapped_at  TIMESTAMPTZ NOT NULL,
    applied_mark     BIGINT      NOT NULL
);
```

- **One row per grant, replaced by version.** An event or a snapshot row is applied only when its
  `grant_version` is higher than the one held, so delivery order never decides which state is
  newer. A revoked grant stays, so a late older event cannot revive it.
- **`scope` is not stored.** Organization publishes only `provider:identity-control`, so an event
  naming another scope is malformed and refused.
- **Deduplication** is `platform.processed_event` under consumer `identity-control`, in the
  transaction that applies the event (`inbox.Guard`).
- **`provider_projection`** records the snapshot this projection was built from and the highest
  stream position applied, for progress reports. No row means no bootstrap, and no activation is
  honored (§Algorithms).

## API / Interface

```text
POST /v1/deliveries        Organization Control's workload only
```

| Outcome | Status | `X-Application-Receipt` |
| :-- | :-- | :-- |
| Applied | `202` | `applied` |
| Already applied (`inbox.Guard` saw the event) | `202` | `applied` |
| Superseded (a higher version is held) | `202` | none |
| Unknown type, malformed payload, another scope | `422` | none |
| Not Organization Control's workload | `401` / `403` | none |

The marker follows `ADR-GLB-016 §5.4`: it is emitted only where the assertion "this consumer holds
this event's effect" is true. A superseded event was discarded, so it carries none, and its dead
letter, if any, closes as `SUPERSEDED` (`TDD-organization-control-005`).

**The intake's caller.** A token is Organization Control's when it verifies against this service's
issuer and audience, names `subject_type` `workload`, and its `principal_id` equals
`IDENTITY_DELIVERY_PRINCIPAL_ID`. Every other route refuses a workload token as before, and this
route refuses every other caller.

## Algorithms / Logic

### Applying an Event

```text
in one transaction:
    inbox.Guard(identity-control, event_id, type): seen -> 202 applied
    decode the payload: malformed, unknown type, scope other than provider:identity-control -> 422
    read the held grant_version for grant_id, FOR UPDATE
    held >= event's version -> 202, no marker (superseded)
    upsert the grant's whole state; set applied_mark = greatest(applied_mark, streamposition)
202 applied
```

### Bootstrap

`cmd/identity-provider-bootstrap`:

1. Reads `POST /v1/projections/provider-authority/snapshot` page by page, under one mark.
2. In one transaction, applies each row by version and records `snapshot_mark`. A grant held
   locally and absent from the snapshot is marked revoked, because the snapshot carries every
   unrevoked grant.
3. Records the mark with `POST /v1/projections/consumers/identity-control/bootstrap`.

The consumer is registered first, so deliveries are owed from the registration's commit and every
event either committed before it and is in the snapshot, or is delivered
(`TDD-organization-control-002` §Bootstrap Contract). An event delivered before the snapshot is
applied is reconciled by version either way.

### Freshness

The process polls `GET /v1/projections/frontier` as its own workload every 15 seconds and keeps the
last observation. It reports `applied_mark` as progress on the same cadence. The projection is
**fresh** at instant `now` when all of these hold:

```text
a bootstrap is recorded
the last observation succeeded at observed_at
(now - observed_at) + oldest_owed_age(at observation) <= 60 s    (0 when nothing was owed)
the observation reported no security debt for this consumer
```

This is the composition foundation-reference makes, at its budget. It holds because the transport
applies within the delivery: published here means applied (`ADR-GLB-016 §5.4`).

### The Provider Decision

```text
provider(principal_id, now):
    an unretired ceremony grant names principal_id                      -> provider, emergency
    an active emergency grant names principal_id                        -> provider, emergency
    an active grant names principal_id with activation_ends_at > now:
        the projection is fresh                                          -> provider
        otherwise                                                        -> not a provider (stale)
    otherwise                                                           -> not a provider
```

- **No network on the request path.** The decision reads the local tables and the held observation.
- **An activation's natural end takes effect at once**, evaluated from its recorded end
  (`ADR-ORG-002 §5.3`). An early end or a revocation takes effect when its priority event is applied,
  within the budget, or the projection reads stale and activations stop.
- **Emergency authority** is reported at WARN on every request it authorizes, with the
  `principal_id` and the route (`ADR-ORG-002 §5.2`).
- **A token carrying `provider_scope` is refused.** No resource checks a grant from a claim and none
  is issued (`STD-IAM-002 §3.1.1`), so one that carries it was minted by a client still configured
  for the old profile.
- A caller that is not a provider is an owner, as before (`TDD-identity-control-003` §Registration
  Ownership).

### The Ceremony's Grant

The bootstrap ceremony creates the first Principal before any Organization grant can exist
(`ADR-IAM-001 §5.11`). It records that Principal as a local emergency grant
(`ADR-ORG-002 §5.4`):

- `identity.bootstrap_ceremony` gains `principal_id`, written in the ceremony's insert-only row.
- The ceremony grant is honored until the projection holds an active emergency grant for anyone.
  At that moment it is retired by an insert into `identity.ceremony_grant_retirement (id = 1,
  retired_at, by_grant_id)`, which is insert-only like the ceremony row. From then on provider
  authority comes from Organization's record alone.
- The ceremony no longer writes the kernel attribute `scnehaux_provider_scope`.

## Configuration

| Setting | Effect |
| :-- | :-- |
| `IDENTITY_DELIVERY_PRINCIPAL_ID` | Organization Control's workload `principal_id`. The intake admits it alone. Unset, the intake answers 503 and no provider event is accepted. |
| `IDENTITY_ORGANIZATION_BASE_URL` | Organization Control's API, for the snapshot, the frontier and progress. |
| `IDENTITY_WORKLOAD_CLIENT_ID`, `IDENTITY_WORKLOAD_KEY_FILE`, `IDENTITY_WORKLOAD_TOKEN_URL`, `IDENTITY_WORKLOAD_AUDIENCE` | This service's workload client for those calls, its key, the kernel token endpoint, and the kernel issuer the assertion names. |
| `IDENTITY_PROVIDER_FRESHNESS` | The budget, default `60s`, as declared at registration. |

## Testing Strategy

- An event is applied once: a duplicate answers applied without a second write, and a lower or
  equal version answers 202 with no marker and leaves the held state.
- An unknown type, a malformed payload or another scope answers 422. A caller other than
  Organization Control's workload is refused, and the intake refuses no route but its own.
- A snapshot replaces the projection by version and marks a grant it omits revoked.
- Freshness: fresh within the budget, stale past it, stale while security debt is reported, stale
  before a bootstrap, and stale when the frontier cannot be read.
- The decision: an emergency grant authorizes while stale, an activation does not, an ended or
  expired activation does not, a revoked grant does not, and the ceremony grant authorizes until an
  emergency grant is projected and never after.
- A token carrying `provider_scope` is refused.

## Security Notes

- The intake is a write path into authority. It admits one workload, and every event it applies
  carries a version Organization assigned, so a replayed or reordered delivery cannot move a grant
  backwards.
- A stale projection fails closed for activations. Emergency grants are honored by declaration, are
  standing in Organization's record, and each use is reported.
- The ceremony grant is a bounded exception with a single recorded end.

## Performance Notes

The decision is two indexed reads in this service's database and one in-memory comparison. The
frontier poll is one request per 15 seconds per replica.

## Operational Notes

1. Register this service's workload client in the kernel, and Organization Control's.
2. Register `identity-control` as an Organization consumer (§Registration).
3. Add the delivery target to Organization Control and restart it.
4. Run `identity-provider-bootstrap`.
5. Grant at least two emergency `provider:identity-control` grants in Organization. The first
   retires the ceremony grant.

Until step 4, no activation is honored, and only the ceremony grant and emergency grants authorize.

## References

| Ref | Source |
| :-- | :-- |
| R1 | Chris Richardson, *Pattern: Transactional outbox*, <https://microservices.io/patterns/data/transactional-outbox.html>, accessed 2026-10-02: "The Message relay might publish a message more than once … a message consumer must be idempotent." |
| R2 | Stripe, *Receive Stripe events in your webhook endpoint*, <https://docs.stripe.com/webhooks>, accessed 2026-10-02: "You can guard against duplicated event receipts by logging the event IDs you've processed, and then not processing already-logged events"; "Stripe doesn't guarantee the delivery of events in the order that they're generated." |
| R3 | Kubernetes, *Kubernetes API Concepts*, §Efficient detection of changes, <https://kubernetes.io/docs/reference/using-api/api-concepts/>, accessed 2026-10-02: "Clients can send a list or a get and then make a follow-up watch request." |

**The tradeoffs.**

- **Polling the frontier.** Freshness costs one request per 15 seconds per replica, and a stale
  observation can be up to 15 seconds old inside the budget. The alternative is a call to
  Organization Control on each provider request, which `ADR-ORG-002` Alternative D rejected: it
  would make every privileged action here depend on Organization's availability.
- **Emergency grants while stale.** They keep the break-glass path working through an Organization
  outage, at the cost of honoring a revocation late if the revocation is what cannot be delivered.
  Emergency grants are few, standing and reported, which is the bound on that cost
  (`ADR-ORG-002 §5.2`).
- **Refusing `provider_scope`.** A client still configured for the old profile stops working at
  once rather than being read silently as an owner. The kernel's `scnehaux-provider` client scope is
  removed in the same rollout.

## Traceability

| Relationship | Target |
| :-- | :-- |
| Decision | `ADR-ORG-002 §5.3`, §5.4 |
| Delivery | `ADR-GLB-018 §5.4`, `ADR-GLB-016 §5.4` |
| Token rule | `STD-IAM-002 §3.1.1`, `ADR-IAM-001 §5.6` |
| Producer | `TDD-organization-control-001` §Provider Authority Projection, `TDD-organization-control-002` §Bootstrap Contract |
| Caller token | `TDD-identity-control-001` §Caller Token |
