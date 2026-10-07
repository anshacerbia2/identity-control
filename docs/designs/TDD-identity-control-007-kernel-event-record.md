---
doc_meta:
  id: TDD-identity-control-007
  title: The Kernel Event Record and Its Completeness
  owner: Core Platform Team
  version: 1.1.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-10-05
  last_reviewed: 2026-10-07
  parent_sad: SAD-001
---

# The Kernel Event Record and Its Completeness

## Purpose

Specify how this service keeps a durable record of every user and admin event the identity kernel
records. The record is read from the kernel's native event store, through the supported Admin API,
and kept until Audit & Evidence has received it.

`TDD-identity-kernel-003` gives this service the completeness reconciliation: "Executed by
`identity-control`, specified here because this repository owns the source." `STD-IAM-001 §3.8`
(2.3.0) states the obligation: "Identity Runtime MUST keep a durable record of every kernel user and
admin event, read from the kernel's native event store, until Audit & Evidence has received it."
`ADR-IAM-001 §5.7` (2026-10-05) orders the build: the native store first, and the listener
extension when a consumer needs events sooner than one sweep interval.

## Scope

**In scope**

- The sweep that reads the kernel's user events and admin events in overlapping windows.
- The record: one row per kernel event, deduplicated on the kernel's event identifier, with the
  Principal resolved where the kernel user maps to one.
- Redaction of credential values from what the kernel's representation carried.
- The record's high-water mark per kind, and what a sweep reports.

**Out of scope**

- The listener extension and its ingest endpoint (`TDD-identity-kernel-003` §Delivery). Built when a
  consumer needs lower latency; the record and its sweep stay correct without it.
- Translation into canonical `identity.*` events and their publication (SAD-001 §6.3). They follow
  when Audit & Evidence consumes them; until then the record holds every event, so nothing is lost
  by waiting.
- Release of the record once Audit & Evidence has received an event. It needs that receipt, which
  does not exist yet.

## Technical Context

The kernel keeps each kind of event for 7 days (`TDD-identity-kernel-003` 1.1.0), and keeps them only
as the reconciliation source. A record that lived only there would be gone a week after each login.

The Admin API reads events newest first, filtered by date rather than by instant, and pages by
`first` and `max`. This service already reads client admin events that way for drift attribution
(`TDD-identity-control-003` §Drift Reconciliation): it asks from the day before the instant it wants,
and filters to the instant itself.

A newest-first page read while events are still being recorded can repeat an event across two pages:
a new event at the head pushes the rest down by one. It never skips one: an event leaves the store
only by expiring from the tail. A repeat is harmless, because the record is keyed on the event's own
identifier.

## Component Design

| Component | Package | Responsibility |
| :-- | :-- | :-- |
| `EventStore` | `internal/keycloak` | Reads user events and admin events since an instant, every page, bounded |
| `Recorder` | `internal/kernelevents` | Records a batch once, resolves Principals, redacts, advances the mark |
| `Sweeper` | `internal/kernelevents` | One sweep per kind, scheduled, and on request |

The sweep reads with the registration credential, which already holds `view-events` to read client
admin events (`deploy/dev/create-registration-client.sh`). `view-events` covers both kinds, so the
credential gains no privilege.

## Data Model

```sql
CREATE TABLE identity.kernel_event (
    realm         TEXT        NOT NULL,
    kind          TEXT        NOT NULL CHECK (kind IN ('user', 'admin')),
    kc_event_id   TEXT        NOT NULL,
    occurred_at   TIMESTAMPTZ NOT NULL,
    event_type    TEXT        NOT NULL,   -- LOGIN, LOGIN_ERROR, ...; or CREATE, UPDATE, ... for admin
    kc_user_id    TEXT,                   -- the subject of a user event, the actor of an admin event
    principal_id  UUID,                   -- resolved from kc_user_id when a mapping holds it
    client_id     TEXT,
    session_id    TEXT,
    ip_address    TEXT,
    error         TEXT,
    resource_type TEXT,                   -- admin events
    resource_path TEXT,                   -- admin events
    details       JSONB       NOT NULL DEFAULT '{}',
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (realm, kind, kc_event_id)
);

CREATE TABLE identity.kernel_event_mark (
    realm         TEXT        NOT NULL,
    kind          TEXT        NOT NULL CHECK (kind IN ('user', 'admin')),
    read_through  TIMESTAMPTZ NOT NULL,   -- the newest event time a complete sweep read
    swept_at      TIMESTAMPTZ NOT NULL,
    last_read     INTEGER     NOT NULL,
    last_recorded INTEGER     NOT NULL,
    PRIMARY KEY (realm, kind)
);
```

**One row per kernel event, written once.** The kernel's event identifier is the key, so an event
read by two overlapping sweeps, two replicas, or later by the listener is recorded once. The runtime
role holds `SELECT` and `INSERT` on `kernel_event` and no `UPDATE` or `DELETE`: the record is not
edited.

**What a row holds.** The actor, subject, action, outcome, time, source and correlation that
`STD-IAM-001 §3.8` asks evidence to preserve: the kernel user and its Principal, the event type and
error, the time, the client and IP address, and the session. `kc_user_id` stays here and is not
published: when canonical events are translated, they carry `principal_id` (`TDD-identity-control-001`).
A kernel user no mapping holds, such as a service account or the bootstrap administrator, is
recorded with no Principal.

**A workload's last authentication is kept on the workload (1.1.0).** A successful
`CLIENT_LOGIN` user event is a client credentials grant, and its user is the client's
service-account user. When that user is a workload's mapped user, the sweep moves the workload's
`last_seen_at` forward to the event's time, in the transaction that records the event, the first
time the event is recorded. It is what unused-workload detection reads
(`TDD-identity-control-004` 1.5.0 §Unused Workload Detection), and it adds a write per workload per
sweep rather than a new stream, as that design's §Performance Notes expect.

**Credential values are removed before a row is written.** An admin event's representation is the
resource as it was written. One that carried a credential, for example a user created with a
password, would carry it here. Every value under a key named `credentials`, `password`, `secret`,
`clientSecret`, `privateKey`, `token`, `access_token`, `refresh_token` or `id_token`, at any depth, is
replaced with `"[redacted]"` (`STD-IAM-001 §3.8` [R18]). A representation that is not JSON is
recorded as `{"unparsed": true}` and not stored.

## API / Interface

```text
POST /v1/kernel-events:sweep        provider: one sweep now
```

It answers what the sweep did, per kind: how many events were read, how many were recorded for the
first time, the mark it reached, and whether the read was truncated. The scheduled sweep runs the same
code, and `deploy-dev` calls this route twice against the live kernel
(`scripts/dev-kernel-events-proof.ps1`): the first records the events the earlier steps left, and the
second reads them again in the overlap and records nothing new.

## Algorithms / Logic

### The Sweep

```text
sweep(kind):
    mark  := the kind's read_through, or now − kernel retention when there is none
    since := mark − interval                          -- the overlap
    read every event of the kind with time ≥ since, newest first, every page, bounded
    if the bound was reached: record what was read, keep the mark, report truncated
    in one transaction:
        insert each event, doing nothing on conflict with (realm, kind, kc_event_id)
        resolve principal_id from the mapping by (kc_user_id, realm)
        set read_through := greatest(read_through, newest time read), swept_at := now()
    report read, recorded, mark
```

**The windows overlap by one interval**, so an event recorded at a boundary is read by both sweeps,
as `TDD-identity-kernel-003` §Completeness Reconciliation requires. The first sweep reads the
kernel's whole retention, so a deployment that starts late still records what the kernel holds.

**A truncated read keeps the mark.** The bound is 50 000 events of one kind per sweep. A sweep that
reaches it has read the newest events and not necessarily all of those since the mark. Advancing the
mark would leave a gap that no later sweep reads. The events it read are recorded, the next sweep
reads the same window again, and the report says truncated, which is an operational signal.

**Every newly recorded event counts as recovered** while there is no listener: the sweep is the only
path. Once the listener delivers, recovered is what it dropped, and an event the listener delivered
that the kernel did not record is the `extra` finding of `TDD-identity-kernel-003`.

### The Interval and the Retention

```text
interval × 24  ≤  the kernel's event retention (7 days)
```

`TDD-identity-kernel-003` §Retention Constraint binds the two, so that an event is read at least
twice before it expires. Startup refuses an interval longer than 7 hours.

## Configuration

| Variable | Default | Purpose |
| :-- | :-- | :-- |
| `IDENTITY_KERNEL_EVENT_INTERVAL` | `1h` | Sweep cadence and window overlap; at most `7h` |

## Testing Strategy

- An event read by two overlapping sweeps is recorded once, and so is one read twice in one sweep.
- The first sweep reads from the kernel's retention, and a later one from the mark less the interval.
- A truncated read records what it read, keeps the mark, and reports truncated.
- A user event's Principal is resolved from the mapping, and an unmapped kernel user records none.
- A credential value in an admin representation, at any depth, is redacted, and a representation
  that is not JSON is not stored.
- The runtime role cannot update or delete a recorded event (integration).
- Startup refuses an interval over 7 hours.
- Against the live kernel in `deploy-dev`: the sweep records the smoke suite's logins and admin
  changes, and a second sweep records nothing new.

## Security Notes

The record holds personal data: who signed in, from which address, and when. It is in this
service's own database under its runtime role, and nothing reads it but the sweep and, later,
translation. It holds no credential value, by redaction rather than by trusting what the kernel
records.

The sweep reads with a credential that already reads admin events. A second Admin API client for
events alone was considered and not built: it would hold the same `view-events` role and add a key to
rotate.

## Performance Notes

A sweep is a few Admin API pages per kind per interval and one insert per event. The kernel's event
table is read through its indexed date filter.

## Operational Notes

| Signal | Meaning |
| :-- | :-- |
| A sweep reports truncated | More than 50 000 events of one kind in one window; the mark holds until a sweep reads it all |
| `swept_at` older than two intervals | The sweep is not running; events approach their 7-day expiry unread |
| A sweep fails | The kernel or the database is unreachable; the next sweep reads the same window |

## Traceability

| Relationship | Target |
| :-- | :-- |
| Parent system | SAD-001 — Scnehaux Identity Runtime §4.2: completeness through scheduled reconciliation |
| Conforms to | STD-IAM-001 §3.8 (2.3.0) — a durable record of every kernel event until Audit & Evidence has it |
| Governed by | ADR-IAM-001 §5.7 — the native store first; the listener where required |
| Realizes | `TDD-identity-kernel-003` §Completeness Reconciliation, §Retention Constraint |
| Related design | `TDD-identity-control-003` §Drift Reconciliation — the same admin-event read |
| Related design | `TDD-identity-control-001` — `kc_user_id` maps to `principal_id` and is not published |
