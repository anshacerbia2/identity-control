---
doc_meta:
  id: TDD-identity-control-008
  title: Account Security Notifications
  owner: Core Platform Team
  version: 1.2.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-10-06
  last_reviewed: 2026-10-06
  parent_sad: SAD-001
---

# Account Security Notifications

## Purpose

Specify how this service tells a person that their account changed, as `ADR-IAM-007` decides. This
service decides which events are notified and to whom. It records each notification as evidence and
hands it to the Notification Platform (`PAD-PLT-005`) to deliver. The kernel sends no mail
(`ADR-IAM-007 §5.4`).

## Scope

**In scope (1.2.0)**

- **Notification addresses.** The address a Principal was created with is its first. The record
  holds more.
- **Detection from the kernel event record.** A notified kernel event becomes a notification request
  in the transaction that records it.
- **The request.** Its event, its recipients at that instant, and its bounded details, recorded once
  per event.
- **The dispatcher.** It hands requests to a delivery adapter, retries, and reports one it could not
  hand over.
- **A development stand-in for the Notification Platform,** which production refuses.
- **The provider's reads.** A Principal's addresses and its notifications.
- **A person's own addresses (1.2.0).** Adding one at `aal2` and proving it with a one-time code,
  and removing one, each notified to the addresses held before (`ADR-IAM-007 §5.2`).

**Not yet**

- **The Identity Experience page** that serves these routes. It follows in `identity-experience`.
- **The Notification Platform client.** It waits on that platform. Until then no notification leaves
  a development server.
- **Notifications from assisted recovery.** That command is built with its own slice.

## Technical Context

The kernel event record (`TDD-identity-control-007`) holds every kernel user and admin event, swept
every interval. identity-kernel's `compat/notified_events_test.go` records how 26.7.5 marks each event
`ADR-IAM-007 §5.1` notifies, and holds those marks on every compatibility run:

| Event | Kernel mark | Notified as |
| :-- | :-- | :-- |
| A TOTP bound | user `UPDATE_CREDENTIAL`, `credential_type=otp` | `authenticator_bound`, `otp` |
| A passkey or security key bound | user `UPDATE_CREDENTIAL`, `credential_type=webauthn` or `webauthn-passwordless` | `authenticator_bound`, `webauthn` |
| Recovery codes issued or replaced | user `UPDATE_CREDENTIAL`, `credential_type=recovery-authn-codes` | `recovery_codes_issued` |
| A recovery code used | user `LOGIN`, `credential_type=recovery-authn-codes`, **no** `custom_required_action` | `account_recovered`, `recovery_code` |
| A password changed | user `UPDATE_CREDENTIAL`, `credential_type=password` | `authenticator_bound`, `password` (1.1.0) |
| A TOTP, passkey or security key removed by the person | user `REMOVE_CREDENTIAL`, naming the credential type | `authenticator_removed`, by the person (1.1.0) |
| An authenticator removed through the Admin API | admin `ACTION`, resource `USER`, path `users/{user}/credentials/{credential}` | `authenticator_removed`, by an administrator |

Three facts about those marks shape the mapping:

- **The enrolment's sign-in is not a recovery.** The `LOGIN` that ends enrolment also names
  `recovery-authn-codes`, and it carries `custom_required_action=CONFIGURE_RECOVERY_AUTHN_CODES`.
  A recovery is told apart by the absence of that detail.
- **Only `UPDATE_CREDENTIAL` maps.** The kernel also writes the legacy `UPDATE_TOTP` and
  `UPDATE_PASSWORD` beside `UPDATE_CREDENTIAL`, and mapping both would notify one binding twice.
- **A removal by the person is preceded by its own sign-in.** The `LOGIN` before
  `kc_action=delete_credential` names the credential and `custom_required_action=delete_credential`.
  It is not a recovery, and only the `REMOVE_CREDENTIAL` maps.
- **A removal through the Admin API names its subject in the path.** In an admin event,
  `kc_user_id` is the actor (`TDD-identity-control-007` §Data Model), so the person whose
  authenticator was removed is the `{user}` in `resource_path`.

## Data Model

```sql
CREATE TABLE identity.notification_address (
    address_id   UUID        PRIMARY KEY,
    principal_id UUID        NOT NULL,
    channel      TEXT        NOT NULL CHECK (channel = 'email'),
    address      TEXT        NOT NULL,
    origin       TEXT        NOT NULL CHECK (origin IN ('creation', 'added')),
    state        TEXT        NOT NULL CHECK (state IN ('pending', 'active', 'removed')),
    added_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at  TIMESTAMPTZ,
    removed_at   TIMESTAMPTZ
);
CREATE UNIQUE INDEX notification_address_held ON identity.notification_address
    (principal_id, lower(address)) WHERE state <> 'removed';

CREATE TABLE identity.security_notification (
    notification_id UUID        PRIMARY KEY,
    principal_id    UUID        NOT NULL,
    event           TEXT        NOT NULL,   -- authenticator_bound, recovery_codes_issued, ...
    source_key      TEXT        NOT NULL UNIQUE,
    occurred_at     TIMESTAMPTZ NOT NULL,
    details         JSONB       NOT NULL DEFAULT '{}',
    recipients      UUID[]      NOT NULL,   -- address_ids held at the event
    state           TEXT        NOT NULL CHECK (state IN ('requested', 'submitted', 'failed', 'no_address')),
    attempts        INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    platform_ref    TEXT,
    last_error      TEXT,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    submitted_at    TIMESTAMPTZ
);
```

- **The creation address is materialized.** The Principal path writes it in the same transaction as
  the pending mapping, when there is an email and the subject is a person. A migration backfills
  every human Principal created before this design.
- **The recipients are fixed at the event.** A request lists the addresses held when it was
  requested, and is delivered to those. Removing an address afterwards does not withdraw a
  notification already owed, so an attacker cannot silence one by changing the addresses first.
- **One request per event.** The source key is `kernel:{realm}:{kind}:{kc_event_id}`, or for a
  command, `command:{id}`. A sweep that reads an event twice requests it once.
- **What a request holds.** Its details are bounded: the authenticator type, whether the person or an
  administrator acted, and the recovery method. They hold no credential identifier, no label the
  person typed, and no code.
- **The record is evidence.** The runtime role holds no `DELETE` on either table. A request's state
  moves forward only.

## Component Design

| Component | Package | Responsibility |
| :-- | :-- | :-- |
| `Classify` | `internal/securitynotify` | Maps one kernel event to a notified event, or to none |
| `Requester` | `internal/securitynotify` | Records a request with its recipients, once per source key |
| `Dispatcher` | `internal/securitynotify` | Hands due requests to the adapter, retries with backoff, reports failures |
| `StandIn` | `internal/securitynotify` | Development adapter: accepts each request and logs its event and recipient count |
| The sweep hook | `internal/kernelevents` | Calls the requester for each event recorded for the first time, in the sweep's transaction |

The sweep calls the hook only for an event it inserted, the same `RowsAffected` it already counts. A
notification is therefore requested exactly when an event first enters the record. A sweep that fails
rolls back both together.

## Algorithms / Logic

### Dispatch

```text
every 15 seconds:
    take up to 50 requested requests whose next_attempt_at has passed, FOR UPDATE SKIP LOCKED
    for each: read its recipients' addresses; hand it to the adapter
        accepted: state submitted, platform_ref, submitted_at
        refused or unreachable: attempts + 1, next_attempt_at = now + 2^attempts minutes (at most 1 hour)
            at 10 attempts: state failed, logged at ERROR with the notification_id
```

`SKIP LOCKED` lets two replicas dispatch without handing a request over twice. A request recorded
with no addresses is `no_address`. It is logged at `ERROR` and is never dispatched: it is a person
who cannot be told.

### The Adapter

`IDENTITY_NOTIFICATION_DELIVERY` selects it:

- **Empty, the default.** No dispatcher runs. Requests are recorded and wait.
- **`standin`.** The development stand-in accepts every request and logs its event and recipient
  count, never an address. Startup refuses `standin` in production, so no production deployment can
  believe a notification was delivered when it was not.

The Notification Platform's client replaces the stand-in when that platform exists.

## API / Interface

```text
GET /v1/principals/{principal_id}/notification-addresses     provider
GET /v1/principals/{principal_id}/security-notifications     provider: the hundred most recent
```

Both are investigation reads, recorded with their reason like every other read
(`TDD-identity-control-005` §Evidence). An address is shown to a provider, because assisted recovery
needs to know where a person is told. It is never written to a log.

### A Person's Own Addresses (1.2.0)

```text
GET  /v1/me/notification-addresses                      self: held and pending, never removed ones
POST /v1/me/notification-addresses                      self, aal2 recent: {"address": "..."}
POST /v1/me/notification-addresses/{address_id}:verify  self: {"code": "..."}
POST /v1/me/notification-addresses/{address_id}:remove  self, aal2 recent
```

- **Adding needs `aal2`, recently.** It is the same step-up as removing an authenticator
  (`IDENTITY_STEP_UP_MAX_AGE`, `ADR-IAM-004 §5.2`). An address changes where the person is told
  about every later change, so it is protected like an authenticator. An add also needs an
  `Idempotency-Key`.
- **An added address is pending until proven.** The service draws a code of 8 digits from the
  operating system's random source. It keeps the code's SHA-256, bound to the address identifier,
  and sends the code to that address alone, as a `notification_address_proof` request.
  - The code is good for the `securityref` lifetime, 10 minutes by default, and five attempts.
  - A wrong, expired or exhausted code leaves the address pending. The person removes it and adds
    it again.
  - A pending address receives nothing else.
- **The code is sealed while it waits.** The request carries it sealed with AEAD_AES_256_GCM under
  the `securityref` key ring. The sealing is bound to the Principal and to the purpose
  `notification-address-proof`.
  - The dispatcher opens the code only to hand it to the adapter, then clears it from the row.
  - A request whose seal has expired is failed, not sent.
  - No code is logged, and the stand-in never sees one in a log line.
- **Proving an address notifies the others.** The address becomes active, and a
  `notification_address_changed` request (`change` added) goes to the addresses held before it.
  The request names the new address only masked, such as `a***@example.com`.
- **Removing an address notifies every address held before.** That includes the one removed, so an
  attacker who removes the person's own address still tells them. The last active address cannot
  be removed: a person who cannot be told is the failure this design exists to prevent.
- **The list is bounded.** A person holds at most five addresses, active or pending. An address
  already held, compared without case, is refused.
- **An address is an email.** It is parsed as one bare addr-spec, with no display name, at most 254
  characters, and stored as given.

## Configuration

| Variable | Default | Purpose |
| :-- | :-- | :-- |
| `IDENTITY_NOTIFICATION_DELIVERY` | empty | `standin` on a development server; refused in production |

## Testing Strategy

- Each kernel mark in §Technical Context maps as the table says. The enrolment's `LOGIN`, the legacy
  `UPDATE_TOTP`, and every other event map to nothing.
- A removal through the Admin API is attributed to the person in its path, not to the actor.
- A request lists the addresses held at the event, and later removing an address does not change
  it.
- A request is recorded once per source key, and a request with no address is `no_address`.
- The dispatcher hands a due request over once, backs off on a refusal, and fails it at ten
  attempts.
- Startup refuses `standin` in production.
- A person's own addresses (1.2.0):
  - Adding needs a recent `aal2`. A malformed, duplicate or sixth address is refused.
  - The proof request goes to the new address alone, and its code is sealed. Once handed over, the
    seal is cleared.
  - The right code activates the address and notifies the others. A wrong code, the sixth attempt
    and an expired code each leave the address pending.
  - Removing notifies every address held before, the removed one included, and the last active
    address cannot be removed.
- The runtime role cannot delete an address or a request.
- Against the live kernel in `deploy-dev`: the bootstrap operator's TOTP enrolment requests
  `authenticator_bound` and `recovery_codes_issued` to the creation address, and the stand-in
  accepts them.

## Security Notes

Addresses are personal data, and they protect the account. A provider reads them through the
recorded investigation route, and no log line carries one.

Recording a request in the same transaction as its event is what makes a notification
impossible to lose without losing the event as well.

## Operational Notes

| Signal | Meaning |
| :-- | :-- |
| A request `failed` | The adapter refused it ten times; the person was not told |
| A request `no_address` | A person with no notification address; give them one |
| Requests `requested` with no dispatcher | `IDENTITY_NOTIFICATION_DELIVERY` is empty; expected until the Notification Platform exists |

## Traceability

| Relationship | Target |
| :-- | :-- |
| Governed by | ADR-IAM-007, NIST SP 800-63B-4 §4.6 through it |
| Conforms to | STD-IAM-001 §3.1 (2.6.0) |
| Consumes | `TDD-identity-control-007`, the kernel event record |
| Proven by | identity-kernel `compat/notified_events_test.go`, the kernel marks |
| Delivers through | PAD-PLT-005, the Notification Platform, once it exists |
