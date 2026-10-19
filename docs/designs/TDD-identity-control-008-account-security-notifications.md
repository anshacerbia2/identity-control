---
doc_meta:
  id: TDD-identity-control-008
  title: Account Security Notifications
  owner: Core Platform Team
  version: 1.6.0
  status: approved
  classification: restricted
  review_cycle_days: 90
  created_date: 2026-10-06
  last_reviewed: 2026-10-19
  parent_sad: SAD-001
---

# Account Security Notifications

## Purpose

Specify how this service tells a person that their account changed, as `ADR-IAM-007` decides. This
service decides which events are notified and to whom. It records each notification as evidence and
hands it to the Notification Platform (`PAD-PLT-005`) to deliver. The kernel sends no mail
(`ADR-IAM-007 §5.4`).

## Scope

**In scope (1.4.0)**

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
- **Assisted recovery (1.3.0).** A provider's restore of a suspended Principal is notified as an
  account recovered (`ADR-IAM-007 §5.1`).
- **A removal told as who acted (1.4.0).** An authenticator this service's own command removed is
  told as the person's or the provider's, with its type, rather than as an Admin API removal.

**Not yet**

- **The Identity Experience page** that serves these routes. It follows in `identity-experience`.
- **The Notification Platform client.** It waits on that platform. Until then no notification leaves
  a development server.
- **Proving an added address on a development server (1.6.0).** The code goes to the new address
  alone, and the stand-in delivers nothing, so no one can read it there. The options are in §Proving
  an Address on a Development Server; none is chosen.
- **A provider adding an address for a person (1.6.0).** `ADR-IAM-007 §5.2` says "A provider can do
  it through assisted recovery". No route does, and this design has none (§A Person With No Address).

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
| An authenticator removed through the Admin API | admin `ACTION`, resource `USER`, path `users/{user}/credentials/{credential}` | `authenticator_removed`, by an administrator, unless this service's command made it (1.4.0) |

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
- **This service's own removals are admin events too (1.4.0).** A person's
  `POST /v1/me/authenticators/{security_ref}:remove` and a provider's `:revoke` both delete through
  the Admin API, as this service's service account. The kernel event cannot tell them apart from a
  removal in the Admin Console, so the command tells its own (§Removals Told as Who Acted).

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
  command, `command:{id}`. A removal of a kernel credential is keyed by the credential instead,
  `credential:{realm}:{sha256 of its id}:removed`, whichever path records it (1.4.0). A sweep that
  reads an event twice requests it once.
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
| The applied hook (1.3.0) | `internal/securitystate` | Calls the requester for each security command applied, in the transaction that records it |

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

### Assisted Recovery (1.3.0)

Assisted recovery is three commands (`TDD-identity-control-005`): suspend, revoke the lost factor,
restore. The revocation is told already, as the kernel's admin `ACTION` above. The restore is what
gives the person their account back, so it is the recovery `ADR-IAM-007 §5.1` notifies, as NIST
SP 800-63B-4 §4.2.3 requires.

```text
the executor records a restore's applied outcome:
    in the same transaction, request account_recovered for the restored Principal
        details   {"method": "assisted", "actor": "administrator"}
        source    command:operation:{operation_id}
        recipients the Principal's active addresses at that instant
```

- **Only an applied restore is told.** A refused, retrying or unresolved restore gave nothing back.
  Suspension and ending sessions are not in `ADR-IAM-007 §5.1`, and request nothing.
- **It commits with the outcome.** `securitystate` calls a hook (`OnApplied`) in the transaction
  that finishes the attempt, so it does not depend on this package (`arch.json`). If the request
  cannot be recorded, the finish fails as a whole. The attempt is then taken again when its lease
  ends, so a restore is never recorded as applied without its notification.
- **One request per operation.** The source key is the operation's, so an attempt finished twice
  requests once.

### Removals Told as Who Acted (1.4.0)

Telling a person that an administrator removed their authenticator, when they removed it themselves,
is the alarm NIST SP 800-63B-4 §4.6 asks them to act on: it sends them to the repudiation contact
for nothing. The command knows who asked, so the command tells it.

```text
the executor deletes a kernel credential for authenticator.remove (self) or authenticator.revoke:
    the applied outcome names the credential and its type
    in the transaction that records it applied, request authenticator_removed
        details    {"authenticator": otp | webauthn | password, "actor": self | administrator}
        source     credential:{realm}:{sha256(credential id)}:removed
the sweep reads the admin ACTION on users/{user}/credentials/{credential}:
    request authenticator_removed, actor administrator, under the same source key
```

- **One request per removal.** Both paths use the credential's key. The command finishes in the
  same moment as its kernel call, before the next sweep, so it is normally first, and the sweep's
  later insert records nothing.
- **The sweep can be first.** It can read the event between the kernel call and the finish. The
  command's insert then replaces the details of the request while it is still `requested`. A request
  already handed over is never rewritten: the person keeps what they were told.
- **Only a removal the command made is claimed.** A credential gone before the command deleted it,
  whether another caller removed it or an earlier attempt of the same command did, names no
  credential. Its removal is told by the sweep, as an administrator's. A wrong label in that rare
  case says "administrator" rather than hiding one.
- **The Admin Console stays an administrator's.** No command names its credential, so the sweep
  alone records it.
- **No credential identifier is held.** The key holds the identifier's SHA-256, as the details
  hold no identifier (§Data Model).

### The Adapter

`IDENTITY_NOTIFICATION_DELIVERY` selects it:

- **Empty, the default.** No dispatcher runs. Requests are recorded and wait.
- **`standin`.** The development stand-in accepts every request and logs its event and recipient
  count, never an address. Startup refuses `standin` in production, so no production deployment can
  believe a notification was delivered when it was not.

The Notification Platform's client replaces the stand-in when that platform exists.

**A development server runs `standin` (1.6.0).** `deploy/dev/.env.example` sets it, and its README
says why, as `deploy-dev` in CI already did. Empty would leave every request `requested` on that
server, so the dispatch path, the backoff and the seal's clearing would run only in CI. The stand-in
delivers nothing, so `standin` on a development server tells no one anything: what it adds is that
the server records each request as handed over, as production will.

### Proving an Address on a Development Server (1.6.0, open)

A person adds an address in the account application, and it stays pending until its code comes back
(§A Person's Own Addresses). On a development server the code goes to the stand-in, which delivers
nothing and logs no code. So nobody can complete `:verify` there: `scripts/dev-notifications-proof.ps1`
proves only that a wrong code leaves the address pending, and the integration tests
(`addresses_integration_test.go`) prove the right code against the sealed request. This design does
not define a development way to read the code. Each option below keeps the code out of every log and
every response in a mode that is not development, which the sources require of a secret:

- OWASP ASVS 4.0.3 7.1.1: "Verify that the application does not log credentials or payment
  details." [R1]
- OWASP Logging Cheat Sheet, data to exclude: "Authentication passwords", "Access tokens" and
  "Encryption keys and other primary secrets" [R2].
- OWASP ASVS 4.0.3 14.3.2: "Verify that web or application server and application framework debug
  modes are disabled in production to eliminate debug features, developer consoles, and unintended
  security disclosures." [R1]

The code proves that the person controls the address. NIST SP 800-63B-4 §4.6 has notifications go
"to the notification addresses stored in the subscriber account", which "may be any means by which
the subscriber can be reliably contacted" [R3]. A code read anywhere but at the address proves
nothing about it, so every option below is for a development server only, and production refuses it
at startup as it refuses `standin`.

| Option | What it is | For | Against |
| :-- | :-- | :-- | :-- |
| A. A development mail catcher | A second development adapter, `smtp-catcher`, hands each request to a local catcher such as Mailpit, "an email & SMTP testing tool with API for developers", whose "REST API" serves "Integration testing using the REST API to view, read and process messages" [R4]. The catcher runs in the development stack, on an internal network, with no relay | The code reaches an inbox, as it will in production, and no log or response carries it. `deploy-dev` could read the message through the catcher's API and prove `:verify` end to end | A new container and adapter in this repository. This service would render a message, which `ADR-IAM-007 §5.3` gives the Notification Platform ("It does not render or send anything itself"), so it needs that decision's owner to accept a development-only exception |
| B. A sealed file the operator reads | The stand-in writes the opened code to a file on a development-only volume, mode `0600`, owned by the service user, and logs nothing | No new container. The code is never in a log or a response | A secret at rest on the server's disk, read with shell access. It is a second, development-only code path in the dispatcher |
| C. A development-only read route | `GET /v1/me/notification-addresses/{id}/proof-code` answers the opened code to its own person, only when `IDENTITY_ENVIRONMENT` is not production | The account application could show it; the proof script could use it | A code in a response is the disclosure ASVS 14.3.2 names. Its whole safety rests on one switch, which production must never carry |
| D. Leave it unproven on development servers | Today's state, stated | Nothing new to secure | The account application's add path cannot be completed on a development server, and only the integration tests prove the right code |

**No option is chosen.** Option A is the closest to production and the only one that puts no code
on disk or in a response, but it touches `ADR-IAM-007 §5.3`, which is cross-cutting and belongs to the
architecture repository. Until a decision is recorded there, this design keeps option D.

| Ref | Source |
| :-- | :-- |
| R1 | OWASP, *Application Security Verification Standard 4.0.3*, V7 and V14, <https://github.com/OWASP/ASVS/tree/v4.0.3/4.0/en>, accessed 2026-10-19: 7.1.1 "Verify that the application does not log credentials or payment details. Session tokens should only be stored in logs in an irreversible, hashed form."; 14.3.2 "Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features, developer consoles, and unintended security disclosures." |
| R2 | OWASP, *Logging Cheat Sheet*, Data to exclude, <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>, accessed 2026-10-19: "Session identification values", "Access tokens", "Authentication passwords", "Encryption keys and other primary secrets" |
| R3 | NIST, *SP 800-63B-4*, §4.6 Subscriber Notifications, <https://pages.nist.gov/800-63-4/sp800-63b.html>, accessed 2026-10-19: "Events that require notification SHALL cause a notification to be sent to the notification addresses stored in the subscriber account. Notification addresses may be any means by which the subscriber can be reliably contacted" |
| R4 | Mailpit, <https://mailpit.axllent.org/>, accessed 2026-10-19: "email & SMTP testing tool with API for developers"; "Integration testing using the REST API to view, read and process messages" |

### A Person With No Address (1.6.0, open)

A Principal created without an email holds no address, and every request for it is `no_address`
(§Dispatch). Up to 1.5.0 §Operational Notes said "give them one". Only the person can:

- **The person adds one,** in the account application, at a recent `aal2`, and proves it with its
  code (§A Person's Own Addresses). Until that is proven they still hold none, and the first address
  has no address held before it to notify.
- **No provider route adds one.** `ADR-IAM-007 §5.2` says "A provider can do it through assisted
  recovery", and this design has no such command. It is not built, because what it needs is not
  designed: whether a provider-added address is proven by its code like the person's, which address is
  told, and how it is recorded as assisted recovery's evidence. A route is not added without that
  design.

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

- **Each of the three commands requires an `Idempotency-Key` (1.5.0)**, and a retry with it is
  answered the first response. Adding required one before and recorded nothing, so a retried add
  was a second add (`TDD-identity-control-003` §The Idempotency-Key on Every Command).

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

- A person's own removal is told as `self` with its type, and a provider's as `administrator`, once
  each, whether the command or the sweep records it first. A request already handed over is not
  rewritten, and a removal in the Admin Console stays an administrator's (1.4.0).

- An applied restore requests `account_recovered`, method `assisted`, to the Principal's active
  addresses, once. A suspension requests nothing, and a hook that fails leaves the restore
  unfinished (1.3.0).

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
| A request `no_address` | A person with no notification address. Ask them to add one in the account application; no provider route adds one (§A Person With No Address) |
| Requests `requested` with no dispatcher | `IDENTITY_NOTIFICATION_DELIVERY` is empty; expected until the Notification Platform exists |

## Traceability

| Relationship | Target |
| :-- | :-- |
| Governed by | ADR-IAM-007, NIST SP 800-63B-4 §4.6 through it |
| Conforms to | STD-IAM-001 §3.1 (2.6.0) |
| Consumes | `TDD-identity-control-007`, the kernel event record |
| Consumes | `TDD-identity-control-005`, the applied restore of assisted recovery (1.3.0) |
| Proven by | identity-kernel `compat/notified_events_test.go`, the kernel marks |
| Delivers through | PAD-PLT-005, the Notification Platform, once it exists |
