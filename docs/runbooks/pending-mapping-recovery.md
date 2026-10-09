# Pending-Mapping Recovery

## Purpose

A mapping is `pending` between its two checkpoints: the claim and the kernel create
(`TDD-identity-control-001` §Idempotency and Crash Recovery). A crash, a timeout or an ambiguous
answer leaves it there. Recovery finishes it on a schedule. This runbook covers what an operator
does when recovery does not finish it, and the one way an operator puts an `active` mapping back
into recovery: `:relink`, for a mapping whose kernel user is gone.

## How recovery works

`RecoverPending` (`internal/identity/provisioning/provisioner.go`) reads up to 100 mappings that have
been `pending` longer than `IDENTITY_PENDING_RECOVERY_AFTER` (60 seconds by default). For each one it
searches the kernel for users carrying the `principal_id`:

| Users found | What recovery does |
| :-- | :-- |
| exactly one | records it and activates the mapping |
| none | retries the create with the same `principal_id`, username and email, from the row |
| more than one | disables every match and quarantines the mapping: [duplicate-identifier containment](duplicate-identifier-containment.md) |

It runs before every Principal sweep, at startup and every `IDENTITY_REGISTRATION_RECONCILE_INTERVAL`
(1 hour by default), and on `POST /v1/principals:reconcile` (`cmd/identity-control/main.go`,
`scheduleSweeps`). `IDENTITY_RECONCILE_INTERVAL` is not read (§Identity Control Service Settings).

## Signals

- **Log, `WARN`:** `kernel create did not confirm; mapping left pending for recovery`, with
  `principal_id` and `error`. The caller got `503` with "retry with the same Idempotency-Key".
- **Log, `ERROR`:** `kernel user created but activation did not commit; recovery will adopt it`.
- **Log, `ERROR`:** `recovery of one mapping failed; continuing the sweep`, with `principal_id` and
  `error`. One mapping that keeps failing logs this on every sweep.
- **Log, `ERROR`:** `principal sweep failed`, which stops recovery for that run.
- **Log, `WARN`:** `principal sweep`, with `recovered` above zero: recovery finished something.
- **Log, `ERROR`:** `an active Principal's Keycloak user is gone; relinking it is an operator's
  decision`, and a `dangling` finding in `GET /v1/principals:dangling`. This starts the relink path
  below.
- **A caller's retry answers `409`** with `request-in-progress` ("An identical request is already in
  progress; retry after it completes"). This holds only while the mapping is pending: recovery
  completes the key (`TDD-identity-control-001` 1.14.0).

- **Gauge:** `identity.principal.pending{overdue="true"}` above zero: a mapping pending past
  `IDENTITY_PENDING_RECOVERY_AFTER` (`TDD-identity-control-001` 1.18.0).
- **API:** `GET /v1/principals:pending` lists every pending mapping, oldest first, with `username`,
  `created_at` and `overdue`.

`TDD-identity-control-001` §Operational Notes classes pending mappings past the recovery threshold as
a **warning**.

## Authority

A provider, with a token at `aal2`. `:relink` is a command: it also needs `auth_time` within
`IDENTITY_STEP_UP_MAX_AGE` and an `X-Administrative-Reason`.

## Steps: a mapping that stays pending

1. **List them.** `GET /v1/principals:pending`. An entry with `overdue: true` is one recovery has had
   at least one chance to resolve; one with `overdue: false` is a creation still in flight, which
   recovery leaves alone until the threshold.
2. **Run recovery now.** Call `POST /v1/principals:reconcile`. `recovered` in the answer counts the
   mappings it finished. A `503` ("The identity kernel could not be enumerated; retry") means the
   kernel could not be reached. Fix that first: nothing
   recovers without it.
3. **Read the error for the `principal_id`** from `recovery of one mapping failed`:
   - **Unavailable or timeout.** The kernel or the network. Recovery retries at the next sweep, and
     nothing is lost: the mapping is durable.
   - **Forbidden.** The administration client lost `manage-users` or `view-users`
     (`deploy/dev/create-kernel-clients.sh` grants them). Restore the role in identity-kernel.
   - **A conflict on the create.** The kernel holds a user with that username that does not carry
     this `principal_id`, so the search found nothing and the retried create is refused. Find that
     user with the Principal sweep's findings: it is an `unmapped` or `orphan` finding, or another
     Principal's user. Triage it with [unmapped-Principal triage](unmapped-principal-triage.md).
     Recovery succeeds once the username is free.
4. **Tell the caller what to retry.** A caller that kept its `Idempotency-Key` gets `409`
   `request-in-progress` while the mapping is pending. Once recovery resolves it, the same key answers
   `201` with the `principal_id` the request minted, and makes no kernel call
   (`TDD-identity-control-001` 1.14.0, `completeCreation` in `provisioner.go`). So the caller retries
   with the same key and never a new one. A mapping written before 1.14.0 holds no key, and its
   retry keeps answering `409`: give that caller the `principal_id` from the log line. A provider can
   confirm the Principal with `GET /v1/principals:search?q=<username>`, which matches the start of a
   username or email (at least `IDENTITY_ADMIN_SEARCH_MIN_LENGTH` characters, 3 by default).

## Steps: relinking a dangling mapping

A Keycloak user can be deleted on purpose, so the sweep never relinks. "Relinking is an operator's
decision, made through `:relink` with a reason" (§Reconciliation Sweep).

1. **Read the finding.** `GET /v1/principals:dangling` lists the open `dangling` findings.
2. **Find out why the user is gone.** Read the kernel's admin events for the deletion. They are kept
   for 7 days.
   - **Deleted to remove someone's access.** Do not relink. Record the decision. Retiring a human
     Principal is not built (see Gaps), so the finding stays open.
   - **Lost by accident,** for example a console mistake or a realm rebuilt from nothing. Continue.
3. **Relink.** `POST /v1/principals/{principal_id}:relink` with `X-Administrative-Reason`.
   - It refuses a mapping that is not `active`, a workload (whose path is
     `POST /v1/workloads/{id}:rebuild`), and, with `409`, a user that still exists.
   - It answers `503` and changes nothing when the kernel cannot be reached.
   - On success it returns the mapping to `pending`, records the caller, the reason and the previous
     user in `principal_relink`, resolves the finding as `relinked`, and runs recovery at once.
4. **Read the answer.** `{"principal_id", "state"}`. `active` means recovery found or created the user.
   `pending` means it did not finish, and the log says `recovery after the relink did not complete;
   the scheduled recovery will retry`. Continue with the steps above.

The new user has the same `principal_id`, so the Principal's Memberships held by
`organization-control` are unchanged. Recovery creates it from the row's username and email only,
so it holds no password and no authenticator (see Gaps).

## Verification

- `GET /v1/principals/{principal_id}` answers `state: active`.
- `GET /v1/principals:dangling` no longer lists it, and `GET /v1/principals/{principal_id}/findings`
  shows the finding resolved as `relinked` or `user_present`.
- `recovery of one mapping failed` stops for that `principal_id`, `GET /v1/principals:pending` no
  longer lists it, and `identity.principal.pending{overdue="true"}` returns to zero.

## Never do

- **Retry `POST /v1/principals` with a new `Idempotency-Key`.** That mints a second identifier for one
  person. The `503` message says to retry with the same key for this reason
  (`internal/httpapi/principals.go`, `writeProvisioningError`).
- **Set `keycloak_user_id` on a pending row by hand.** Recovery's search is the only thing that
  proves the user carries the identifier.
- **Delete a pending row.** Its identifier is "the only way to find the user if the call actually
  succeeded" (`provisioner.go`).
- **Lower `IDENTITY_PENDING_RECOVERY_AFTER` to or below `IDENTITY_PROVISION_TIMEOUT`.** Startup refuses
  it, because recovery would search for a user the original request is still creating.

## Gaps

- **Fixed in `TDD-identity-control-001` 1.14.0: recovery completes the creating request's key.**
  Before it, the mapping did not record the key, so after recovery a retry with that key answered
  `409` `request-in-progress` for as long as the claim was kept. Mappings written before the fix
  still hold no key (step 3).
- **Fixed in `TDD-identity-control-001` 1.18.0: a listing and a metric.** `GET /v1/principals:pending`
  and the `identity.principal.pending` gauge, by `overdue`, are the warning's instrument.
- **No route abandons a pending mapping** whose create can never succeed.
- **No credential path after a relink.** The recreated user has no password or authenticator, and
  this service offers no route to give it one. How the person signs in again is not designed here.
- **No route retires a human Principal.** A dangling mapping whose user was deleted on purpose stays
  `active` with an open finding.

## References

- `TDD-identity-control-001` §Data Model, §API / Interface, §Idempotency and Crash Recovery,
  §Reconciliation Sweep, §Identity Control Service Settings, §Operational Notes.
- NIST SP 800-61 Rev. 3, Table 2, RC.RP-05
  (<https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf>, accessed
  2026-10-07): "The integrity of restored assets is verified, systems and services are restored, and
  normal operating status is confirmed". This is the verification after a relink: the state is read
  back, not assumed.
- NIST SP 800-53 Rev. 5, AC-2, from the OSCAL catalog
  (<https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json>,
  accessed 2026-10-07): "Create, enable, modify, disable, and remove accounts in accordance with
  [Assignment]". This is why step 2 of the relink asks whether the deletion was a decision before
  the account is recreated.
