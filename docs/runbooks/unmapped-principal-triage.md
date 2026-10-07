# Unmapped-Principal Triage

## Purpose

A Keycloak user that no mapping accounts for came from outside every authorized creation path
(`TDD-identity-control-001` §Authorized and Prohibited Creation Paths). This runbook decides what
that user is and removes it from the kernel when it should not be there.

It covers two finding classes the Principal sweep records (`internal/identity/provisioning/sweep.go`):
- **`unmapped`**: the user carries no `scnehaux_principal_id`.
- **`orphan`**: the user carries an identifier that no mapping and no pending workload holds.

A user carrying another Principal's identifier is a `duplicate`. That is
[duplicate-identifier containment](duplicate-identifier-containment.md), not this runbook.

## Signals

- **Log, `ERROR`:** `a Keycloak user carries no principal_id; it came from outside every authorized
  creation path`, with `finding_class`, `username` and `disabled`.
- **Log, `ERROR`:** `a Keycloak user carries a principal_id no mapping holds`, with
  `claimed_principal_id` as well.
- **Log, `WARN`:** `principal sweep`, with the counts `unmapped` and `orphan`
  (`cmd/identity-control/main.go`, `scheduleSweeps`).
- **API:** an entry with `finding_class` `unmapped` or `orphan` in `GET /v1/principals:unmapped`.

`TDD-identity-control-001` §Operational Notes classes an unmapped Principal as **critical**. No
event is emitted yet. The finding and the `ERROR` line are the alert (§Reconciliation Sweep).

## Authority

- A provider, with a token at `aal2` (`providerOnly`).
- A Keycloak realm administrator for step 6 only. This service does not delete users, by design
  (§Reconciliation Sweep: "Disabling rather than deleting is deliberate").

## Steps

1. **Read the open findings.** Call `GET /v1/principals:unmapped`. Each entry has `finding_id`,
   `finding_class`, `username`, `user_disabled`, `detected_at`, and `claimed_principal_id` for an
   orphan. The list is oldest first.
2. **Check whether the user is already disabled.** `user_disabled: true` means the sweep disabled it.
   It does that only under `IDENTITY_UNMAPPED_USERS=disable`, the production default
   (`internal/config/config.go`). Under `report`, the user can still sign in. Treat that as an open
   incident and make the step 6 decision first.
3. **Find out how the user was made.** Read the kernel's admin events for that `username`.
   identity-kernel enables admin events with representation and 7-day retention (`ROADMAP.md`
   §Proof B). Past 7 days the kernel no longer holds the event, so do this step first. The usual
   causes are:
   - a console creation, which the user profile should have refused (Proof B scenario 6b);
   - an import;
   - a user-profile change that dropped the required attribute;
   - an identity-provider first login that created a user, which the realm must not allow
     (§Realm Configuration Required by This Design).
4. **For an orphan, read `claimed_principal_id`.** It may not parse as an identifier. When it does,
   call `GET /v1/principals/{claimed_principal_id}`:
   - a `404` means no Principal ever held that identifier. Someone typed it in.
   - A Principal that exists means a mapping was lost or retired. A retired Principal's identifier
     on a live user is a re-use. Escalate it as an access incident.
5. **Close the creation path that let the user in.** That path is a realm setting identity-kernel
   owns, so the change is made there, not here. Do this before step 6, or the next import makes
   another one.
6. **Decide the user's fate.**
   - **It should not exist.** A realm administrator deletes it in the kernel. The next complete
     sweep resolves the finding as `user_absent`.
   - **It is evidence in an open incident.** Leave it disabled. Under `report`, disable it in the
     kernel first. A user left disabled keeps its finding open, which is intended: "a user disabled
     and left in place is still evidence" (§Reconciliation Sweep).
   - **It belongs to a real person who needs access.** Create that person through
     `POST /v1/principals`, with a new `Idempotency-Key`, and delete the stray user. No route turns
     an existing user into a Principal (see Gaps).
7. **Record the decision** in the incident record: the `finding_id`, the cause from step 3, the
   change from step 5, and who decided step 6.

## Verification

- After the next sweep, the finding is gone from `GET /v1/principals:unmapped`. Its row is kept,
  with `resolution = 'user_absent'`.
- The sweep runs on `IDENTITY_REGISTRATION_RECONCILE_INTERVAL` (1 hour by default). To run one now,
  call `POST /v1/principals:reconcile`. The answer counts what that sweep found:
  `{"recovered", "dangling", "unmapped", "orphan", "duplicate"}`.

## Never do

- **Add a `scnehaux_principal_id` to the user by hand.** It makes the user an orphan or a
  duplicate, and it creates a Principal no authorized path made.
- **Re-enable a disabled user to "see what it does".** Disabling exists so that a false positive is
  recoverable. Re-enabling one that is not a false positive restores the access that was cut.
- **Switch `IDENTITY_UNMAPPED_USERS` to `report` in production to quiet the alert.** The setting
  exists for the rollout of an estate whose users predate this service (§Reconciliation Sweep).
- **Delete or resolve a finding row.** The runtime deletes none, and a finding resolves only by
  what the sweep sees.

## Gaps

- **No route adopts an existing user as a Principal.** A legitimate user made outside the path is
  replaced, not adopted.
- **No event is emitted.** `identity.principal.*_detected` waits for Audit & Evidence
  (`TDD-identity-control-007` §Scope). Alerting depends on the log line.

## References

- `TDD-identity-control-001` §Reconciliation Sweep, §Operational Notes, §Realm Configuration
  Required by This Design.
- NIST SP 800-53 Rev. 5, AC-2(3) Disable Accounts, from the OSCAL catalog
  (<https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json>,
  accessed 2026-10-07): "Disable accounts within [Assignment] when the accounts: ... (c) Are in
  violation of organizational policy". This is why the production default disables.
- NIST SP 800-53 Rev. 5, AC-2, same source: "Create, enable, modify, disable, and remove accounts in
  accordance with [Assignment]". An account made outside the authorized path is the case this
  runbook removes.
- NIST SP 800-61 Rev. 3, Table 2, RS.AN-03
  (<https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf>, accessed
  2026-10-07): "Analysis is performed to establish what has taken place during an incident and the
  root cause of the incident". This is steps 3 to 5: the creation path is found and closed before
  the user is removed.
- NIST SP 800-61 Rev. 3, Table 2, RS.AN-07, same source: "Incident data and metadata are
  collected, and their integrity and provenance are preserved". This is why the finding row is kept
  and admin events are read before their retention ends.
