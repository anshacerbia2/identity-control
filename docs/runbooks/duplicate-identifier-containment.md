# Duplicate-Identifier Containment

## Purpose

Two Keycloak users carry the same `scnehaux_principal_id`. Either user's token asserts that
Principal, so every domain that keys on `principal_id` treats them as one person. Keycloak does not
enforce attribute uniqueness. The sweep and pending recovery are the compensating control
(`TDD-identity-control-001` §Reconciliation Sweep, §Keycloak Admin API: "Uniqueness. It is not
enforced.").

The service contains a duplicate itself: it disables both users and quarantines the mapping. This
runbook confirms the containment, finds the cause, and records what is left for a decision.

## Signals

Two paths find a duplicate, and they leave different records.

- **The sweep** (`internal/identity/provisioning/sweep.go`):
  - log, `ERROR`: `a second Keycloak user carries a Principal's identifier; both users are
    disabled`, with `principal_id`, `username`, `disabled` and `quarantined`;
  - a `duplicate` entry in `GET /v1/principals:unmapped`, with `principal_id` and the extra user's
    `username`;
  - the `duplicate` count in the `principal sweep` `WARN` line.
- **Pending recovery** (`internal/identity/provisioning/provisioner.go`, `recoverOne`):
  - log, `ERROR`: `duplicate principal_id in the kernel; both users disabled and mapping
    quarantined`, with `principal_id` and `matches`;
  - then `recovery of one mapping failed; continuing the sweep` for the same `principal_id`.
  - This path quarantines the mapping and disables every matching user. It writes no
    `principal_finding` row. It completes the creating request's key with the `principal_id`, so
    the caller's retry learns which Principal its request made, now quarantined
    (`TDD-identity-control-001` 1.14.0).

- **API and gauge:** the mapping in `GET /v1/principals:quarantined`, with `quarantined_at`,
  `quarantine_reason` and `linked` (whether it holds a kernel user; one recovery quarantined does
  not), and `identity.principal.quarantined` above zero (`TDD-identity-control-001` 1.18.0).

`TDD-identity-control-001` §Operational Notes classes a duplicate as **critical**.

## Authority

A provider, with a token at `aal2`. Steps 1 to 7 change nothing: containment is already done by the
service. Step 8, the release, is a command: it also needs `auth_time` within
`IDENTITY_STEP_UP_MAX_AGE`, an `X-Administrative-Reason` and an `Idempotency-Key`. A Keycloak realm
administrator deletes the extra user in step 8; this service deletes no user.

## Steps

1. **Name the Principal.** Take `principal_id` from the log line or the finding.
2. **Confirm the containment.** Call `GET /v1/principals/{principal_id}`:
   - `state` is `quarantined`, with `quarantined_at` and `quarantine_reason`. The sweep's reason is
     "the sweep found a second Keycloak user carrying this principal_id". Recovery's reason is
     "N kernel users carry this principal_id".
   - A mapping that was already `quarantined` or `retired` keeps its state. Only its users are
     disabled (§Reconciliation Sweep).
   - `user_disabled: true` on the `duplicate` finding means the sweep disabled the extra user. A
     duplicate is disabled "whatever `IDENTITY_UNMAPPED_USERS` says".
3. **Read what the Principal did.** Read the evidence before anything changes:
   - `GET /v1/principals/{principal_id}/sessions`. It needs the mapping's own kernel user, so it
     fails for a mapping recovery quarantined, which holds none (`internal/investigation`,
     `kernelUser`);
   - `GET /v1/principals/{principal_id}/events`, the kernel event record (`TDD-identity-control-007`);
   - `GET /v1/principals/{principal_id}/findings`.
   Each read is recorded as privileged access, naming the reader (`internal/investigation`,
   `record`).
4. **Tell the domains that key on the Principal.** Both users are disabled, and nothing here ends
   their sessions (see Gaps). An access token already issued stays valid until it expires. Its
   lifetime is the audience's class (SAD-001 §7.7). Treat any action taken under that
   `principal_id` since the extra user appeared as possibly either user's.
5. **Find the cause.**
   - Read the kernel's admin events for the extra user's `username`. They are kept for 7 days.
   - A user made through the console with a copied identifier, or an import, is a prohibited
     creation path (§Authorized and Prohibited Creation Paths).
   - A duplicate found by recovery, with no outside creation, is a kernel create that landed twice.
     The search retries with the same identifier by design (§Idempotency and Crash Recovery).
     Report it as a defect in this service.
6. **Close the creation path,** as in [unmapped-Principal triage](unmapped-principal-triage.md)
   step 5.
7. **Decide which user is the person,** with the Principal's owner and security. Record the
   decision, naming the username kept.
8. **Release the mapping** (`TDD-identity-control-001` 1.18.0 §Leaving Quarantine):
   1. Delete the other user in the kernel's console, as a realm administrator. Only that one: the
      Principal outlives its kernel user, and a release needs exactly one user carrying the
      identifier.
   2. `POST /v1/principals/{principal_id}:release` with `X-Administrative-Reason` and
      `{"username": "<the username kept>"}`. It answers `200` with `state: suspended`: the mapping is
      bound to that user, the user stays disabled and its sessions are ended, and the release is
      recorded in `identity.principal_release` with you, the reason and the reason it was held.
      - `409` naming a count means the kernel does not hold exactly one user carrying the
        identifier: the extra one is not deleted yet, or both were (see Gaps).
      - `409` "is not the username named" means the one user left is not the one decided. Stop:
        the wrong user may have been deleted.
      - `409` for a mapping that is not quarantined, or a workload; `503` when the kernel did not
        confirm the containment, with nothing recorded, so retry with the same key.
   3. `POST /v1/principals:reconcile`. The sweep resolves the `duplicate` finding as `user_absent`
      once it no longer finds the deleted user.
   4. **Return the person to service** with `POST /v1/principals/{principal_id}:restore`
      (`TDD-identity-control-005` §Containment Is Reversible), with `{"expected_version": <the
      security_version GET /v1/principals/{principal_id} answers>}`. It refuses while any finding
      about the Principal is open, which is why step 3 comes first. Release and restore are two
      decisions on purpose: the first proves the duplicate is gone, the second returns access.
      Proof B scenario 6b runs this step against the kernel on every `deploy-dev` run.

## Verification

- Until step 8, `GET /v1/principals/{principal_id}` answers `state: quarantined`, and both users stay
  disabled. A later sweep logs nothing new for them while the finding is open (`act` in `sweep.go`
  logs only a new finding or a new quarantine).
- The finding resolves as `user_absent` only after the extra user is deleted in the kernel and a
  complete sweep no longer returns it.
- After the release, `GET /v1/principals:quarantined` no longer lists the Principal, and it reads
  `suspended`; after the restore, `active`, with the kept user enabled.

## Never do

- **Re-enable either user in the console.** Both carry the identifier, so either one's token asserts
  the same Principal. The kept user is enabled by `:restore`, after the release.
- **Delete both users.** The Principal outlives its kernel user. Deleting both leaves a quarantined
  mapping with nothing to recover from.
- **Edit `principal_mapping` to set the state back to `active`.** Quarantine is the reconciler's
  hold, left by `:release` once the kernel shows the duplicate gone, and only to `suspended`
  (§Leaving Quarantine).
- **Suspend or terminate the sessions through the containment routes and expect them to work.**
  `:suspend`, `:restore` and `sessions:terminate-all` accept only an `active` or `suspended`
  Principal, and refuse a quarantined one with `409` (`TDD-identity-control-005` §State).

## Gaps

- **Fixed in `TDD-identity-control-001` 1.18.0: `:release` leaves `quarantined`,** to `suspended`, once
  exactly one kernel user carries the identifier (step 8).
- **A quarantined mapping whose users were all deleted stays quarantined.** `:release` refuses zero
  users, and a human `:retire` is not built (`TDD-identity-control-001` §API / Interface).
- **No route ends a quarantined Principal's sessions before the release.** `sessions:terminate-all`
  refuses it, and neither the sweep nor recovery ends sessions: they only disable the users. Whether
  a disabled user's open session can still refresh is not asserted by any test in this repository.
  The release ends the kept user's sessions, and deleting the extra user removes its own; until
  then a realm administrator can end them in the kernel, and this service records nothing.
- **Recovery's duplicate writes no finding.** It is visible only in the log and in the mapping's
  `quarantine_reason`. `GET /v1/principals:unmapped` may not list it.
- **Fixed in `TDD-identity-control-001` 1.18.0: `GET /v1/principals:quarantined`** lists the held
  mappings, and `identity.principal.quarantined` counts them.

## References

- `TDD-identity-control-001` §Data Model, §Idempotency and Crash Recovery, §Reconciliation Sweep,
  §Operational Notes.
- `TDD-identity-control-005` §State, §Refusal order.
- NIST SP 800-61 Rev. 3, Table 2, RS.MI-01
  (<https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf>, accessed
  2026-10-07): "Incidents are contained". The note says: "Containment refers to preventing the
  expansion of an incident. Containment can prevent additional damage and avoid overwhelming the
  organization's resources." The same entry, R1: "Allow incident handlers to manually select and
  perform containment actions instead of or in addition to automated containment measures." That is
  why step 7 remains a person's decision after the automatic disable.
- NIST SP 800-61 Rev. 3, Table 2, RS.AN-07, same source: "Incident data and metadata are
  collected, and their integrity and provenance are preserved". This is why step 3 reads first and
  the users are disabled, not deleted.
- NIST SP 800-53 Rev. 5, IR-4 Incident Handling, from the OSCAL catalog
  (<https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json>,
  accessed 2026-10-07): "Implement an incident handling capability for incidents that is consistent
  with the incident response plan and includes preparation, detection and analysis, containment,
  eradication, and recovery".
