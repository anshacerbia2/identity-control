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

`TDD-identity-control-001` §Operational Notes classes a duplicate as **critical**.

## Authority

A provider, with a token at `aal2`. No step here changes anything: containment is already done by
the service.

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
   decision. The remedy is not built: see Gaps.

## Verification

- `GET /v1/principals/{principal_id}` answers `state: quarantined`.
- Both users stay disabled. A later sweep logs nothing new for them while the finding is open
  (`act` in `sweep.go` logs only a new finding or a new quarantine).
- The finding resolves as `user_absent` only after the extra user is deleted in the kernel and a
  complete sweep no longer returns it.

## Never do

- **Re-enable either user.** Both carry the identifier, so either one's token asserts the same
  Principal.
- **Delete both users.** The Principal outlives its kernel user. Deleting both leaves a quarantined
  mapping with nothing to recover from.
- **Edit `principal_mapping` to set the state back to `active`.** Quarantine is the reconciler's
  hold. "No administrator sets it, and only a relink or a retirement leaves it" (§Data Model).
  Neither is available for it today.
- **Suspend or terminate the sessions through the containment routes and expect them to work.**
  `:suspend`, `:restore` and `sessions:terminate-all` accept only an `active` or `suspended`
  Principal, and refuse a quarantined one with `409` (`TDD-identity-control-005` §State).

## Gaps

- **No route leaves `quarantined`.** `:relink` refuses any mapping that is not `active`
  (`internal/identity/provisioning/relink.go`). A human `:retire` is not built
  (`TDD-identity-control-001` §API / Interface). A quarantined Principal therefore stays
  quarantined until one of them is designed and built.
- **No route ends a quarantined Principal's sessions.** `sessions:terminate-all` refuses it. Neither
  the sweep nor recovery ends sessions: they only disable the users. Whether a disabled user's open
  session can still refresh is not asserted by any test in this repository. A realm administrator
  can end the sessions in the kernel; this service records nothing when they do.
- **Recovery's duplicate writes no finding.** It is visible only in the log and in the mapping's
  `quarantine_reason`. `GET /v1/principals:unmapped` may not list it.
- **No listing of quarantined mappings.** An operator finds one only through a log line or
  `GET /v1/principals:search`.

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
