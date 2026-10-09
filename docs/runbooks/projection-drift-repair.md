# Projection Drift Repair

## Purpose

The kernel's Organizations and their members are a projection of Organization Control's Tenants
and Memberships (`TDD-identity-control-002`). Drift can sit in two places, and each is repaired
differently (§Reconciliation (2.1.0)):

- **The kernel against the desired state.** The kernel holds a member, an Organization or a state
  the desired state does not. The Tenant context sweep repairs this on its own and records a
  finding.
- **The desired state against the authority.** This service missed or misapplied an event. The
  snapshot adds what was missed. Only Organization Control's reconciliation removes what it no
  longer grants, after an operator posts this service's report.

This runbook also covers the three cases `TDD-identity-control-002` §Operational Notes requires a
runbook for: a revocation not converged within budget, an `unresolved` Tenant, and an extra member
or unknown Organization.

## Signals

| Signal | Where | Severity (§Operational Notes) |
| :-- | :-- | :-- |
| `a sweep found the kernel apart from the desired state`, `WARN`, with `tenant_id` and `findings` | `internal/tenantcontext/converger.go` | an `extra_member` finding is critical |
| `an Organization the authority never created was disabled and emptied`, `ERROR`, with `organization_id` and `members_removed` | `internal/tenantcontext/reconcile.go` | critical |
| `tenant convergence unresolved`, `ERROR`, with `tenant_id`, `attempt`, `priority`, `error_class` | `converger.go` | warning; critical for a priority mark |
| `tenant convergence failed; it will be retried`, `WARN` | `converger.go` | none on its own |
| `identity.tenant_projection.unresolved` gauge above zero, by `priority` | `converger.go` | as above; `priority="true"` is critical |
| `identity.tenant_projection.attempts` with `outcome=unresolved` | `converger.go` | as above |
| `identity.tenant_projection.delivery_to_converged` above 2 s, by `priority` (2.5.0) | `converger.go` | warning; above 4 s critical |
| `identity.tenant_projection.findings` by `finding_class` (2.5.0) | `converger.go`, `reconcile.go` | `extra_member` or `unknown_organization` is critical |
| `the Organization snapshot could not be read; the kernel is swept without it`, `WARN` | `reconcile.go` | the authority half did not run |
| `identity.tenant_projection.sweep_age` above one interval (2.5.0), `tenant context sweep failed`, `ERROR`, or a run recorded `unresolved` | `reconcile.go`, `cmd/identity-control/main.go` | warning at one interval, critical at two |

The finding classes are in `identity.projection_finding`: `missing_member`, `extra_member`,
`organization_state` and `unknown_organization` (§Findings). `GET
/v1/projections/tenant-context:findings?class=<class>` lists them newest first, with the Tenant and the
Principal, and without any kernel user identifier (2.5.0, §Operator Routes).

## Authority

- A provider, with a token at `aal2`, for `GET /v1/projections/tenant-context/report`, the listings
  `:unconverged` and `:findings`, and the sweep on request `POST /v1/projections/tenant-context:sweep`.
- The same, with an `X-Administrative-Reason`, for a re-drive,
  `POST /v1/projections/tenant-context/tenants/{tenant_id}:redrive`. Neither command needs an
  `Idempotency-Key`: both are level-driven sweeps (`keyOptional`, STD-GLB-001 1.4.0).
- A provider of Organization Control for its `POST /v1/projections/reconcile`, which "admits a
  provider, because it reports across consumers" (§Reconciliation (2.1.0)).

## Steps: a sweep's finding

1. **Read the finding** from the alert, or from `GET /v1/projections/tenant-context:findings`,
   filtered by `class`.
   - **`missing_member` or `organization_state`.** The kernel lacked a member, or held an
     Organization in the wrong state. The sweep has already repaired it. Find out why it drifted
     (step 3).
   - **`extra_member`.** Someone was a member of a Tenant the authority never granted them. "Either
     is the shape a privilege-escalation defect takes, and the record is the evidence" (§Findings).
     The member was removed. Open a security incident for the Principal, and read
     `GET /v1/principals/{principal_id}/events` for what it did under that Tenant.
   - **`unknown_organization`.** An Organization whose name is no known `tenant_id`. It was disabled
     and emptied, not deleted. Open a security incident.
2. **Do not undo the repair.** The kernel now matches the desired state. A change made in the
   console is drift, and the next sweep reverts it.
3. **Find who changed the kernel.** Read the kernel's admin events for the Organization. They are
   kept for 7 days. Only this service's Principal credential should hold `manage-organizations`
   (§Keycloak Admin API, Roles).

## Steps: the desired state against the authority

Use this after an incident, after an outage in delivery, or when a Tenant looks wrong and the sweep
reports nothing. The sweep cannot see this kind of drift: the kernel matches a desired state that is
itself wrong.

1. **Read this service's report.** `GET /v1/projections/tenant-context/report` answers
   `{"consumer_id": "identity-control", "mark": ..., "rows": [{"membership_id", "membership_version"}]}`:
   the active Memberships held, at the position applied.
2. **Post it, unchanged, to Organization Control.** `POST /v1/projections/reconcile` on
   Organization Control, with that body (`organization-control/internal/httpapi`, `reconcile`). The
   mark must be the report's own. A report with no position is refused, because comparing it "would
   classify every change made since the report as a divergence" (§The Report an Operator Posts).
3. **Read Organization Control's answer.** It lists the findings, and publishes them as
   `com.scnehaux.organization.projection.repair.reconciled`.
4. **Wait for the repair to arrive.** It is delivered to `POST /v1/deliveries` and applied in one
   transaction (§Applying a Repair):
   - a finding with a state replaces the held one where its `membership_version` is greater;
   - an `extra` finding with no state sets the Membership `absent`;
   - each named Tenant is marked, and the converger makes the kernel match.
   A `missing` or `mismatch` finding with no state makes the whole sweep poison, refused. That is a
   defect in the producer. Report it to Organization Control.
5. **Check the result.** Read the report again. The rows now match the authority.

## Steps: an unresolved Tenant

A Tenant is `unresolved` after `IDENTITY_PROJECTION_MAX_ATTEMPTS` (8) failed attempts, retried with
full-jitter backoff up to 30 seconds (`converger.go`).

1. **List the Tenants.** `GET /v1/projections/tenant-context:unconverged` lists every Tenant `pending`
   or `unresolved`, oldest mark first, with `priority`, `attempts`, `last_error_class`,
   `delivered_at` and `next_attempt_at`.
2. **Read `last_error_class`**, the same as `error_class` in `tenant convergence unresolved`
   (`errorClass` in `converger.go`):
   - **`forbidden`.** The Principal credential lost `manage-organizations`, `view-organizations` or
     `manage-users`. Restore the roles in identity-kernel (`deploy/dev/create-kernel-clients.sh`
     grants them).
   - **`unavailable` or `timeout`.** The kernel or the network. Each call is bounded by
     `IDENTITY_PROJECTION_ATTEMPT_TIMEOUT` (2 seconds).
   - **`read_back`.** The kernel answered, but reading the members back did not show the desired
     state. Something else is changing the Organization. Find it in the admin events.
   - **`ambiguous`.** A call's outcome is unknown, for example an Organization created with no
     identifier in the answer (`keycloak.ErrAmbiguous`, `internal/keycloak/organizations.go`). The
     next attempt finds the Organization by its name before it creates another (§Convergence
     Work). Look for a second Organization with the same name in the kernel.
3. **Fix the cause.** A parked Tenant blocks no other Tenant: "A level-driven loop loses nothing by
   waiting" (§Convergence Work).
4. **Re-drive it.** `POST /v1/projections/tenant-context/tenants/{tenant_id}:redrive` with the reason
   answers `202`: the Tenant is `pending` with its attempts reset, and marked as a sweep marks it, so
   whatever its convergence changes is recorded as a finding. Without a re-drive, the next mark for
   the Tenant or the next sweep does the same; the sweep runs every
   `IDENTITY_PROJECTION_RECONCILE_INTERVAL` (15 minutes), and `POST /v1/projections/tenant-context:sweep`
   runs it now.
5. **For a priority mark, treat the delay as a revocation not enforced.** A suspension or a
   revocation for that Tenant has not reached the kernel. Tell the Tenant's administrators and
   security. Until it converges, the kernel can still issue tokens for the revoked context.

## Steps: a revocation not converged within budget

This service owns a 2-second share of the propagation budget, from delivery to the kernel applied
(§Technical Context). SAD-001 §7.7 sets the propagation budget at 60 seconds as the planning figure,
against an operational target below 10 seconds.

1. **Check that the event arrived.** Ask Organization Control whether its dispatcher delivered the
   event to this consumer and got `202` from `POST /v1/deliveries`. Until this service accepts it,
   the delay is Organization Control's, not this service's.
2. **Check whether the Tenant is pending, retrying or unresolved.** `GET
   /v1/projections/tenant-context:unconverged` says which, with `delivered_at`, the first delivery not
   yet converged, and `attempts`. Then follow the unresolved steps above.
3. **Check the converger is running.** With no `tenant converged` line for any Tenant while marks
   arrive, the converger is stalled. It polls every `IDENTITY_PROJECTION_CONVERGER_INTERVAL` (1
   second) and holds a claim for `IDENTITY_PROJECTION_LEASE` (30 seconds). A replica that died
   mid-claim delays the Tenant by up to the lease.
4. **Record the measured delay** in the incident: `identity.tenant_projection.delivery_to_converged`
   for the period, which measures from the first delivery the convergence closed, or the Tenant's
   `delivered_at` and the time the kernel was found to match.

## Verification

- `tenant converged` for the `tenant_id`, `identity.tenant_projection.unresolved` back to zero, and
  the Tenant no longer listed by `:unconverged`.
- The next sweep, scheduled or `POST /v1/projections/tenant-context:sweep`, records a run whose
  `outcome` is `converged`, and no new `a sweep found the kernel apart from the desired state` for
  that Tenant.
- For a revocation, a new sign-in asking for `organization:<tenant_id>` carries no `tenant_id`, and
  the refresh token issued for it is refused with `invalid_grant` (`scripts/dev-tenant-proof.ps1`
  proves both on every `deploy-dev` run).

## Never do

- **Change an Organization or its members in the console** to fix a Tenant. The sweep reverts it, and
  records it as a finding.
- **Delete an `unknown_organization`.** It was disabled and emptied, and is the evidence.
- **Edit `tenant_desired`, `membership_desired` or `tenant_convergence` by hand.** A desired state
  changes only by an event or a repair, each with its inbox guard and version rule.
- **Post a report you edited.** Its rows and its mark are what make Organization Control's
  comparison sound.

## Gaps

- **Fixed in `TDD-identity-control-002` 2.5.0:** the `:unconverged` and `:findings` listings, the
  re-drive and the sweep on request; the `marked`, `converged`, `findings` and
  `delivery_to_converged` metrics; the Tenant sweep's runs in `identity.reconcile_run`
  (`tenant_context`) with the `sweep_age` gauge. `deploy-dev` reads both listings, re-drives a Tenant
  and sweeps on request (`scripts/dev-tenant-proof.ps1` step 5).
- **No alert rule ships with this service.** The metrics carry the thresholds §Operational Notes
  sets; an alerting platform implements them.

## References

- `TDD-identity-control-002` §Technical Context, §Convergence Work, §Findings, §The Report an Operator
  Posts, §Applying a Repair, §Reconciliation (2.1.0), §Operational Notes, [R1] (Kubernetes controller
  guidance on level-driven loops).
- SAD-001 §7.7 Revocation Classes and Enforcement: the propagation budget.
- NIST SP 800-61 Rev. 3, Table 2, RS.AN-03
  (<https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf>, accessed
  2026-10-07): "Analysis is performed to establish what has taken place during an incident and the
  root cause of the incident". This is step 3 of a sweep's finding: the repair is automatic, and the
  cause is still found.
- NIST SP 800-61 Rev. 3, Table 2, RS.AN-07, same source: "Incident data and metadata are
  collected, and their integrity and provenance are preserved". This is why an unknown Organization
  is disabled and emptied, not deleted.
- NIST SP 800-53 Rev. 5, SI-4 System Monitoring, from the OSCAL catalog
  (<https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json>,
  accessed 2026-10-07): "Analyze detected events and anomalies". A finding the sweep repaired is still
  analyzed.
