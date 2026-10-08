# Identity Control Runbooks

The production gate (`ROADMAP.md` §Gates) asks for these runbooks before production. Each one
starts from a signal this service already emits, uses only routes it already serves, and says
where an operator would need something that is not built.

| Runbook | Starts from | Design |
| :-- | :-- | :-- |
| [Unmapped-Principal triage](unmapped-principal-triage.md) | an `unmapped` or `orphan` finding | `TDD-identity-control-001` §Reconciliation Sweep |
| [Duplicate-identifier containment](duplicate-identifier-containment.md) | a `duplicate` finding, or a duplicate found by pending recovery | `TDD-identity-control-001` §Idempotency and Crash Recovery, §Reconciliation Sweep |
| [Pending-mapping recovery](pending-mapping-recovery.md) | a mapping left `pending`, or a `dangling` finding | `TDD-identity-control-001` §Idempotency and Crash Recovery, §Data Model (`relink`) |
| [Projection drift repair](projection-drift-repair.md) | a projection finding, an `unresolved` Tenant, or a revocation not converged in budget | `TDD-identity-control-002` §Operational Notes, §Reconciliation |
| [Control Database restore](control-database-restore.md) | a lost or damaged Control Database | `TDD-identity-control-001` §Restore Evidence, `deploy/dev/README.md` §Backups |

## What every runbook assumes

- **A provider calls the API.** Every route below is `providerOnly`: provider authority and a token
  at `aal2` (`internal/httpapi/ownership.go`, `TDD-identity-control-005` §Step-Up). A command also
  needs `auth_time` within `IDENTITY_STEP_UP_MAX_AGE` (5 minutes by default). In development,
  `deploy/dev/README.md` §Calling the API shows how a provider token is obtained.
- **Nothing is edited by hand.** Each runbook names the route that makes a change. Where no route
  exists, the runbook says so and stops. A row changed by hand has no actor, no reason and no
  record. The insert-only tables (`principal_relink`, the findings) exist so that a change carries
  all three.
- **No secret goes into a ticket.** Logs and API answers carry `principal_id` and `username`. They
  never carry `keycloak_user_id` (`TDD-identity-control-001` §Operational Notes). Keep it that way
  in tickets and chat.

## Why they are written down

Google's SRE book: "thinking through and recording the best practices ahead of time in a
'playbook' produces roughly a 3x improvement in MTTR as compared to the strategy of 'winging it.'"
([Site Reliability Engineering, Introduction](https://sre.google/sre-book/introduction/), accessed
2026-10-07).
