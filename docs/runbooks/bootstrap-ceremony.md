# Bootstrap Ceremony

## Purpose

A fresh Control Database has no Principal, and `POST /v1/principals` requires a caller holding one.
The bootstrap ceremony is the single entry point: `cmd/identity-bootstrap` creates the realm's first
Principal, registers this service's own protected resource, and records who did it and why
(`ADR-IAM-001 §5.11`, `TDD-identity-control-001` §The Bootstrap Ceremony). It runs once per Control
Database. This runbook is how it is performed, resumed, and checked, written from the code.

It is not a break-glass procedure. Once it has succeeded, every later Principal comes through the
API, and a second ceremony is refused by the database.

## Who performs it, and where the record is reviewed

> **OWNER DECISION REQUIRED.** The production gate (`ROADMAP.md` §Gates) asks for a runbook "naming
> who is authorized to perform it and where the record is reviewed, since the evidence is worthless if
> nobody reads it". The code records an operator and a reason; it does not decide who may be the
> operator or who reads the record. Until the owner decides, these are placeholders:
>
> - **Authorized operator:** _[to be decided: the role or named people allowed to run the ceremony
>   for a production realm, and whether a second person must witness it]_.
> - **Where the record is reviewed, by whom, and when:** _[to be decided: the review forum or ticket
>   system, the reviewer role, and the deadline after the ceremony]_.
> - **Where the printed output is kept:** _[to be decided]_.
>
> NIST SP 800-53 Rev. 5 AU-6 asks an organization to "Review and analyze system audit records
> [Assignment: organization-defined frequency]" and "Report findings to [Assignment:
> organization-defined personnel or roles]" (§References). The assignments are the decision.

In development (`deploy/dev`), the operator is whoever stands the server up, and the record is the
job log or the server's shell history; that is not evidence for production.

## What the ceremony does

In this order (`cmd/identity-bootstrap/main.go`, `internal/identity/provisioning/ceremony.go`):

1. **Refuses a database that has a ceremony on record**, before touching the kernel, and prints the
   recorded operator and reason. Only `-resume` with that exact operator continues.
2. **Claims the ceremony row** in `identity.bootstrap_ceremony`: `id = 1` (the only value the primary
   key and `CHECK (id = 1)` admit), the operator, the reason, the idempotency key it will create the
   Principal under, and the `principal_id` it mints. The same transaction asserts
   `identity.principal_mapping` is empty. The row is insert-only for the runtime role (`grants.sql`).
3. **Creates the first Principal through the ordinary creation path**, `Provisioner.Create`, under
   the scope `ceremony:bootstrap`, which no API caller's scope can equal. The kernel user is created
   owing a credential-setting action: the ceremony never holds a password.
4. **Registers `identity-control-api`**, the name in `IDENTITY_TOKEN_AUDIENCE`: a keyless `resource`,
   `privileged`, lifetime class `L0`, registered by the first Principal, through the registration
   path's own Admin API client, under the key `bootstrap-resource:<realm>` (`ADR-IAM-001 §5.11` rule 5).
5. **Prints** the `principal_id`, username, realm, operator and resource, and logs `bootstrap ceremony
   complete` with `principal_id`, `realm` and `operator`.

**The first Principal is the first provider.** The ceremony's row is a local emergency grant,
honored until Organization's first emergency `provider:identity-control` grant is projected. That
projection retires it by an insert-only `identity.ceremony_grant_retirement` row, in the same
transaction (`TDD-identity-control-006` §The Ceremony's Grant).

## Preconditions

- **The kernel realm is applied** (identity-kernel's `realm-apply`), with the declared user profile
  and `scnehaux-provider`.
- **This service's two Admin API clients exist with their keys**: `identity-control` and
  `identity-control-registration` (`deploy/dev/create-kernel-clients.sh`,
  `deploy/dev/create-registration-client.sh`). The ceremony reads both keys.
- **The Control Database is migrated**: the migrate job has printed `control database ready`.
- **The ceremony's environment** (`config.LoadBootstrap`): `IDENTITY_DATABASE_URL` (the runtime
  role), `IDENTITY_KEYCLOAK_BASE_URL`, `IDENTITY_KEYCLOAK_REALM`, `IDENTITY_KEYCLOAK_CLIENT_ID`,
  `IDENTITY_KEYCLOAK_CLIENT_KEY_FILE`, `IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID`,
  `IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE`, `IDENTITY_TOKEN_AUDIENCE` (default
  `identity-control-api`), `IDENTITY_PROVISION_TIMEOUT`, `IDENTITY_PENDING_RECOVERY_AFTER`.
- **The operator has decided the first Principal's username and email**, and has a reason to state.
  Both are recorded and cannot be changed afterwards.

## Steps

1. **Run the ceremony once**, as the authorized operator, naming yourself, not a service account:

   ```sh
   identity-bootstrap -operator '<your name or email>' -reason '<why: e.g. production realm stand-up, change ticket>' \
     -username '<first Principal username>' -email '<first Principal email>'
   ```

   On `deploy/dev` this is `docker compose run --rm bootstrap …` with the same flags. `bootstrap.sh`
   runs it and then, **for development only**, sets the Principal's password; never use its second
   step on a realm that matters. The whole ceremony is bounded by `-timeout` (2 minutes).
2. **Keep the printed output** where the owner decided (§Who performs it). It is the only place the
   `principal_id` is printed for a person to copy.
3. **If it failed after the Principal was created**, it says so and names the resource registration
   that failed: "the first Principal exists; registering identity-control-api failed, so resume the
   ceremony". Resume with the recorded operator, the same username and email, and `-resume`:

   ```sh
   identity-bootstrap -operator '<recorded operator>' -reason '<any>' -username '<same>' -email '<same>' \
     -resume '<recorded operator>'
   ```

   A resume replays the recorded idempotency key, so it returns the same Principal and registers the
   resource once. The recorded reason is kept; the one passed on a resume is not recorded.
4. **Complete the first Principal's credential** through the kernel's own required action: the first
   sign-in asks the person to set a password. Provider routes then need `aal2`, so the person enrolls
   a TOTP at the first provider sign-in (ADR-IAM-004).
5. **Stand up the rest from the first Principal**: further Principals through `POST /v1/principals`,
   registrations through `POST /v1/registrations` or adoption (`deploy/dev/README.md` §First start).
6. **Grant the first emergency `provider:identity-control` in Organization Control** once it runs.
   Its projection retires the ceremony's grant. Until then the ceremony's Principal is the only
   provider.

## Refusals and what they mean

| Message | Meaning | What to do |
| :-- | :-- | :-- |
| `the bootstrap ceremony has already been performed`, with the operator and reason | The ceremony ran on this Control Database | Nothing. Resume only to finish an interrupted one, with `-resume` naming that operator |
| `-resume "…" does not match the recorded operator; refusing` | The resume named someone else | Read the record; resume with the operator it names |
| `the Principal registry is not empty; the ceremony creates the first Principal only` | Principals exist with no ceremony on record: an out-of-band insert, or a database restored from another estate | Stop. This is the prohibited path `ADR-IAM-001 §5.11` and `ADR-ORG-001` exist to catch; treat it as an incident |
| `the ceremony row names no principal_id; … Reset this Control Database` | A row claimed before the column existed whose Principal was never created | The row is insert-only and cannot be repaired; stand the database up again from zero |
| `operator is required; the ceremony records a person, not a process` | `-operator` was empty | Name the person |

## Verification

- The output names a `principal_id` and the resource `identity-control-api` with its registration.
- `GET /v1/principals/{principal_id}`, with the first Principal's provider token, answers `active`.
- `GET /v1/registrations` lists `identity-control-api`, `resource`, `privileged`, `L0`.
- A second run without `-resume` is refused, naming the recorded operator and reason. `deploy-dev`
  proves this on every change ("the ceremony succeeds only once").
- The record exists: `SELECT operator, reason, principal_id, requested_at FROM identity.bootstrap_ceremony`
  with a read-only role. No API route serves it yet (§Gaps).

## Never do

- **Run it with a service account or a shared name as `-operator`.** The record exists to name the
  person accountable for the one identifier nobody else authorized.
- **Insert a Principal by hand** to get past a refusal. An identifier that entered the registry
  without a recorded decision "is indistinguishable from one an attacker placed there"
  (`ADR-IAM-001 §5.11`).
- **Use `deploy/dev/bootstrap.sh`'s second step outside development.** It gives the Principal a
  password through the kernel's administrator, which is the concentration `ADR-IAM-001 §5.10` forbids.
- **Restore a backup into a fresh estate to skip the ceremony.** The restored record names the old
  operator; the restore runbook applies only to the same estate (`control-database-restore.md`).

## Gaps

- **Who may perform it and where its record is reviewed are not decided** (§Who performs it).
- **No route reads the ceremony record.** It is in `identity.bootstrap_ceremony`, readable by a
  database role, and in the operator's kept output. A provider route serving it, or an event to Audit
  & Evidence, would let the review happen where other evidence is reviewed.
- **The ceremony's grant is not reported as used.** A request on the ceremony's grant is not recorded
  as an emergency use (`TDD-identity-control-006` §Emergency Grant Validation); only its retirement is
  recorded.

## References

- `ADR-IAM-001 §5.11`; `TDD-identity-control-001` §The Bootstrap Ceremony; `TDD-identity-control-006`
  §The Ceremony's Grant; `cmd/identity-bootstrap/main.go`; `internal/identity/provisioning/ceremony.go`.
- NIST SP 800-53 Rev. 5, AU-6 Audit Record Review, Analysis, and Reporting
  (<https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>, as published at
  <https://csf.tools/reference/nist-sp-800-53/r5/au/au-6/>, accessed 2026-10-09): "a. Review and
  analyze system audit records [Assignment: organization-defined frequency] for indications of
  [Assignment: organization-defined inappropriate or unusual activity] and the potential impact of the
  inappropriate or unusual activity; b. Report findings to [Assignment: organization-defined personnel
  or roles]". The ceremony's record is such an audit record, and the assignments are the owner's
  decision above.
