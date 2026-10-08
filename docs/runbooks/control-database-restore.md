# Control Database Restore

## Purpose

The Control Database is the only record of which `principal_id` belongs to which kernel user, and of
every registration, ownership and security record. Nothing outside it can rebuild a `principal_id`
(`deploy/dev/README.md` §Backups). This runbook restores it from the daily backup when its volume or
its data is lost, and says what a restore to an older point does to the kernel, which kept changing
after the backup.

`deploy-dev` proves the procedure on every change and weekly (`scripts/dev-restore-drill.sh`,
`STD-GLB-002` §Restore Evidence). The drill restores to the instant of its own backup. A real
restore is older than the last change, and §After a restore to an older point is what the drill
does not cover.

## Signals

- `/readyz` fails and `docker compose logs postgres` shows the database will not start, or reports
  corrupted data.
- The volume `scnehaux-identity-control-dev_postgres` is gone, or `docker compose down -v` was run.
- The migrate job fails on a database it accepted before, and the cause is the data, not a release.

## Authority

- The operator of the server, with the backup storage, `.env` and `keys/`.
- A provider, with a token at `aal2`, for §After a restore to an older point.

## Steps

1. **Stop the service.** `docker compose stop identity-control`. A service writing to a damaged
   database makes the later comparison harder, and nothing it writes will survive the restore.
2. **Keep what is left.** If the volume still exists, copy it before deleting anything:
   `docker run --rm -v scnehaux-identity-control-dev_postgres:/data -v "$PWD":/out alpine tar -C /data -czf /out/damaged-volume.tgz .`.
   A restore replaces it, and an investigation may need it.
3. **Choose the backup.** The newest `globals-<date>.sql` and `identity_control-<date>.dump` pair
   from the same date. Note the date: every change after it is lost (§After a restore to an older
   point).
4. **Put `.env` and `keys/` back** from the same backup. The migrate job sets `identity_app`'s
   password from `.env`, and the service signs with the keys in `keys/`.
5. **Delete the damaged database.** `docker compose down -v`, deliberately, now that step 2 has kept
   a copy. `restore.sh` refuses a cluster that still holds `identity_control`.
6. **Restore.** From `deploy/dev`:
   `./restore.sh <backup>/globals-<date>.sql <backup>/identity_control-<date>.dump`. It applies the
   roles, then the database with `pg_restore --create --exit-on-error`, and stops at the first error.
7. **Before starting the service on a backup older than the last change,** set
   `IDENTITY_UNMAPPED_USERS=report` and `IDENTITY_UNMANAGED_CLIENTS=report` in `.env`. Their first
   sweep runs at startup, and in `disable` it would disable every kernel user and client created
   after the backup (§After a restore to an older point).
8. **Start.** `docker compose up -d --build`. The migrate job finds the schema at its revision,
   applies anything newer, and re-asserts every privilege; `docker compose logs migrate` ends with
   `control database ready`. Then `curl -fsS http://127.0.0.1:8082/readyz`.

## After a restore to an older point

The kernel kept every change made after the backup, and the restored database knows none of them.
The service then treats the difference as drift, and repairs the kernel toward the older state.

| Made after the backup | What the restored service sees | What to do |
| :-- | :-- | :-- |
| A Principal created | An `orphan` kernel user: it carries a `principal_id` no mapping holds | In `report`, it is only recorded. [Unmapped-Principal triage](unmapped-principal-triage.md) |
| A client registered | An `unmanaged` client | In `report`, it is only recorded. Register it again from its request record, or adopt it |
| A registration changed | Drift from the restored registration (`TDD-identity-control-003` §Drift Reconciliation) | A `redirect_uris` difference disables the client, `blocked`. Another class is repaired to the restored value when an admin event attributes it, and recorded `unattributed` otherwise. Repeat each change through the API; the kernel's admin events after the backup list them |
| A Membership or Tenant event applied | Nothing: Organization Control does not deliver an acknowledged event again | At once, [projection drift repair](projection-drift-repair.md) §The desired state against the authority |
| A security command, such as a suspension | Nothing: the record is gone, and the kernel keeps the effect | Repeat the command, so the record exists again |

Then return `IDENTITY_UNMAPPED_USERS` and `IDENTITY_UNMANAGED_CLIENTS` to `disable`, and
`docker compose up -d identity-control`.

## Verification

- `docker compose logs migrate` ends with `control database ready`: the privilege shape holds on the
  restored database.
- `GET /v1/registrations` lists the registrations the backup held.
- `GET /v1/principals:unmapped` and the orphan findings hold only users that step 7's table
  accounts for.
- `GET /v1/projections/tenant-context/report` matches Organization Control after the
  reconciliation.

## Never do

- **Restore over the running database.** `restore.sh` refuses it. Delete the volume deliberately,
  after step 2.
- **Start a restored service in `disable` before triage.** It disables every Principal and client
  created after the backup.
- **Edit rows to put back what the backup lost.** Each change goes through its route, so it has an
  actor, a reason and a record (§What every runbook assumes).
- **Keep a backup readable by others.** Both files hold role password hashes.

## Gaps

- **The RPO is 24 hours, not 1 minute.** The backup is a daily `pg_dump`. `PAD-PLT-001 §6.2` targets
  1 minute, which needs continuous WAL archiving with point-in-time recovery on the production
  platform (`STD-GLB-002` §Restore Evidence). Until it does, a restore loses up to a day.
- **No switch holds the registration sweep or the Tenant context converger.** The first sweep runs
  at startup and blocks or repairs registrations toward the restored values, and the converger can act on a
  restored Membership that Organization Control has since revoked, until the reconciliation in
  §After a restore to an older point lands. A restore older than the last change has that window.
- **Only the procedure is timed.** The drill measures it on CI data, not on a production-sized
  database.
- **The drill does not cover `.env` and `keys/`.** It deletes the volume only.

## References

- `TDD-identity-control-001` §Restore Evidence; `STD-GLB-002` §Restore Evidence; `STD-GLB-009`
  rule 9.
- PostgreSQL 17, _pg_restore_ (<https://www.postgresql.org/docs/17/app-pgrestore.html>, accessed
  2026-10-08): `--exit-on-error`: "Exit if an error is encountered while sending SQL commands to the
  database. The default is to continue and to display a count of errors at the end of the
  restoration." This is why step 6 stops at the first error.
- PostgreSQL 17, _pg_dumpall_ (<https://www.postgresql.org/docs/17/app-pg-dumpall.html>, accessed
  2026-10-08): the bootstrap superuser's "role already exists" error "is harmless and should be
  ignored". It is the only error `restore.sh` allows in the roles file.
- NIST SP 800-53 Rev. 5, CP-10, from the OSCAL catalog
  (<https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json>,
  accessed 2026-10-08): "Provide for the recovery and reconstitution of the system to a known state
  within [Assignment] after a disruption, compromise, or failure." §After a restore to an older point
  is what makes the known state the current one.
