#!/usr/bin/env bash
# The Control Database restore drill (STD-GLB-002 §Restore Evidence, ROADMAP.md §Gates,
# docs/runbooks/control-database-restore.md). deploy-dev runs it last, against the stack every earlier
# step filled:
#
#   1. reads the registrations through the API, then stops the service so nothing writes;
#   2. fingerprints the database: its schema with owners and grants, its migration version, every
#      table's row count and content checksum, every sequence, and the cluster's roles;
#   3. backs it up with deploy/dev/backup.sh, the script README.md §Backups gives the operator's cron;
#   4. deletes the database volume with docker compose down --volumes, the loss a backup is for;
#   5. restores into the new, empty volume with deploy/dev/restore.sh, and fingerprints it again
#      before any migration job runs; a second restore.sh over it must refuse, and two probes show
#      the checks are load-bearing: one row removed in a rolled-back transaction changes the
#      fingerprint, and the same dump restored into a cluster without its roles stops;
#   6. starts the stack with docker compose up -d --build, waits for /readyz, and reads the
#      registrations again;
#   7. writes restore-evidence.json and fails on any difference, or on a recovery slower than the
#      15-minute RTO of PAD-PLT-001 §6.2.
#
# It also drills a restore to a point older than the kernel's (scripts/dev-restore-older-point.ps1,
# docs/runbooks/control-database-restore.md §After a restore to an older point): changes made before
# the backup, more made after it while the service runs again on the old database, the restored
# service started in report mode as the runbook's step 7 says, the runbook's reconciliation carried out
# and checked, and the rollout switches returned afterwards. Its record is older-point-evidence.json.
#
# It deletes the database, so it refuses to run outside CI. The environment is deploy/dev/.env's,
# plus IDENTITY_API_URL, KC_BASE_URL, KC_ADMIN_URL and IDENTITY_OPERATOR_TOTP_FILE for the API reads,
# as the other deploy-dev steps set them, and TENANT_PROOF_STATE, the Tenant proof's state file, whose
# delivering workload stands in for Organization Control.
#
#   bash scripts/dev-restore-drill.sh "$RUNNER_TEMP/restore-drill"
set -euo pipefail

out="${1:?usage: dev-restore-drill.sh <evidence directory>}"
if [ "${CI:-}" != "true" ]; then
	echo "refusing: the drill deletes the database volume, so it runs in CI only" >&2
	exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
deploy="$root/deploy/dev"
database=identity_control
service=identity-control
volume=scnehaux-identity-control-dev_postgres
ready_url="${IDENTITY_API_URL:-http://127.0.0.1:8082}/readyz"
rto_seconds=900
# TDD-identity-control-001 §Restore Evidence: the tables deploy-dev is known to fill. Each must hold
# rows in the source, or the drill would be comparing empty tables.
required=(identity.principal_mapping identity.bootstrap_ceremony identity.client_registration
	identity.client_key identity.tenant_desired identity.membership_desired identity.kernel_event
	identity.privileged_access)

mkdir -p "$out"
out="$(cd "$out" && pwd)"
# Stands in for storage outside the Docker volume. The workflow never uploads it: the files hold role
# password hashes.
backup="$out/backup"

compose() { (cd "$deploy" && docker compose "$@"); }
older="$out/older-point"
mkdir -p "$older"
older_point() { pwsh -NoProfile -File "$root/scripts/dev-restore-older-point.ps1" -Phase "$1" -State "$older/state.json" \
	-TenantState "${TENANT_PROOF_STATE:?TENANT_PROOF_STATE names the state file of the Tenant proof}"; }
wait_ready() {
	for _ in $(seq 1 180); do
		curl -fsS "$ready_url" >/dev/null 2>&1 && return 0
		sleep 1
	done
	return 1
}
# env_value and set_env read and write one deploy/dev/.env setting, as an operator edits the file.
# Compose prefers a variable in its own environment to .env, and the workflow exports .env before the
# drill runs, so set_env changes the exported value too, or compose would keep the old one.
env_value() { sed -n "s/^$1=//p" "$deploy/.env" | tail -n 1; }
set_env() {
	sed -i "/^$1=/d" "$deploy/.env"
	if [ -z "$2" ]; then
		unset "$1"
	else
		echo "$1=$2" >> "$deploy/.env"
		export "$1=$2"
	fi
}
now() { date +%s.%N; }
elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", b - a }'; }

fingerprint() {
	compose exec -T postgres psql -X -v ON_ERROR_STOP=1 -qtA -U postgres -d "$database" \
		< "$root/scripts/restore-fingerprint.sql" | jq -S . > "$out/fingerprint-$1.json"
	compose exec -T postgres pg_dump -U postgres --schema-only --create --restrict-key=drill "$database" \
		> "$out/schema-$1.sql"
}

read_api() { pwsh -NoProfile -File "$root/scripts/dev-restore-read.ps1" -Out "$out/read-$1.json"; }

# same <name> <file a> <file b>: true when equal; otherwise false, with the diff kept beside the evidence.
same() {
	if diff -u "$2" "$3" > "$out/diff-$1.txt"; then
		rm -f "$out/diff-$1.txt"
		echo true
	else
		echo false
	fi
}

section() { jq -S ".$2" "$out/fingerprint-$1.json" > "$out/$2-$1.json"; }

started_at="$(date -u +%FT%TZ)"

echo "0. the older point: changes the backup will hold"
older_point before

echo "1. read the registrations through the API, then stop the service"
read_api before
compose stop "$service"

echo "2. fingerprint the source"
fingerprint source

echo "3. back up with deploy/dev/backup.sh"
t="$(now)"
bash "$deploy/backup.sh" "$backup" > "$out/backup-files.txt"
backup_seconds="$(elapsed "$t" "$(now)")"
globals="$(sed -n 1p "$out/backup-files.txt")"
dump="$(sed -n 2p "$out/backup-files.txt")"
dump_bytes="$(stat -c %s "$dump")"

echo "3b. the older point: the service runs again on the backed-up database, and changes the kernel"
compose start "$service"
wait_ready || { echo "::error::the service did not come back before the older point's changes"; exit 1; }
older_point after-backup
compose stop "$service"

echo "4. lose the database: docker compose down --volumes"
volume_before="$(docker volume inspect -f '{{.CreatedAt}}' "$volume")"
compose down --volumes
if docker volume inspect "$volume" >/dev/null 2>&1; then
	echo "::error::the database volume survived docker compose down --volumes"
	exit 1
fi

echo "5. restore into an empty volume with deploy/dev/restore.sh"
t0="$(now)"
bash "$deploy/restore.sh" "$globals" "$dump"
restore_seconds="$(elapsed "$t0" "$(now)")"
volume_after="$(docker volume inspect -f '{{.CreatedAt}}' "$volume")"
fingerprint restored

# The comparison is load-bearing: one row removed from the probe table, inside a transaction that rolls
# back, must change that table's count and checksum.
probe_table=identity.kernel_event
compose exec -T postgres psql -X -v ON_ERROR_STOP=1 -qtA -U postgres -d "$database" \
	-c "BEGIN" -c "SET LOCAL session_replication_role = replica" \
	-c "DELETE FROM $probe_table WHERE ctid = (SELECT ctid FROM $probe_table LIMIT 1)" \
	-f - -c "ROLLBACK" < "$root/scripts/restore-fingerprint.sql" | jq -S . > "$out/fingerprint-probe.json"
probe_entry() { jq -c --arg t "$probe_table" '.tables[] | select(.table == $t) | [.rows, .checksum]' "$1"; }
one_row_detected=false
if [ "$(probe_entry "$out/fingerprint-probe.json")" != "$(probe_entry "$out/fingerprint-restored.json")" ] &&
	[ "$(jq '.tables' "$out/fingerprint-probe.json")" != "$(jq '.tables' "$out/fingerprint-source.json")" ]; then
	one_row_detected=true
fi
rm -f "$out/fingerprint-probe.json"

# Roles first is load-bearing: the same dump restored into a cluster without them must stop on its
# first owner or grantee.
probe_container="restore-drill-probe-$$"
image="$(docker inspect -f '{{.Config.Image}}' "$(compose ps -q postgres)")"
docker run -d --rm --name "$probe_container" -e POSTGRES_PASSWORD="$(openssl rand -hex 16)" "$image" >/dev/null
for _ in $(seq 1 60); do
	docker exec "$probe_container" pg_isready -q -h 127.0.0.1 -U postgres && break
	sleep 1
done
without_roles_refused=false
if docker exec -i "$probe_container" pg_restore -U postgres -d postgres --create --exit-on-error \
	< "$dump" > "$out/restore-without-roles.txt" 2>&1; then
	echo "::error::the dump restored into a cluster without its roles; the roles-first order tests nothing"
else
	grep -qE 'role "[^"]+" does not exist' "$out/restore-without-roles.txt" && without_roles_refused=true
fi
docker rm -f "$probe_container" >/dev/null

refuses_occupied=false
if bash "$deploy/restore.sh" "$globals" "$dump" > "$out/second-restore.txt" 2>&1; then
	echo "::error::a second restore.sh ran over the restored database; it must refuse"
else
	grep -qF "refusing:" "$out/second-restore.txt" && refuses_occupied=true
fi

echo "6. start the stack on the restored database, in report mode (runbook step 7)"
unmapped_before="$(env_value IDENTITY_UNMAPPED_USERS)"
unmanaged_before="$(env_value IDENTITY_UNMANAGED_CLIENTS)"
set_env IDENTITY_UNMAPPED_USERS report
set_env IDENTITY_UNMANAGED_CLIENTS report
t="$(now)"
compose up -d --build
ready=false
for _ in $(seq 1 180); do
	if curl -fsS "$ready_url" >/dev/null 2>&1; then
		ready=true
		break
	fi
	sleep 1
done
ready_seconds="$(elapsed "$t" "$(now)")"
migrate_ready=false
compose logs --no-color migrate | grep -F "control database ready" >/dev/null && migrate_ready=true
read_ok=false
if [ "$ready" = true ] && read_api after; then
	read_ok=true
fi
recovery_seconds="$(elapsed "$t0" "$(now)")"

echo "6b. the older point: what the restored service sees, and the runbook's reconciliation"
older_point_reconciled=false
if [ "$ready" = true ] && older_point reconcile; then
	older_point_reconciled=true
fi
# The runbook's last step: the rollout switches return to what they were.
set_env IDENTITY_UNMAPPED_USERS "$unmapped_before"
set_env IDENTITY_UNMANAGED_CLIENTS "$unmanaged_before"
compose up -d "$service"
switches_returned=false
wait_ready && switches_returned=true

echo "7. compare"
for side in source restored; do
	for part in migration tables sequences roles; do section "$side" "$part"; done
done
schema_equal="$(same schema "$out/schema-source.sql" "$out/schema-restored.sql")"
migration_equal="$(same migration "$out/migration-source.json" "$out/migration-restored.json")"
tables_equal="$(same tables "$out/tables-source.json" "$out/tables-restored.json")"
sequences_equal="$(same sequences "$out/sequences-source.json" "$out/sequences-restored.json")"
roles_equal="$(same roles "$out/roles-source.json" "$out/roles-restored.json")"
read_equal=false
if [ "$read_ok" = true ]; then
	read_equal="$(same read "$out/read-before.json" "$out/read-after.json")"
fi
volume_new=false
[ "$volume_before" != "$volume_after" ] && volume_new=true

required_json="$(printf '%s\n' "${required[@]}" | jq -R . | jq -s .)"
critical="$(jq --argjson names "$required_json" \
	'[.tables[] | select(.table as $t | $names | index($t)) | {table, rows}]' "$out/fingerprint-source.json")"
critical_filled="$(jq --argjson names "$required_json" \
	'($names | length) == ([.[] | select(.rows > 0)] | length)' <<< "$critical")"
within_rto="$(awk -v s="$recovery_seconds" -v b="$rto_seconds" 'BEGIN { print (s <= b) ? "true" : "false" }')"

jq -n \
	--arg service identity-control --arg database "$database" --arg started_at "$started_at" \
	--arg commit "${GITHUB_SHA:-}" \
	--arg run "${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}" \
	--arg postgres "$(compose exec -T postgres postgres --version)" \
	--argjson backup_seconds "$backup_seconds" --argjson dump_bytes "$dump_bytes" \
	--argjson restore_seconds "$restore_seconds" --argjson ready_seconds "$ready_seconds" \
	--argjson recovery_seconds "$recovery_seconds" --argjson rto_seconds "$rto_seconds" \
	--argjson within_rto "$within_rto" --argjson volume_new "$volume_new" \
	--argjson schema_equal "$schema_equal" --argjson migration_equal "$migration_equal" \
	--argjson tables_equal "$tables_equal" --argjson sequences_equal "$sequences_equal" \
	--argjson roles_equal "$roles_equal" --argjson ready "$ready" --argjson migrate_ready "$migrate_ready" \
	--argjson read_equal "$read_equal" --argjson critical "$critical" --argjson critical_filled "$critical_filled" \
	--argjson refuses_occupied "$refuses_occupied" --argjson one_row_detected "$one_row_detected" \
	--argjson without_roles_refused "$without_roles_refused" --arg probe_table "$probe_table" \
	--argjson older_point_reconciled "$older_point_reconciled" --argjson switches_returned "$switches_returned" \
	--slurpfile older "$( [ -s "$older/older-point-evidence.json" ] && echo "$older/older-point-evidence.json" || echo /dev/null )" \
	--slurpfile source "$out/fingerprint-source.json" \
	'{
	  standard: "STD-GLB-002 §Restore Evidence",
	  service: $service, database: $database, started_at: $started_at, commit: $commit, run: $run,
	  postgres: $postgres,
	  backup: {procedure: "deploy/dev/backup.sh", roles: "pg_dumpall --globals-only",
	           database: "pg_dump --format=custom", seconds: $backup_seconds, dump_bytes: $dump_bytes},
	  loss: {procedure: "docker compose down --volumes", new_volume: $volume_new},
	  restore: {procedure: "deploy/dev/restore.sh", seconds: $restore_seconds,
	            refuses_a_cluster_holding_the_database: $refuses_occupied},
	  integrity: {
	    migration: $source[0].migration,
	    tables: ($source[0].tables | length),
	    rows: ([$source[0].tables[].rows] | add),
	    schema_equal: $schema_equal, migration_equal: $migration_equal, tables_equal: $tables_equal,
	    sequences_equal: $sequences_equal, roles_equal: $roles_equal,
	    critical_tables: $critical, critical_tables_filled: $critical_filled
	  },
	  load_bearing: {one_row_removed_from: $probe_table, detected: $one_row_detected,
	                 restore_without_roles_refused: $without_roles_refused},
	  service_check: {migrate_job_privileges_asserted: $migrate_ready, ready: $ready,
	                  ready_seconds: $ready_seconds, read: "GET /v1/registrations?limit=100",
	                  read_equal: $read_equal},
	  rto: {target_seconds: $rto_seconds, recovery_seconds: $recovery_seconds, within: $within_rto,
	        measured: "from restore.sh on an empty volume to the verified API read"},
	  older_point: {procedure: "docs/runbooks/control-database-restore.md §After a restore to an older point",
	                reconciled: $older_point_reconciled, switches_returned: $switches_returned,
	                cases: ($older[0].cases // [])},
	  rpo: {target_seconds: 60, backup_interval_seconds: 86400, met: false,
	        why: "A daily pg_dump loses up to 24 hours. A 1-minute RPO needs continuous WAL archiving with point-in-time recovery on the production platform; a drill of a logical dump never proves it."}
	}' > "$out/restore-evidence.json"

cat "$out/restore-evidence.json"

checks=(schema_equal migration_equal tables_equal sequences_equal roles_equal critical_filled
	volume_new refuses_occupied one_row_detected without_roles_refused ready migrate_ready read_equal within_rto
	older_point_reconciled switches_returned)
failures=0
for check in "${checks[@]}"; do
	if [ "${!check}" = true ]; then
		echo "  ok    $check"
	else
		echo "  FAIL  $check"
		failures=$((failures + 1))
	fi
done
for diff in "$out"/diff-*.txt; do
	[ -e "$diff" ] || continue
	echo "--- $(basename "$diff")"
	head -n 60 "$diff"
done

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		echo "### Control Database restore drill"
		echo ""
		echo "| Measure | Value |"
		echo "| :-- | :-- |"
		echo "| Tables, rows | $(jq '.integrity.tables' "$out/restore-evidence.json"), $(jq '.integrity.rows' "$out/restore-evidence.json") |"
		echo "| Backup | ${backup_seconds} s, ${dump_bytes} bytes |"
		echo "| Restore into an empty volume | ${restore_seconds} s |"
		echo "| Recovery, to the verified read | ${recovery_seconds} s, against an RTO of ${rto_seconds} s |"
		echo "| Schema, migration, tables, sequences, roles equal | $schema_equal, $migration_equal, $tables_equal, $sequences_equal, $roles_equal |"
		echo "| API read equal | $read_equal |"
		echo "| RPO | not met: a daily dump loses up to 24 h, against 1 min (STD-GLB-002 §Restore Evidence) |"
	} >> "$GITHUB_STEP_SUMMARY"
fi

if [ "$failures" -gt 0 ]; then
	echo "::error::the restore drill failed $failures check(s); see restore-evidence.json"
	exit 1
fi
echo "the Control Database restores"
