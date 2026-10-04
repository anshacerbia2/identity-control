#!/usr/bin/env bash
# Grants identity-control's existing Admin API client the two roles TDD-identity-control-002 2.0.0
# adds, manage-organizations and view-organizations, on a server whose client was registered before
# them. create-kernel-clients.sh grants them to a new client, and is never rerun for an existing one.
#
# Idempotent: granting a role the service account already holds changes nothing. It adds nothing
# else, and prints the roles the service account then holds.
set -euo pipefail
cd "$(dirname "$0")"

set -a
# shellcheck disable=SC1091
. ./.env
set +a

container="${KERNEL_KEYCLOAK_CONTAINER:-scnehaux-identity-dev-keycloak-1}"
realm=scnehaux

kc() {
	docker exec -i "$container" /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm-identity-control.config
}

kc config credentials --server http://localhost:8080 --realm master \
	--user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null

kc add-roles -r "$realm" --uusername service-account-identity-control \
	--cclientid realm-management --rolename manage-organizations --rolename view-organizations
kc get-roles -r "$realm" --uusername service-account-identity-control --cclientid realm-management \
	--fields name --format csv --noquotes
