#!/usr/bin/env bash
# Registers identity-control-registration in the development kernel, and prints its secret once as
# an .env line. Run once, on the server, by whoever operates it.
#
#   identity-control-registration  the registration path's own Admin API client
#                                  (TDD-identity-control-003 §Security Notes). A service account
#                                  holding realm-management manage-clients, view-clients and
#                                  view-events: register and reconcile clients, and read the admin
#                                  events that attribute a console change. No user management, so
#                                  one leaked secret cannot both mint a Principal and register a
#                                  client that redirects its tokens.
#
# It creates this one client and nothing else. create-kernel-clients.sh is not rerun for it: that
# script refuses once its clients exist, and the dev server's clients already do. This script
# refuses the same way, because a secret cannot be read back and a second run would have to replace
# the one the service holds.
set -euo pipefail
cd "$(dirname "$0")"

set -a
# shellcheck disable=SC1091
. ./.env
set +a

container="${KERNEL_KEYCLOAK_CONTAINER:-scnehaux-identity-dev-keycloak-1}"
realm=scnehaux
client=identity-control-registration
random() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

kc() {
	docker exec -i "$container" /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm-identity-control-registration.config
}

kc config credentials --server http://localhost:8080 --realm master \
	--user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null

if [ -n "$(kc get clients -r "$realm" -q "clientId=$client" --fields id --format csv --noquotes | head -n 1)" ]; then
	echo "create-registration-client: $client already exists in realm $realm; nothing created." >&2
	echo "Its secret cannot be read back here. Regenerate it in the Admin Console if it was lost." >&2
	exit 1
fi

secret="$(random)"
kc create clients -r "$realm" \
	-s clientId="$client" -s enabled=true -s publicClient=false \
	-s serviceAccountsEnabled=true -s standardFlowEnabled=false \
	-s directAccessGrantsEnabled=false -s implicitFlowEnabled=false \
	-s "secret=$secret" >/dev/null
kc add-roles -r "$realm" --uusername "service-account-$client" \
	--cclientid realm-management --rolename manage-clients --rolename view-clients --rolename view-events

echo "IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_SECRET=$secret"
