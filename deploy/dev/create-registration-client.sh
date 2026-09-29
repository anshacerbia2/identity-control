#!/usr/bin/env bash
# Registers identity-control-registration in the development kernel. It authenticates with its own
# key by signed JWT and holds no client secret (ADR-IAM-001 §5.12). Run once, on the server, by
# whoever operates it.
#
#   identity-control-registration  the registration path's own Admin API client
#                                  (TDD-identity-control-003 §Security Notes). A service account
#                                  holding realm-management manage-clients, view-clients and
#                                  view-events: register and reconcile clients, and read the admin
#                                  events that attribute a console change. No user management, so
#                                  one leaked key cannot both mint a Principal and register a
#                                  client that redirects its tokens.
#
# It creates this one client and its key, ./keys/identity-control-registration.pem, owned by
# KEYS_OWNER. create-kernel-clients.sh is not rerun for it: that script refuses once its clients
# exist, and the dev server's clients already do. This script refuses the same way. To rotate the
# key, use the kernel's set-client-key.sh (deploy/dev/README.md).
set -euo pipefail
cd "$(dirname "$0")"

set -a
# shellcheck disable=SC1091
. ./.env
set +a

kernel="${KERNEL_DEPLOY_DIR:?set KERNEL_DEPLOY_DIR in .env to the kernel checkout's deploy/dev}"
container="${KERNEL_KEYCLOAK_CONTAINER:-scnehaux-identity-dev-keycloak-1}"
owner="${KEYS_OWNER:-65532:65532}"
realm=scnehaux
client=identity-control-registration
keys="$PWD/keys"

kc() {
	docker exec -i "$container" /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm-identity-control-registration.config
}

kc config credentials --server http://localhost:8080 --realm master \
	--user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null

if [ -n "$(kc get clients -r "$realm" -q "clientId=$client" --fields id --format csv --noquotes | head -n 1)" ]; then
	echo "create-registration-client: $client already exists in realm $realm; nothing created." >&2
	echo "To give it a key, or rotate its key, use $kernel/set-client-key.sh (deploy/dev/README.md)." >&2
	exit 1
fi

mkdir -p "$keys"
"$kernel/new-client-key.sh" "$client" "$keys" "$owner" >&2

kc create clients -r "$realm" \
	-s clientId="$client" -s enabled=true -s publicClient=false \
	-s clientAuthenticatorType=client-jwt \
	-s serviceAccountsEnabled=true -s standardFlowEnabled=false \
	-s directAccessGrantsEnabled=false -s implicitFlowEnabled=false >/dev/null
kc add-roles -r "$realm" --uusername "service-account-$client" \
	--cclientid realm-management --rolename manage-clients --rolename view-clients --rolename view-events

"$kernel/set-client-key.sh" "$realm" "$client" "$keys/$client.jwk.json" >&2
