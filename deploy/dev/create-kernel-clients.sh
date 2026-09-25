#!/usr/bin/env bash
# Registers identity-control's two clients in the development kernel, and prints their secrets once
# as .env lines. Run on the server after the kernel stack is up and its realm applied.
#
#   identity-control         the service's Admin API client. A service account holding
#                            realm-management manage-users and view-users: create, read, search,
#                            write attributes, disable. No client management, no realm
#                            administration, no credential read -- TDD-identity-control-001.
#
#   identity-control-caller  development only: how a person obtains a provider-scope token to call
#                            the API. Authorization Code with PKCE S256 and no password grant
#                            (STD-IAM-001 §3.2), the kernel's scnehaux-provider scope attached
#                            (STD-IAM-002 §3.2.1), identity-control named in aud, and a 240-second
#                            access token because provider-scope is lifetime class L0 (§3.3).
#
# The realm itself -- scopes, attributes, keys -- is identity-kernel's, applied by its realm-apply.
# Nothing here changes it; this script only registers clients against it.
set -euo pipefail
cd "$(dirname "$0")"

set -a
# shellcheck disable=SC1091
. ./.env
set +a

container="${KERNEL_KEYCLOAK_CONTAINER:-scnehaux-identity-dev-keycloak-1}"
realm=scnehaux
random() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

kc() {
	docker exec -i "$container" /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm-identity-control.config
}

kc config credentials --server http://localhost:8080 --realm master \
	--user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null

client_uuid() {
	kc get clients -r "$realm" -q "clientId=$1" --fields id --format csv --noquotes | head -n 1
}

for existing in identity-control identity-control-caller; do
	if [ -n "$(client_uuid "$existing")" ]; then
		echo "create-kernel-clients: $existing already exists in realm $realm; nothing created." >&2
		echo "Its secret cannot be read back here. Regenerate it in the Admin Console, or delete both" >&2
		echo "clients and rerun." >&2
		exit 1
	fi
done

scope="$(kc get client-scopes -r "$realm" --fields id,name --format csv --noquotes | grep ',scnehaux-provider$' | cut -d, -f1 || true)"
if [ -z "$scope" ]; then
	echo "create-kernel-clients: realm $realm has no scnehaux-provider scope. Apply identity-kernel's realm" >&2
	echo "definition first (realm-apply), which declares it." >&2
	exit 1
fi

service_secret="$(random)"
kc create clients -r "$realm" \
	-s clientId=identity-control -s enabled=true -s publicClient=false \
	-s serviceAccountsEnabled=true -s standardFlowEnabled=false \
	-s directAccessGrantsEnabled=false -s implicitFlowEnabled=false \
	-s "secret=$service_secret" >/dev/null
kc add-roles -r "$realm" --uusername service-account-identity-control \
	--cclientid realm-management --rolename manage-users --rolename view-users

caller_secret="$(random)"
caller="$(kc create clients -r "$realm" -i \
	-s clientId=identity-control-caller -s enabled=true -s publicClient=false \
	-s serviceAccountsEnabled=false -s standardFlowEnabled=true \
	-s directAccessGrantsEnabled=false -s implicitFlowEnabled=false \
	-s 'redirectUris=["http://127.0.0.1:8099/callback"]' \
	-s 'attributes."pkce.code.challenge.method"=S256' \
	-s 'attributes."access.token.signed.response.alg"=PS256' \
	-s 'attributes."access.token.lifespan"=240' \
	-s "secret=$caller_secret")"
# Which API a token is for belongs to the client relationship, not to the claim profile: the
# audience sits on the caller, so the provider scope does not make every provider token valid at
# every API.
kc create "clients/$caller/protocol-mappers/models" -r "$realm" \
	-s name=identity-control-audience -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
	-s 'config."included.client.audience"=identity-control' \
	-s 'config."access.token.claim"=true' -s 'config."id.token.claim"=false' \
	-s 'config."introspection.token.claim"=true' >/dev/null
kc update "clients/$caller/default-client-scopes/$scope" -r "$realm"

echo "IDENTITY_KEYCLOAK_CLIENT_SECRET=$service_secret"
echo "IDENTITY_CALLER_SECRET=$caller_secret"
