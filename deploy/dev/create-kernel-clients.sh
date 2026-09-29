#!/usr/bin/env bash
# Registers identity-control's two clients in the development kernel. Each authenticates with its
# own key by signed JWT, and neither holds a client secret (ADR-IAM-001 §5.12, STD-IAM-001 §3.2).
# Run on the server after the kernel stack is up and its realm applied.
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
# The keys are made in ./keys by the kernel's new-client-key.sh, and the public halves installed by
# its set-client-key.sh. The kernel checkout is KERNEL_DEPLOY_DIR in .env.
#   identity-control.pem         belongs to KEYS_OWNER, the service container's user.
#   identity-control-caller.pem  belongs to whoever runs this script, because dev-token.ps1 signs
#                                with it on this host.
# stdout carries only the .env line naming the caller's key, so the output can be appended to .env.
#
# The realm itself -- scopes, attributes, keys -- is identity-kernel's, applied by its realm-apply.
# Nothing here changes it; this script only registers clients against it.
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
keys="$PWD/keys"

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
		echo "To give it a key, or rotate its key, use $kernel/set-client-key.sh (deploy/dev/README.md)." >&2
		exit 1
	fi
done

scope="$(kc get client-scopes -r "$realm" --fields id,name --format csv --noquotes | grep ',scnehaux-provider$' | cut -d, -f1 || true)"
if [ -z "$scope" ]; then
	echo "create-kernel-clients: realm $realm has no scnehaux-provider scope. Apply identity-kernel's realm" >&2
	echo "definition first (realm-apply), which declares it." >&2
	exit 1
fi

# The keys first, so a failure leaves no client without one.
mkdir -p "$keys"
"$kernel/new-client-key.sh" identity-control "$keys" "$owner" >&2
"$kernel/new-client-key.sh" identity-control-caller "$keys" "$(id -u):$(id -g)" >&2

kc create clients -r "$realm" \
	-s clientId=identity-control -s enabled=true -s publicClient=false \
	-s clientAuthenticatorType=client-jwt \
	-s serviceAccountsEnabled=true -s standardFlowEnabled=false \
	-s directAccessGrantsEnabled=false -s implicitFlowEnabled=false >/dev/null
kc add-roles -r "$realm" --uusername service-account-identity-control \
	--cclientid realm-management --rolename manage-users --rolename view-users

caller="$(kc create clients -r "$realm" -i \
	-s clientId=identity-control-caller -s enabled=true -s publicClient=false \
	-s clientAuthenticatorType=client-jwt \
	-s serviceAccountsEnabled=false -s standardFlowEnabled=true \
	-s directAccessGrantsEnabled=false -s implicitFlowEnabled=false \
	-s 'redirectUris=["http://127.0.0.1:8099/callback"]' \
	-s 'attributes."pkce.code.challenge.method"=S256' \
	-s 'attributes."access.token.signed.response.alg"=PS256' \
	-s 'attributes."access.token.lifespan"=240')"
# Which API a token is for belongs to the client relationship, not to the claim profile: the
# audience sits on the caller, so the provider scope does not make every provider token valid at
# every API.
kc create "clients/$caller/protocol-mappers/models" -r "$realm" \
	-s name=identity-control-audience -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
	-s 'config."included.client.audience"=identity-control' \
	-s 'config."access.token.claim"=true' -s 'config."id.token.claim"=false' \
	-s 'config."introspection.token.claim"=true' >/dev/null
kc update "clients/$caller/default-client-scopes/$scope" -r "$realm"

# Installing the keys also regenerates, unprinted, the secret Keycloak gave each new client.
"$kernel/set-client-key.sh" "$realm" identity-control "$keys/identity-control.jwk.json" >&2
"$kernel/set-client-key.sh" "$realm" identity-control-caller "$keys/identity-control-caller.jwk.json" >&2

echo "IDENTITY_CALLER_KEY_FILE=$keys/identity-control-caller.pem"
