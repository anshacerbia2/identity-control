#!/usr/bin/env bash
# Rotates one of this service's Keycloak Admin API credentials: the key identity-control or
# identity-control-registration signs its client assertion with (README.md §Keys, Rotating a key).
#
#   ./rotate-client-key.sh identity-control
#   ./rotate-client-key.sh identity-control-registration
#
# The steps are README.md's, in order, and the service is never without an accepted key:
#   1. make the new pair, keys/CLIENT-next.pem and .jwk.json, owned by KEYS_OWNER;
#   2. install both public keys on the kernel client, the current one and the new one;
#   3. move the new pair over the current file names;
#   4. restart the service, which reads the key at start, and wait for it to be ready;
#   5. install the new public key alone. The previous key stops working here.
# The previous pair is then deleted: a private key that no client accepts is kept by nobody.
#
# deploy-dev rehearses this on every run, against a kernel that lives for the job, and proves each
# credential still reaches the kernel and the previous key is refused (scripts/dev-key-rotation-proof.ps1).
# On a server, run it from this directory, with .env as the service reads it; it prints no key.
set -euo pipefail
cd "$(dirname "$0")"

client="${1:?usage: rotate-client-key.sh identity-control|identity-control-registration}"
case "$client" in
identity-control | identity-control-registration) ;;
*)
	echo "rotate-client-key: $client is not an Admin API credential of this service" >&2
	exit 1
	;;
esac

set -a
# shellcheck disable=SC1091
. ./.env
set +a
kernel="${KERNEL_DEPLOY_DIR:?set KERNEL_DEPLOY_DIR in .env to the deploy/dev directory of the kernel checkout}"
owner="${KEYS_OWNER:-65532:65532}"
realm=scnehaux
keys="$PWD/keys"
next="$client-next"

[ -f "$keys/$client.pem" ] && [ -f "$keys/$client.jwk.json" ] ||
	{ echo "rotate-client-key: $keys/$client.pem or .jwk.json is missing; nothing to rotate" >&2; exit 1; }
if [ -e "$keys/$next.pem" ] || [ -e "$keys/$next.jwk.json" ] || [ -e "$keys/$client-previous.pem" ]; then
	echo "rotate-client-key: a rotation of $client was left half-done ($next or $client-previous exists)." >&2
	echo "Finish it by hand from README.md §Keys before starting another." >&2
	exit 1
fi

echo "1. a new key pair for $client"
"$kernel/new-client-key.sh" "$next" "$keys" "$owner"

echo "2. the kernel accepts the current key and the new one"
"$kernel/set-client-key.sh" "$realm" "$client" "$keys/$client.jwk.json" "$keys/$next.jwk.json"

echo "3. the new pair takes the current file names"
mv "$keys/$client.pem" "$keys/$client-previous.pem"
mv "$keys/$client.jwk.json" "$keys/$client-previous.jwk.json"
mv "$keys/$next.pem" "$keys/$client.pem"
mv "$keys/$next.jwk.json" "$keys/$client.jwk.json"

echo "4. the service restarts with the new key"
docker compose restart identity-control
port="${IDENTITY_CONTROL_PORT:-8082}"
ready=""
for _ in $(seq 1 60); do
	if curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1; then
		ready=yes
		break
	fi
	sleep 2
done
[ -n "$ready" ] || { echo "rotate-client-key: identity-control is not ready; both keys are still accepted" >&2; exit 1; }

echo "5. the kernel accepts the new key alone"
"$kernel/set-client-key.sh" "$realm" "$client" "$keys/$client.jwk.json"

if [ -n "${ROTATE_KEEP_PREVIOUS:-}" ]; then
	# deploy-dev keeps it to prove the kernel refuses it, then deletes it itself.
	echo "the previous pair is kept as $keys/$client-previous.pem for the proof"
else
	rm -f "$keys/$client-previous.pem" "$keys/$client-previous.jwk.json"
fi
echo "$client rotated."
