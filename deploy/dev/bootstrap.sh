#!/usr/bin/env bash
# The bootstrap ceremony on the development server, then a local credential for the Principal it
# creates. Run once, after `docker compose up -d --build`.
#
#   ./bootstrap.sh "you@example.com" "why this is being done"
#
# Step 1 is the production procedure (ADR-IAM-001 §5.11): identity-bootstrap creates the first
# Principal through the same path POST /v1/principals uses, records the operator and reason
# immutably, and succeeds at most once per Control Database.
#
# Step 2 is DEVELOPMENT ONLY. The ceremony leaves the Principal owing a credential so that no
# process ever holds one; a real operator completes that through the kernel's own flow. Here the
# kernel's administrator sets IDENTITY_CALLER_PASSWORD and clears the pending action, so the
# Principal can log in to obtain a token -- the same step scripts/dev-bootstrap.ps1 takes locally.
set -euo pipefail
cd "$(dirname "$0")"

operator="${1:?usage: bootstrap.sh <operator> <reason>}"
reason="${2:?usage: bootstrap.sh <operator> <reason>}"
username=bootstrap-operator

set -a
# shellcheck disable=SC1091
. ./.env
set +a
: "${IDENTITY_CALLER_PASSWORD:?set IDENTITY_CALLER_PASSWORD in .env: the password the bootstrap Principal logs in with}"

echo "[1/2] bootstrap ceremony"
docker compose run --rm bootstrap \
	-operator "$operator" -reason "$reason" -username "$username" -email "$username@scnehaux.local"

echo "[2/2] local credential  <-- DEVELOPMENT ONLY"
container="${KERNEL_KEYCLOAK_CONTAINER:-scnehaux-identity-dev-keycloak-1}"
kc() {
	docker exec -i "$container" /opt/keycloak/bin/kcadm.sh "$@" --config /tmp/kcadm-identity-control.config
}
kc config credentials --server http://localhost:8080 --realm master \
	--user "${KC_BOOTSTRAP_ADMIN_USERNAME:-admin}" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/dev/null
user="$(kc get users -r scnehaux -q "username=$username" -q exact=true --fields id --format csv --noquotes | head -n 1)"
if [ -z "$user" ]; then
	echo "bootstrap: the ceremony reported success but $username is not in the kernel" >&2
	exit 1
fi
kc set-password -r scnehaux --userid "$user" --new-password "$IDENTITY_CALLER_PASSWORD"
# firstName and lastName are required by the kernel's default user profile, and a login with them missing
# is interrupted by a profile-completion page instead of returning a code. A person would fill them in at
# that page; this step stands in for that person, as scripts/dev-bootstrap.ps1 does locally.
kc update "users/$user" -r scnehaux -s firstName=Bootstrap -s lastName=Operator -s 'requiredActions=[]'
echo "      $username can now log in with IDENTITY_CALLER_PASSWORD"
