#!/usr/bin/env bash
# Makes the key ring that seals security_ref handles: ./keys/security-ref.json, one 32-byte
# AES-256-GCM key with a kid, mode 0600 and owned by KEYS_OWNER (TDD-identity-control-005
# §Technical Context). Run once, on the server, by whoever operates it.
#
# The key is made inside the migrate image, which has a shell and /dev/urandom, so the host needs
# Docker and nothing else, and the key is never printed. The script refuses when the file exists:
# replacing the key is a rotation, which keeps the previous key in the ring for one handle TTL.
set -euo pipefail
cd "$(dirname "$0")"

set -a
# shellcheck disable=SC1091
. ./.env
set +a

owner="${KEYS_OWNER:-65532:65532}"
keys="$(mkdir -p ./keys && cd ./keys && pwd)"
file=security-ref.json

if [ -e "$keys/$file" ]; then
	echo "create-security-ref-key: $keys/$file already exists; nothing created." >&2
	exit 1
fi

docker compose build -q migrate
docker compose run --rm --no-deps --user 0:0 -v "$keys:/out" --entrypoint sh migrate -ec '
	umask 077
	kid="k$(date -u +%Y%m%d)"
	key="$(head -c 32 /dev/urandom | base64 | tr -d "\n")"
	printf "{\"keys\":[{\"kid\":\"%s\",\"key\":\"%s\"}]}\n" "$kid" "$key" > "/out/$1"
	chown "$2" "/out/$1"
	chmod 0600 "/out/$1"
' sh "$file" "$owner"
echo "create-security-ref-key: wrote $keys/$file, owned by $owner." >&2
