# Development server

identity-control runs beside `identity-kernel`'s development Keycloak on the same host. It uses its
own Control Database, and reaches Keycloak over the kernel's `scnehaux-identity-api` network, which
carries Keycloak alone. CI brings this exact stack up against the kernel's `main` on every change.

It is **development only**, and three things make it so:

- Step 5 below sets the bootstrap Principal a password.
- The caller client exists so a person can get a token from a shell.
- The API is published on loopback.

| Service | Image | Runs |
| :-- | :-- | :-- |
| `postgres` | `postgres:17.11-alpine`, pinned | The Control Database |
| `migrate` | built, `migrate` target | Once per `up`: roles and platform schema, Atlas, privileges, the `identity_app` login role, and an assertion of the privilege shape. The service starts only if it succeeds |
| `identity-control` | built, `service` target (distroless, non-root) | The API, on `127.0.0.1:8082` |
| `bootstrap` | built, `migrate` target | Only through `bootstrap.sh`: the ceremony of ADR-IAM-001 §5.11 |

## Before you start

- **Kernel stack:** `identity-kernel/deploy/dev` must be up. It creates the `scnehaux-identity-api`
  network.
- **Kernel realm:** it must be applied with `realm-apply`. This service needs the realm's
  `scnehaux-provider` scope, and `create-kernel-clients.sh` refuses to run without it.

## First start

On the server:

```sh
cd identity-control/deploy/dev
cp .env.example .env
# fill in:
#   KEYCLOAK_ISSUER           the kernel's issuer, as its discovery document states it
#   POSTGRES_PASSWORD, IDENTITY_APP_PASSWORD, IDENTITY_CALLER_PASSWORD
#   KC_BOOTSTRAP_ADMIN_PASSWORD, copied from the kernel's deploy/dev/.env
#   KERNEL_DEPLOY_DIR         the kernel checkout's deploy/dev, whose key tools the scripts use

./create-kernel-clients.sh >> .env           # both clients, each with its own key in ./keys
./create-registration-client.sh              # the registration client, with its key
docker compose up -d --build
curl -fsS http://127.0.0.1:8082/readyz       # ready once the migration job has succeeded

./bootstrap.sh "you@example.com" "first stand-up of the development server"
```

The ceremony can succeed once per Control Database, and a second run is refused. That is the
design, not a fault.

If the network intercepts TLS to `proxy.golang.org`, the build fails at `go mod download`. Pass
`GOPROXY=direct` as a build argument from a local, uncommitted compose override:

```yaml
services:
  migrate:
    build: { args: { GOPROXY: direct } }
  bootstrap:
    build: { args: { GOPROXY: direct } }
  identity-control:
    build: { args: { GOPROXY: direct } }
```

Modules are then fetched from their origins. `go.sum` and the checksum database still verify every
one of them.

## Calling the API

Every mutation needs a provider-scope token. Get one by logging in as `bootstrap-operator` with
`IDENTITY_CALLER_PASSWORD`, through the kernel's login form and the `identity-control-caller`
client. `scripts/dev-token.ps1` does this without a browser, and `scripts/dev-smoke.ps1` exercises
the API with it. They are the same scripts CI runs:

```sh
set -a; . deploy/dev/.env; set +a
# KC_BASE_URL is the kernel's public origin: the origin of KEYCLOAK_ISSUER, which is the tunnel host in tunnel mode
export IDENTITY_API_URL=http://127.0.0.1:8082 KC_BASE_URL=https://<KEYCLOAK_HOSTNAME>
pwsh ./scripts/dev-smoke.ps1
```

**Log in on the public origin, never the private port.** Keycloak's hostname is fixed, so its
login form always posts to the public origin. A login started on `http://127.0.0.1:8081` stores
its session cookie for `127.0.0.1`, and the form's post then goes to the tunnel host without it.
Keycloak answers "Restart login cookie not found". CI uses `https://localhost` because that is
its kernel's public origin. The private port is for Admin API calls from code only.

The scripts need PowerShell 7 (`pwsh`). A server without it can run the same flow in another
language. The steps are:

1. Authorization Code with PKCE `S256` on the public origin.
2. Exchange the code with a PS256 assertion signed by `IDENTITY_CALLER_KEY_FILE`.
3. Call the API.

To call the API from off the server, add port `8082` to the tunnel. Keep it owner-only unless
something else must reach it. Every mutation is refused without a provider-scope token either way.

## Running the code from a laptop

A realm has exactly one identity-control authority: one Control Database. A second instance with
its own database would break three things:

- **Mappings:** it would hold mappings the first has never seen.
- **Reconciler:** each instance's reconciler would read the other's Principals as orphans and
  disable them (TDD-identity-control-001).
- **Ceremony:** its bootstrap ceremony would collide with the existing `bootstrap-operator`.

So a laptop does not run a second authority. It runs a second *replica* of this one: the server's
Control Database, the server's clients, and the server's Keycloak. The service is built for
several replicas, because idempotency and the outbox live in the database. Migrations stay with the
server's migration job, so the laptop needs no Postgres and no Atlas.

On the server, publish the Control Database on loopback from a local, uncommitted override, and
add the port to the tunnel as **owner-only**:

```yaml
# compose.override.yaml
services:
  postgres:
    ports: ["127.0.0.1:5433:5432"]
```

```sh
docker compose up -d
devtunnel port create <tunnel> -p 5433      # no --anonymous: owner-only
```

**The laptop signs with its own keys, never the server's.** No client has a secret, and a private
key never leaves the host that made it (ADR-IAM-001 §5.12). So the laptop makes a key pair for each
Admin API client and sends only the public halves to whoever operates the server:

```powershell
cd ../identity-kernel
go run ./cmd/client-key new -out ../identity-control/deploy/dev/keys/identity-control.pem
go run ./cmd/client-key new -out ../identity-control/deploy/dev/keys/identity-control-registration.pem
# send deploy/dev/keys/*.jwk.json to the server's operator
```

The operator installs each laptop key beside the server's own. A client accepts at most two keys, so
this cannot overlap a rotation. The operator runs, from the kernel's `deploy/dev`:

```sh
./set-client-key.sh scnehaux identity-control /srv/identity-control/deploy/dev/keys/identity-control.jwk.json laptop-identity-control.jwk.json
./set-client-key.sh scnehaux identity-control-registration /srv/identity-control/deploy/dev/keys/identity-control-registration.jwk.json laptop-identity-control-registration.jwk.json
```

When the laptop is done, the operator installs the server's key alone again, and the laptop's
keys stop working.

On the laptop, forward the tunnel's ports to localhost and keep that running. That forwards
`8081` (Keycloak's private port) and `5433` (the Control Database). Then run the service with the
server's values from `deploy/dev/.env` and the laptop's own keys:

```powershell
devtunnel connect <tunnel>

$env:IDENTITY_DATABASE_URL           = "postgres://identity_app:<IDENTITY_APP_PASSWORD>@localhost:5433/identity_control?sslmode=disable"
$env:IDENTITY_LISTEN_ADDRESS         = ':8090'
$env:IDENTITY_KEYCLOAK_REALM         = 'scnehaux'
$env:IDENTITY_KEYCLOAK_BASE_URL      = 'http://localhost:8081'
$env:IDENTITY_KEYCLOAK_CLIENT_ID     = 'identity-control'
$env:IDENTITY_KEYCLOAK_CLIENT_KEY_FILE = (Resolve-Path deploy/dev/keys/identity-control.pem).Path
$env:IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID       = 'identity-control-registration'
$env:IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE = (Resolve-Path deploy/dev/keys/identity-control-registration.pem).Path
$env:IDENTITY_TOKEN_ISSUER           = '<KEYCLOAK_ISSUER>'
$env:IDENTITY_TOKEN_AUDIENCE         = 'identity-control'
$env:IDENTITY_JWKS_URL               = 'http://localhost:8081/realms/scnehaux/protocol/openid-connect/certs'
go run ./cmd/identity-control
```

- **Keycloak:** the Admin API must be reached on the private port. The public port refuses
  `/admin` to everyone, which is what keeps it off the internet.
- **Do not run `scripts/dev-keycloak.ps1` against this realm.** It replaces the clients' keys with
  the laptop's, and the server's replica would lose access to Keycloak. The clients are already
  registered, by `create-kernel-clients.sh`.
- **Do not run the ceremony again.** It succeeded once, on the server, and belongs to this Control
  Database.
- **Server replica:** it may keep running alongside the laptop's. If you would rather have every
  request land on your code, stop it with `docker compose stop identity-control`.
- **Schema changes still go through the server.** A migration you are developing is applied by the
  migration job after you push, never by hand from the laptop. The runtime role cannot run DDL
  anyway.

## What it does not do

- **It writes nothing into the realm.** Scopes, attributes, and keys are `identity-kernel`'s
  `realm/`, applied by its `realm-apply`. `create-kernel-clients.sh` only registers this service's
  two clients.
- **It does not register other applications' clients yet.** The Admin API client holds
  `manage-users` and `view-users` only, as TDD-identity-control-001 states. Client registration
  (TDD-identity-control-003) has its tables and its own credential, `identity-control-registration`,
  holding `manage-clients`, `view-clients` and `view-events`. The registration drift sweep uses it,
  and the service refuses to start without it.
  `scripts/dev-credential-split.ps1` asserts that neither credential can do the other's work.

## Adding the registration client to a running server

A server stood up before the registration client existed has the two kernel clients and not this
one. Add it once, without rerunning `create-kernel-clients.sh`:

```sh
cd identity-control/deploy/dev
./create-registration-client.sh              # refuses if the client already exists
```

It creates `identity-control-registration` and its key, and changes nothing else in the realm. Run
it again and it refuses. A key is replaced by a rotation, below, never by a rerun.

## Adopting the BFF

`identity-experience-bff` was created by `identity-experience`'s `deploy/dev/create-bff-client.sh`
before this service could register it, so it is **adopted** (`TDD-identity-control-003` §Adoption):
a plan first, then the adoption, held to the key it already authenticates with. Until it is, the
sweep reports it `unmanaged`, and the server must stay on `IDENTITY_UNMANAGED_CLIENTS=report`,
the default, or the BFF is disabled with every open session.

With a provider-scope token (`scripts/dev-token.ps1`), plan it:

```http
POST /v1/registrations:adopt
X-Administrative-Reason: the BFF comes under registration
Content-Type: application/json

{"client_key":"identity-experience-bff","profile":"confidential","audience_class":"internal",
 "application_ref":"identity-experience","redirect_uris":["<the BFF's callback URIs, exactly>"],
 "public_keys":[<the public JWK of identity-experience-bff.pem>],"dry_run":true}
```

The answer is the plan. `adoptable: true` means the client runs as declared. A `token_lifespan`,
`audience_scope`, `enabled` or `token_format` difference is converged only if named in
`"converge": [...]`. A client a script made before the token profile differs in `token_format` (no
at+jwt attribute, no `client_id` mapper) and `audience_scope` (the realm's old default scopes, which
put email, names and roles into its access tokens), so name both:
`"converge":["token_format","audience_scope"]`. A
`redirect_uris` or `client_keys` difference means the declaration is wrong, and is fixed in the
declaration, never in the console. Then send the same body without `dry_run` and with an
`Idempotency-Key`. Once the BFF and the caller are adopted, set `IDENTITY_UNMANAGED_CLIENTS=disable`
in `.env` and recreate the service with `docker compose up -d identity-control`; a restart keeps the
environment the container was created with. `IDENTITY_TOKEN_TYPE=enforce` goes the same way, once
the log no longer reports a token not typed at+jwt. `compose.yaml` passes both to the container,
defaulting to `report`, and passes nothing it does not list.

## The token profile, on a server that ran before it

A client registered or adopted before the token profile (`TDD-identity-control-003` §Profiles)
lacks the at+jwt attribute and the `client_id` mapper, and holds the realm's old default scopes.
The first sweep after the upgrade records each such client `unattributed` in `token_format` and
`audience_scope`, because no admin event explains a difference that predates the comparison. Apply
the registered state once per finding, from the Admin Portal's registration page or with
`POST /v1/registrations:reconcile` naming the findings and a reason. The clients' access tokens then
carry `typ` `at+jwt` and `client_id`, and no email, names, or roles.

## Keys, and moving a server from secrets to keys

Every client of this service authenticates with its own key by signed JWT. The private keys live
in `./keys`, mode 0600, owned by `KEYS_OWNER`: the service's container user, 65532 unless `.env`
says otherwise. The kernel holds only the public halves. `identity-kernel/deploy/dev/README.md`
documents its two tools, `new-client-key.sh` and `set-client-key.sh`.

**A server stood up with client secrets** moves once. Each client stops authenticating between its
`set-client-key.sh` and the rebuild, so run the steps together. From this directory, after `git
pull`:

```sh
k="$KERNEL_DEPLOY_DIR"   # after: set -a; . ./.env; set +a
mkdir -p keys
"$k/new-client-key.sh" identity-control "$PWD/keys" "${KEYS_OWNER:-65532:65532}"
"$k/new-client-key.sh" identity-control-registration "$PWD/keys" "${KEYS_OWNER:-65532:65532}"
"$k/new-client-key.sh" identity-control-caller "$PWD/keys" "$(id -u):$(id -g)"
"$k/set-client-key.sh" scnehaux identity-control "$PWD/keys/identity-control.jwk.json"
"$k/set-client-key.sh" scnehaux identity-control-registration "$PWD/keys/identity-control-registration.jwk.json"
"$k/set-client-key.sh" scnehaux identity-control-caller "$PWD/keys/identity-control-caller.jwk.json"
# .env: delete IDENTITY_KEYCLOAK_CLIENT_SECRET, IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_SECRET and
# IDENTITY_CALLER_SECRET; add KERNEL_DEPLOY_DIR, and IDENTITY_CALLER_KEY_FILE=$PWD/keys/identity-control-caller.pem
docker compose up -d --build
curl -fsS http://127.0.0.1:8082/readyz
```

**Rotating a key.**

1. Make the new pair under a new name, for example `identity-control-next`.
2. Install both public keys, the current one and the new one.
3. Move the new pair over the current file names (`identity-control.pem` and `.jwk.json`).
4. Restart the service.
5. Install the new public key alone.

The service is never without an accepted key while this runs.
