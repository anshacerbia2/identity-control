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

./create-kernel-clients.sh                   # prints two secrets; put both into .env
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
export IDENTITY_API_URL=http://127.0.0.1:8082 KC_BASE_URL=http://127.0.0.1:8081   # the kernel's private port
pwsh ./scripts/dev-smoke.ps1
```

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
Control Database, the server's client secret, and the server's Keycloak. The service is built for
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

On the laptop, forward the tunnel's ports to localhost and keep that running. That forwards
`8081` (Keycloak's private port) and `5433` (the Control Database). Then run the service with the
server's values from `deploy/dev/.env`:

```powershell
devtunnel connect <tunnel>

$env:IDENTITY_DATABASE_URL           = "postgres://identity_app:<IDENTITY_APP_PASSWORD>@localhost:5433/identity_control?sslmode=disable"
$env:IDENTITY_LISTEN_ADDRESS         = ':8090'
$env:IDENTITY_KEYCLOAK_REALM         = 'scnehaux'
$env:IDENTITY_KEYCLOAK_BASE_URL      = 'http://localhost:8081'
$env:IDENTITY_KEYCLOAK_CLIENT_ID     = 'identity-control'
$env:IDENTITY_KEYCLOAK_CLIENT_SECRET = '<IDENTITY_KEYCLOAK_CLIENT_SECRET>'
$env:IDENTITY_TOKEN_ISSUER           = '<KEYCLOAK_ISSUER>'
$env:IDENTITY_TOKEN_AUDIENCE         = 'identity-control'
$env:IDENTITY_JWKS_URL               = 'http://localhost:8081/realms/scnehaux/protocol/openid-connect/certs'
go run ./cmd/identity-control
```

- **Keycloak:** the Admin API must be reached on the private port. The public port refuses
  `/admin` to everyone, which is what keeps it off the internet.
- **Do not run `scripts/dev-keycloak.ps1` against this realm.** It sets the clients' secrets from
  your environment, and the server's replica would lose access to Keycloak. The clients are already
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
- **It does not register other applications' clients.** The Admin API client holds
  `manage-users` and `view-users` only, as TDD-identity-control-001 states. Client registration
  (TDD-identity-control-003) is not built, and it will need a decision on its credential first;
  see ROADMAP.md.
