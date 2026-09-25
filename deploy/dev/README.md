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

## What it does not do

- **It writes nothing into the realm.** Scopes, attributes, and keys are `identity-kernel`'s
  `realm/`, applied by its `realm-apply`. `create-kernel-clients.sh` only registers this service's
  two clients.
- **It does not register other applications' clients.** The Admin API client holds
  `manage-users` and `view-users` only, as TDD-identity-control-001 states. Client registration
  (TDD-identity-control-003) is not built, and it will need a decision on its credential first;
  see ROADMAP.md.
