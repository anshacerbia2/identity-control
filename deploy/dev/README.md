# Development server

## What runs

identity-control runs beside `identity-kernel`'s development Keycloak on the same host. It uses its
own Control Database, and reaches Keycloak over the kernel's `scnehaux-identity-api` network, which
carries Keycloak alone. CI brings this exact stack up against the kernel's `main` on every change.

It is **development only**, and three things make it so:

- The ceremony in §First start gives the bootstrap Principal a password.
- The caller client exists so a person can get a token from a shell.
- The API is published on loopback.

| Service | Image | Runs |
| :-- | :-- | :-- |
| `postgres` | `postgres:17.11-alpine`, pinned | The Control Database |
| `migrate` | built, `migrate` target | Once per `up`: roles and platform schema, Atlas, privileges, the `identity_app` login role, and an assertion of the privilege shape. The service starts only if it succeeds |
| `identity-control` | built, `service` target (distroless, non-root) | The API, on `127.0.0.1:8082` |
| `bootstrap` | built, `migrate` target | Only through `bootstrap.sh`: the ceremony of ADR-IAM-001 §5.11 |

The compose project is `scnehaux-identity-control-dev`, and the network other stacks call this service
on is `scnehaux-identity-control-api`; both are the defaults STD-GLB-009 §Development Server Deployment
names.

What it does not do:

- **It writes nothing into the realm.** Scopes, attributes, and keys are `identity-kernel`'s
  `realm/`, applied by its `realm-apply`. `create-kernel-clients.sh` only registers this service's
  two clients.
- **It does not register other applications' clients yet.** The Admin API client holds
  `manage-users` and `view-users`, as TDD-identity-control-001 states, and `manage-organizations` and
  `view-organizations`, which TDD-identity-control-002 2.0.0 adds to project Tenants. Client registration
  (TDD-identity-control-003) has its tables and its own credential, `identity-control-registration`,
  holding `manage-clients`, `view-clients` and `view-events`. The registration drift sweep uses it,
  and the service refuses to start without it.
  `scripts/dev-credential-split.ps1` asserts that neither credential can do the other's work.

## Before you start

- **Kernel stack:** `identity-kernel/deploy/dev` must be up. It creates the `scnehaux-identity-api`
  network.
- **Kernel realm:** it must be applied with `realm-apply`. This service needs the realm's
  `scnehaux-provider` scope, and `create-kernel-clients.sh` refuses to run without it.
- **Docker with Compose v2**, and a user in the `docker` group.
- **PowerShell 7 (`pwsh`).** The token, smoke and adoption scripts in `scripts/` need it:
  `dev-token.ps1`, `dev-smoke.ps1`, `dev-adopt-caller.ps1`, `dev-adopt-bff.ps1`. Install it before step 8
  of §First start. §One-off tasks says how to call the API without it.
- **A network that intercepts TLS to `proxy.golang.org`** fails the build at `go mod download`. Put
  `GOPROXY=direct` in `.env`; `compose.yaml` passes it to both builds as a build argument. Modules are
  then fetched from their origins, and `go.sum` and the checksum database still verify every one of
  them. `compose.override.example.yaml` shows the same as a local override.

## First start

On the server, from `identity-control/deploy/dev`:

1. **Configure.** `cp .env.example .env`, and fill in:
   - `KEYCLOAK_ISSUER`, the kernel's issuer, as its discovery document states it;
   - `POSTGRES_PASSWORD`, `IDENTITY_APP_PASSWORD`, `IDENTITY_CALLER_PASSWORD`;
   - `KC_BOOTSTRAP_ADMIN_PASSWORD`, copied from the kernel's `deploy/dev/.env`;
   - `KERNEL_DEPLOY_DIR`, the kernel checkout's `deploy/dev`, whose key tools the scripts use;
   - `GOPROXY=direct`, only where the network intercepts TLS to the module proxy (§Before you start).
2. **Register this service's two clients,** each with its own key in `./keys`:
   `./create-kernel-clients.sh >> .env`.
3. **Register the registration client,** with its key: `./create-registration-client.sh`.
4. **Make the key ring that seals `security_ref` handles:** `./create-security-ref-key.sh`.
5. **Start the stack:** `docker compose up -d --build`.
6. **Wait until it is ready:** `curl -fsS http://127.0.0.1:8082/readyz` answers once the migration
   job has succeeded.
7. **Perform the bootstrap ceremony:**
   `./bootstrap.sh "you@example.com" "first stand-up of the development server"`.

The same, as one block:

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
./create-security-ref-key.sh                 # the key ring that seals security_ref handles
docker compose up -d --build
curl -fsS http://127.0.0.1:8082/readyz       # ready once the migration job has succeeded

./bootstrap.sh "you@example.com" "first stand-up of the development server"
```

The ceremony can succeed once per Control Database, and a second run is refused. That is the
design, not a fault.

8. **Adopt the development caller.** `create-kernel-clients.sh` made `identity-control-caller` in the
   kernel before this service could register it, so it is adopted, held to the key it already
   authenticates with (`TDD-identity-control-003` §Adoption). The script plans first and adopts only
   with `-Apply`; it sends the declaration `scripts/dev-smoke.ps1` step 9b adopts in CI:

   ```sh
   cd identity-control
   set -a; . deploy/dev/.env; set +a
   export IDENTITY_API_URL=http://127.0.0.1:8082 KC_BASE_URL=https://<KEYCLOAK_HOSTNAME>
   pwsh ./scripts/dev-adopt-caller.ps1            # the plan
   pwsh ./scripts/dev-adopt-caller.ps1 -Apply     # adopt
   ```

   The plan names `token_format` and `audience_scope` as differences it converges: the script made the
   caller before the token profile. A `redirect_uris` or `client_keys` difference means the
   declaration is wrong, and is fixed in the declaration, never in the console. A second run answers
   that the caller is registered already. Provider routes need `aal2`, so export
   `IDENTITY_OPERATOR_TOTP_FILE=$PWD/deploy/dev/keys/operator-totp.json` first: the script then signs
   in with the server's TOTP for the bootstrap operator, and binds one there on the first sign-in if
   the operator has no second factor yet. Where the owner's TOTP is enrolled already, bind the server's
   with one of the owner's codes first (§Updating, The server's own TOTP).
9. **Adopt the BFF,** once `identity-experience`'s `create-bff-client.sh` has made it: §Wiring to other
   services, Adopting the BFF.
10. **Apply the registered state, if anything differs.** Both adoptions converge `token_format` and
    `audience_scope`, so every client this server holds now carries the token profile (`TDD-identity-control-003`
    §Profiles) and none should differ. Read the open findings with a provider token:
    `GET /v1/registrations:drift`, whose `findings` should be empty. A finding there is applied, with
    its reason, by `POST /v1/registrations:reconcile` naming it
    (`{"findings":["<finding_id>"]}`, `X-Administrative-Reason`); a `redirect_uris` or `client_keys`
    finding instead means a declaration was wrong (§Never do).
11. **End in the production settings.** Put both in `.env`, then recreate the service, since a
    restart keeps the environment the container was created with:

    ```sh
    echo IDENTITY_UNMANAGED_CLIENTS=disable >> .env   # a client no registration describes is disabled
    echo IDENTITY_TOKEN_TYPE=enforce >> .env          # a token not typed at+jwt is refused with 401
    docker compose up -d identity-control
    curl -fsS http://127.0.0.1:8082/readyz
    ```

    Both must wait for step 10: before the caller and the BFF are adopted, `disable` would disable them
    with every open session, and before they carry the token profile their tokens are typed `JWT`,
    which `enforce` refuses. `compose.yaml` defaults both to `report`, which is what a server is until
    this step (`TDD-identity-control-003` §Adoption, `TDD-identity-control-001` §Caller Token).
    Then check it, with the environment of step 8: `pwsh ./scripts/dev-production-switches.ps1` signs
    in, requires the token typed `at+jwt` and a provider call to answer, runs a registration sweep and
    requires no client recorded `unmanaged`. `docker compose logs identity-control | grep 'not typed
    at+jwt'` then finds nothing. `deploy-dev` runs this step on every change.

## Updating

The same on every server and in every repository (STD-GLB-009 §Development Server Deployment):

```sh
cd identity-control/deploy/dev
git pull
docker compose up -d --build
```

The migrate job applies whatever is new before the service restarts. The one-off tasks run the
migrate image, so this rebuilds them too. A release that needs more than this is taken by standing the
server up again from zero (§First start), which every environment is: there is no in-place upgrade
procedure to keep in step with the code.

### The server's own TOTP for the bootstrap operator

The agent that operates this server needs `aal2` tokens, and nobody can relay a 30-second code to it.
So the server holds a second TOTP for the bootstrap operator (ADR-IAM-004 §5.5). It is bound at
`aal2`, as NIST SP 800-63B-4 §4.1.2.1 requires: once, with one code the owner reads from their own
authenticator.

```powershell
. ./scripts/dev-token.ps1
# -Otp is the owner's current code, read from their phone; it is good for about a minute.
Get-ScnehauxToken -Username bootstrap-operator -Password $env:IDENTITY_CALLER_PASSWORD `
  -KeyFile $env:IDENTITY_CALLER_KEY_FILE -EnrollTotpFile deploy/dev/keys/operator-totp.json -Otp <code>
```

The script signs in at `aal2` and asks the kernel to set up another TOTP labelled `dev-server`. It
then writes the secret to `deploy/dev/keys/operator-totp.json`, mode 0600. The secret is never
printed, and the script refuses when the file exists. From then on:

```powershell
Get-ScnehauxToken … -AcrValues aal2 -TotpSecretFile deploy/dev/keys/operator-totp.json
```

Rules:
- **Development servers only.** On this server the password and this TOTP sit together, so for
  this account the two factors are one place.
- **To end it,** a provider revokes the `dev-server` authenticator of the bootstrap operator from the
  Admin Portal. That removes the server's TOTP without touching the owner's.

## One-off tasks

Each is a service behind a profile that runs the migrate image, and never starts with `up`:

| Task | Run | When |
| :-- | :-- | :-- |
| `bootstrap` | `./bootstrap.sh "<operator>" "<reason>"` the first time; to resume, `docker compose run --rm bootstrap -operator … -resume …` | once per Control Database (ADR-IAM-001 §5.11) |
| `provider-bootstrap` | `docker compose run --rm provider-bootstrap` | once Organization Control serves this consumer, and again after its registration changes; organization-control's `deploy/dev/README.md` says when. It bootstraps provider authority and the Tenant context, and records the lower mark |

### Calling the API

Every mutation needs a provider: a Principal this service's records name as one, for each request
(TDD-identity-control-006). On a fresh stack that is the ceremony's Principal, `bootstrap-operator`,
until Organization's first emergency `provider:identity-control` grant is projected. Log in as
`bootstrap-operator` with `IDENTITY_CALLER_PASSWORD`, through the kernel's login form and the
`identity-control-caller` client. The token carries no `provider_scope`; one that does is refused. `scripts/dev-token.ps1` does this without a browser, and `scripts/dev-smoke.ps1` exercises
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
something else must reach it. Every mutation is refused to a caller that is not a provider either way.

### Running the code from a laptop

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

# Once: the key ring that seals security_ref handles. 32 random bytes, never printed.
if (-not (Test-Path deploy/dev/keys/security-ref.json)) {
    $bytes = [byte[]]::new(32); [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    @{ keys = @(@{ kid = 'k1'; key = [Convert]::ToBase64String($bytes) }) } | ConvertTo-Json -Depth 3 -Compress |
        Set-Content -NoNewline deploy/dev/keys/security-ref.json
}
$env:IDENTITY_DATABASE_URL           = "postgres://identity_app:<IDENTITY_APP_PASSWORD>@localhost:5433/identity_control?sslmode=disable"
$env:IDENTITY_LISTEN_ADDRESS         = ':8090'
$env:IDENTITY_KEYCLOAK_REALM         = 'scnehaux'
$env:IDENTITY_KEYCLOAK_BASE_URL      = 'http://localhost:8081'
$env:IDENTITY_KEYCLOAK_CLIENT_ID     = 'identity-control'
$env:IDENTITY_KEYCLOAK_CLIENT_KEY_FILE = (Resolve-Path deploy/dev/keys/identity-control.pem).Path
$env:IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID       = 'identity-control-registration'
$env:IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE = (Resolve-Path deploy/dev/keys/identity-control-registration.pem).Path
$env:IDENTITY_SECURITY_REF_KEY_FILE  = (Resolve-Path deploy/dev/keys/security-ref.json).Path
$env:IDENTITY_TOKEN_ISSUER           = '<KEYCLOAK_ISSUER>'
$env:IDENTITY_TOKEN_AUDIENCE         = 'identity-control-api'
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

## Wiring to other services

Organization Control's stack joins this one's `scnehaux-identity-control-api` network, so start this
stack first. Until it runs, the delivery intake answers 503, the provider projection is never fresh,
and the ceremony's grant is the only provider authority (TDD-identity-control-006). organization-control's
`deploy/dev/README.md` §Wiring to other services is the procedure. It ends by setting
`IDENTITY_DELIVERY_PRINCIPAL_ID` and `IDENTITY_ORGANIZATION_BASE_URL` here and running
`provider-bootstrap`.

### Adopting the BFF

`identity-experience-bff` was created by `identity-experience`'s `deploy/dev/create-bff-client.sh`
before this service could register it, so it is **adopted** (`TDD-identity-control-003` §Adoption):
a plan first, then the adoption, held to the keys it already authenticates with. Until it is, the
sweep reports it `unmanaged`, and the server must stay on `IDENTITY_UNMANAGED_CLIENTS=report`,
the default, or the BFF is disabled with every open session.

`scripts/dev-adopt-bff.ps1` does both steps, with the caller's credentials from the environment as
`dev-smoke.ps1` reads them and the BFF's **public** JWKs, each the one `new-client-key.mjs` wrote
beside its private key. It plans first and adopts only with `-Apply`:

```powershell
pwsh ./scripts/dev-adopt-bff.ps1 -BffJwkFile ./identity-experience-bff.jwk.json          # the plan
pwsh ./scripts/dev-adopt-bff.ps1 -BffJwkFile ./identity-experience-bff.jwk.json -Apply   # adopt
```

**Every key the client holds is declared.** The plan compares the client's JWKS with `public_keys`
as a set, so a client given two keys with the kernel's `set-client-key.sh`, one per developer device,
is declared with both, or the plan shows a `client_keys` difference. Pass them as one comma-separated
list:

```powershell
pwsh ./scripts/dev-adopt-bff.ps1 -BffJwkFile ./laptop-a.jwk.json,./laptop-b.jwk.json          # the plan
pwsh ./scripts/dev-adopt-bff.ps1 -BffJwkFile ./laptop-a.jwk.json,./laptop-b.jwk.json -Apply   # adopt
```

The API takes one or two keys, the most a client holds (`TDD-identity-control-003` §Adoption) and as
many as `set-client-key.sh` installs; the script refuses a third before it sends anything.

**The second key does not stay.** The adoption records the first file's key `active` and the
second's `retiring`, as for a client adopted in the middle of a rotation. The second is removed from
the client once `IDENTITY_CLIENT_KEY_ROTATION_OVERLAP` ends (168 hours by default), at the next sweep,
and the device that signs with it stops working. So list first the key that must keep working. A
registered client holds one active key, and a second only while a rotation overlaps: moving the BFF
to the other device's key afterwards is a rotation, `POST /v1/registrations/{registration_id}/keys`.

The declaration it sends, with a provider-scope token (`scripts/dev-token.ps1`):

```http
POST /v1/registrations:adopt
X-Administrative-Reason: the BFF comes under registration
Content-Type: application/json

{"client_key":"identity-experience-bff","profile":"confidential","audience_class":"privileged",
 "privileged_form":"provider-scope","application_ref":"identity-experience",
 "redirect_uris":["http://127.0.0.1:8090/auth/callback"],"audience":["identity-control-api"],
 "public_keys":[<each public JWK identity-experience-bff holds, one or two>],
 "converge":["token_format","audience_scope"],"dry_run":true}
```

**No back-channel logout URI is declared for this BFF** (`ADR-IAM-009 §5.3`): it runs on a
developer's machine, which the kernel cannot reach, so a session the kernel removes ends at the BFF's
next refresh, within four minutes. `create-bff-client.sh` made it with front-channel logout off, which
is what the plan's `logout` class expects, so the declaration above adopts it with no `logout`
difference. A BFF the kernel can reach declares `"backchannel_logout_uri"`, its
`/auth/back-channel-logout` on an address the kernel's container resolves, in the registration or the
adoption, and names `logout` in `converge` for a client made without it (`TDD-identity-control-003`
1.37.0). `deploy-dev` proves that path from zero with `scripts/dev-back-channel-logout-proof.ps1`: a
client registered with a receiver's URI on the runner gets a logout token naming its session when the
API ends that session.

`deploy-dev` runs this procedure on every change, against a client made by `create-bff-client.sh`
the way this server's was and then given a second device's key with `set-client-key.sh`
(`scripts/dev-bff-adoption-proof.ps1`, STD-GLB-009 1.3.0). It also checks that a wrong declaration,
and one declaring only one of the two keys, is refused at the plan, that the first key is adopted
active and the second retiring, and that the adopted BFF's own token is served on a provider route.

**The class is `privileged`, in the `provider-scope` form, never `internal`.** The script attached
`scnehaux-provider`, and the Admin Portal's calls are provider routes, which require `acr` and
`auth_time` (STD-IAM-002 §3.1.1). Adopted as `internal`, converging `audience_scope` would replace
that scope with `scnehaux-internal`, and the BFF's next token would carry neither: every provider
route would refuse it. This section said `internal` until 2026-10-05. Such a declaration is now
refused at the plan, on `audience_profile` (`TDD-identity-control-003` 1.30.0).

The answer is the plan. `adoptable: true` means the client runs as declared. A `token_lifespan`,
`audience_scope`, `enabled`, `token_format` or `logout` difference is converged only if named in
`"converge": [...]`. A client a script made before the token profile differs in `token_format` (no
at+jwt attribute, no `client_id` mapper) and `audience_scope` (the realm's old default scopes, which
put email, names and roles into its access tokens), so name both:
`"converge":["token_format","audience_scope"]`. A
`redirect_uris` or `client_keys` difference means the declaration is wrong, and is fixed in the
declaration, never in the console: for `client_keys`, pass every public JWK the client holds. Then send the same body without `dry_run` and with an
`Idempotency-Key`. Once the BFF and the caller are adopted, §First start steps 10 and 11 apply any
registered state that still differs and end the server in `IDENTITY_UNMANAGED_CLIENTS=disable` and
`IDENTITY_TOKEN_TYPE=enforce`.

## Keys

Every client of this service authenticates with its own key by signed JWT. The private keys live
in `./keys`, mode 0600, owned by `KEYS_OWNER`: the service's container user, 65532 unless `.env`
says otherwise. The kernel holds only the public halves. `identity-kernel/deploy/dev/README.md`
documents its two tools, `new-client-key.sh` and `set-client-key.sh`.



**Rotating a key.**

1. Make the new pair under a new name, for example `identity-control-next`.
2. Install both public keys, the current one and the new one.
3. Move the new pair over the current file names (`identity-control.pem` and `.jwk.json`).
4. Restart the service.
5. Install the new public key alone.

The service is never without an accepted key while this runs.

For the two Keycloak administration credentials, `rotate-client-key.sh` runs the five steps and then
deletes the previous pair:

```sh
./rotate-client-key.sh identity-control
./rotate-client-key.sh identity-control-registration
```

It refuses to start over a rotation left half-done, and prints no key. `deploy-dev` rehearses it on
every run, on a kernel that lives for the job: after each rotation the new key is accepted, the
previous one is refused as `invalid_client`, and the restarted service still reaches the kernel
(`scripts/dev-key-rotation-proof.ps1`). The caller's key, `identity-control-caller`, rotates by the
same five steps by hand; nothing restarts for it.

The other secrets on disk: `keys/security-ref.json`, the key ring `create-security-ref-key.sh` made
(§First start, step 4), and `keys/operator-totp.json`, the server's TOTP for the
bootstrap operator (§Updating, The server's own TOTP). Neither is ever printed, and both are in the
backup below.

## Backups

The Control Database lives in the `postgres` volume of this project. **`docker compose down -v`
deletes it**, and with it every mapping, registration and record: nothing outside it can rebuild a
`principal_id`. Back it up daily to storage outside the Docker volume, and keep `.env` and `keys/`
with it, because a restored database is useless without the keys its clients authenticate with.

`./backup.sh <directory>` writes two files: `globals-<date>.sql`, the cluster's roles from
`pg_dumpall --globals-only`, and `identity_control-<date>.dump`, the database from
`pg_dump --format=custom`. A database dump holds no roles, and the roles must exist before the
objects they own or are granted are restored. Both files hold role password hashes, so the script
makes them readable by their owner alone. It connects over the container's local socket, which the
image trusts, so no password is typed or written anywhere. The service keeps running.

```sh
cd identity-control/deploy/dev
./backup.sh /mnt/backups/identity-control              # outside the Docker volume; yours may differ
```

Daily, from the operator's crontab (`crontab -e`), with the checkout's path:

```cron
15 2 * * * /home/development/apps/identity-control/deploy/dev/backup.sh /mnt/backups/identity-control >/dev/null
```

`keys/` belongs to `KEYS_OWNER`, the container's user, so it is copied with `sudo`:
`sudo tar -C . -czf "/mnt/backups/identity-control/keys-$(date +%F).tgz" keys .env`. Keep the archive as private as the keys.

To restore into an empty volume, put `.env` and `keys/` back first, then:

```sh
./restore.sh /mnt/backups/identity-control/globals-<date>.sql \
             /mnt/backups/identity-control/identity_control-<date>.dump
docker compose up -d --build
curl -fsS http://127.0.0.1:8082/readyz
```

`restore.sh` starts `postgres` alone and refuses a cluster that already holds `identity_control`:
replacing a live database is a decision, made by deleting the volume, never a side effect. It applies
the roles, allowing only the bootstrap superuser's harmless "role already exists", then restores the
database whole with `pg_restore --create --exit-on-error`, which stops at the first error. The
migrate job that `up` runs then finds the schema at its revision, applies anything newer, and sets
`identity_app`'s password from `.env` again. The ceremony record in the dump keeps a second ceremony
refused.

**What is proven, and what is not.** `deploy-dev` runs both scripts on every change and weekly, as
the restore drill `scripts/dev-restore-drill.sh` (STD-GLB-002 §Restore Evidence): it backs the filled
stack up, deletes its volume, restores, compares schema, migration version, every table, sequence and
role with the source, then starts the service and reads the registrations through the API. The
recovery is timed against the 15-minute RTO, and the evidence is the job's `restore-evidence`
artifact. A daily dump loses up to 24 hours of changes, against the 1-minute RPO of
`PAD-PLT-001 §6.2`; meeting it needs WAL archiving on the production platform. The runbook is
[`docs/runbooks/control-database-restore.md`](../../docs/runbooks/control-database-restore.md).

## Never do

- **`docker compose down -v`.** It deletes the Control Database (§Backups). `down` without `-v` keeps
  it. organization-control's stack joins `scnehaux-identity-control-api`, so stop that stack first
  when this one goes down.
- **Rename the compose project or the `api` network.** The volume and the network organization-control
  joins are named after them; a rename starts an empty database beside the old one.
- **Run the ceremony a second time,** or `bootstrap.sh` again. It succeeded once and belongs to this
  Control Database; a resume is `docker compose run --rm bootstrap … -resume …`.
- **Run `create-kernel-clients.sh` or `scripts/dev-keycloak.ps1` against this realm again.** They
  would replace the clients' keys, and this service would lose access to Keycloak. A key changes by a
  rotation (§Keys).
- **Fix a `redirect_uris` or `client_keys` difference in the console.** It is fixed in the declaration
  or through the API; a console change is drift the sweep blocks.
- **Log in on `http://127.0.0.1:8081`.** Log in on the public origin (§One-off tasks, Calling the API).
- **Put a client secret in `.env`.** No client of this service has one (ADR-IAM-001 §5.12).
- **Set `IDENTITY_UNMANAGED_CLIENTS=disable` or `IDENTITY_TOKEN_TYPE=enforce` before the caller and
  the BFF are adopted** (§First start, step 11).

## Troubleshooting

| Symptom | Cause, and what to do |
| :-- | :-- |
| The build fails at `go mod download` with a certificate error | The network intercepts TLS to the module proxy. Set `GOPROXY=direct` in `.env` and `docker compose up -d --build` |
| `/readyz` does not answer | The service waits for the migrate job. `docker compose logs migrate` shows which stage failed; the service starts only once it succeeds |
| A setting in `.env` changes nothing | compose passes a container only the variables `compose.yaml` lists, a restart keeps the environment the container was created with, and a variable exported in the shell wins over `.env` (a shell that ran `set -a; . deploy/dev/.env; set +a` holds the old values). Check the variable is listed, `unset` it in the shell or open a new one, then `docker compose up -d identity-control` |
| The login form answers "Restart login cookie not found" | The login started on the private port. Log in on the public origin (§One-off tasks, Calling the API) |
| Every provider route answers 401 with `insufficient_user_authentication` | The token is not `aal2`: a provider route asks for a password and a TOTP code (ADR-IAM-004). Pass `IDENTITY_OPERATOR_TOTP_FILE` to the scripts (§Updating, The server's own TOTP) |
| Every call answers 401 after §First start step 11 | A caller's token is typed `JWT`, not `at+jwt`: its client was not adopted with `token_format` converged. The log names it by `azp`; apply its registered state (step 10) |
| The BFF's sessions all end at once | `IDENTITY_UNMANAGED_CLIENTS=disable` was set before the BFF was adopted. Adopt it (§Wiring to other services) and re-enable it with the registered state |
| The ceremony is refused | It ran already; that is the design (§First start). Resume it only to finish an interrupted one |
| `create-kernel-clients.sh` refuses to run | The realm is not applied, or lacks `scnehaux-provider`: apply identity-kernel's realm first (§Before you start) |
| The Principal sweep lists users at `GET /v1/principals:unmapped` | Users in the realm that no mapping accounts for. On this server they are reported, not disabled (`IDENTITY_UNMAPPED_USERS`); triage each, then delete it in the console |
