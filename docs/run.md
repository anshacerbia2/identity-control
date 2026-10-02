# Running identity-control locally

This is the whole procedure for getting the service up and making a real authenticated call
against it. It has been run end to end on Windows against PostgreSQL 15.5 and Keycloak 26.7.1.

Nothing here is a deployment mechanism. A deployed instance is handed a database, a configured
Keycloak realm, and a credential from the secret manager; these scripts stand in for the parties
that provide them.

## What the harness proves

Not that the process starts — that it behaves the way the governance documents say it must:

| Property | Source |
|---|---|
| An unauthenticated mutation is refused | EAD-006 §8, fail closed |
| The probes answer without a credential | An orchestrator cannot present a token |
| Only a `PS256` token is accepted | STD-IAM-002 §3.2.2, ADR-IAM-002 |
| A replayed `Idempotency-Key` returns the same identifier without a second Keycloak call | STD-GLB-002 |
| A workload Principal without an accountable owner is refused | TDD-identity-control-001 |
| A client cannot supply `keycloak_user_id` | TDD-identity-control-001 |
| The runtime role holds DML and no DDL, and cannot reach Atlas's revision table | ADR-GLB-004 |
| The first Principal is created by an evidenced ceremony that can succeed once | ADR-IAM-001 §5.11 |
| Only a `privileged` / `provider-scope` token is accepted | STD-IAM-002 §3.1.1, §3.2, §3.5 |
| The token lifetime is class `L0` — four minutes | STD-IAM-002 §3.3 |
| No step writes a Principal out of band | ADR-IAM-001 §5.11 |

## Prerequisites

- Go (the toolchain the `go` directive resolves; see the version note in `README.md`)
- PostgreSQL 15 or later
- The Atlas CLI
- Keycloak 26.x, run locally

Neither `psql` nor `atlas` is reliably on `PATH` on Windows, so both are overridable:

```powershell
$env:PSQL  = 'C:\Program Files\PostgreSQL\15\bin\psql.exe'
$env:ATLAS = 'D:\Atlas\atlas.exe'
```

On a network where `proxy.golang.org` is unreachable, set `GOPROXY=direct`.

## 1. Choose credentials

Every script reads its passwords from the environment and defaults none of them. No client has a
secret: each authenticates with its own key by signed JWT (ADR-IAM-001 §5.12).
`scripts/dev-keycloak.ps1` makes the keys in `deploy/dev/keys`, which git ignores, with
identity-kernel's `client-key` tool from the sibling checkout.

```powershell
$env:PGPASSWORD               = '<postgres superuser password>'
$env:IDENTITY_APP_PASSWORD    = '<a password for the identity_app login role>'
$env:KC_ADMIN_PASSWORD        = '<keycloak bootstrap admin password>'
$env:IDENTITY_CALLER_PASSWORD = '<harness caller user password>'
```

## 2. Start Keycloak

Development mode only. It runs HTTP without TLS and with a relaxed hostname policy, both of
which STD-IAM-001 forbids in any environment that holds real credentials.

```powershell
$env:KC_BOOTSTRAP_ADMIN_USERNAME = 'admin'
$env:KC_BOOTSTRAP_ADMIN_PASSWORD = $env:KC_ADMIN_PASSWORD
$env:KC_DB                       = 'postgres'
$env:KC_DB_URL                   = 'jdbc:postgresql://127.0.0.1:5432/keycloak_dev'
$env:KC_DB_USERNAME              = 'postgres'
$env:KC_DB_PASSWORD              = $env:PGPASSWORD

# Port 8081, because 8080 is identity-control's own default.
& <keycloak>/bin/kc.bat start-dev --http-port=8081
```

Create `keycloak_dev` first if it does not exist. Keycloak does not create its own database.

## 3. Configure the realm

The realm belongs to `identity-kernel`, so it is applied from that repository's definition. This
is the same source the development server's realm comes from:

```powershell
cd ../identity-kernel            # a clean checkout: realm-apply records the commit it applied
$env:KEYCLOAK_ADMIN_USER     = 'admin'
$env:KEYCLOAK_ADMIN_PASSWORD = $env:KC_ADMIN_PASSWORD
go run ./cmd/realm-apply -environment local -url http://127.0.0.1:8081 -apply
cd ../identity-control
```

That creates the realm with its **PS256 / 3072-bit** signing key, the `scnehaux_*` user
attributes, and the `scnehaux-provider` scope this service's callers need (STD-IAM-002 §3.2.1). A
realm an earlier version of this harness built is one `realm-apply` never applied, and it refuses
it; add `-adopt` once to take it over.

Then register this service's two clients against it:

```powershell
./scripts/dev-keycloak.ps1
```

This registers the service client, with `manage-users` and `view-users` only, and the harness
caller: Authorization Code with PKCE, the provider scope attached, `identity-control` in `aud`,
and a 240-second token. It removes the client-management roles an earlier version granted.

It creates no user. Issuing a `principal_id` is the Identity Control Service's authority and
nothing else's, per `ADR-IAM-001 §5.11`, so the first Principal comes from the ceremony in step 5.

Two settings the realm needs are not optional, and both were found by running the service rather
than by reading the configuration. `identity-kernel`'s `compat/` now asserts both on every release:

- **The signing key.** A fresh realm is provisioned with a 2048-bit RS256 key. The verifier
  permits exactly one algorithm, so every token signed with the default key is rejected. FAPI 2.0
  prohibits RS256 and ADR-IAM-002 follows it.
- **The attribute declaration.** Keycloak 24+ discards user attributes the user profile does not
  declare, and it does so without an error. The create call succeeds, the attribute never lands,
  and the symptom appears three steps later as a token with no `principal_id`.

## 4. Build the control database

```powershell
./scripts/dev-database.ps1
```

This runs the same four-source pipeline a deployment runs, in the same order, then asserts the
resulting privilege shape against the live database rather than trusting the grants ran.

The order is load-bearing. `grants.sql` opens with a guard that raises if the objects it grants
on are absent, because an earlier version of this pipeline ran it before Atlas and it granted
nothing at all — silently, with no error and no privileges.

The registry is left empty. This script writes no Principal.

## 5. Perform the bootstrap ceremony

```powershell
./scripts/dev-bootstrap.ps1 -Operator 'you@example.com' -Reason 'initial local stand-up'
```

This is the entry point into a realm with no Principals. `POST /v1/principals` requires a caller
holding a `principal_id` and is the only path that issues one, so without the ceremony the API
cannot be reached at all. `ADR-IAM-001 §5.11` records the decision and why a standing break-glass
identity was rejected.

The command prints the identifier and then something that reads like a failure but is not:

```text
This Principal owes a credential. It cannot authenticate until the kernel's
credential-setting action is completed; this command never held one.
```

That is the point. The kernel user is created with `UPDATE_PASSWORD` outstanding, so the first
human interaction establishes the credential and no process in the estate ever holds one.

**Step 2 of that script is development only**, and it is separated in the output for that reason.
It sets a password and clears the required action, because direct access grant is the only way to
get a token without a browser and Keycloak refuses one to an account with a pending action. A real
operator completes the credential through the kernel's own flow instead.

The ceremony can succeed at most once per Control Database, and this is worth seeing:

```powershell
# refused, and it shows you who is on record
./scripts/dev-bootstrap.ps1

# refused: the recorded operator cannot be guessed from the flags
go run ./cmd/identity-bootstrap -operator x -reason y -username z -resume 'someone@else.com'

# permitted, and returns the same principal_id with no second kernel call
go run ./cmd/identity-bootstrap -operator ignored -reason ignored `
    -username bootstrap-operator -resume 'you@example.com'
```

The record itself cannot be rewritten, including by the application:

```powershell
# ERROR: permission denied for table bootstrap_ceremony
psql -U identity_app -d identity_control_dev `
    -c "UPDATE identity.bootstrap_ceremony SET operator='someone else' WHERE id=1;"
```

## 6. Run the service

```powershell
$env:IDENTITY_DATABASE_URL           = "postgres://identity_app:$($env:IDENTITY_APP_PASSWORD)@127.0.0.1:5432/identity_control_dev?sslmode=disable"
$env:IDENTITY_LISTEN_ADDRESS         = ':8090'
$env:IDENTITY_KEYCLOAK_REALM         = 'scnehaux'
$env:IDENTITY_KEYCLOAK_BASE_URL      = 'http://127.0.0.1:8081'
$env:IDENTITY_KEYCLOAK_CLIENT_ID     = 'identity-control'
$env:IDENTITY_KEYCLOAK_CLIENT_KEY_FILE = (Resolve-Path deploy/dev/keys/identity-control.pem).Path
$env:IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_ID       = 'identity-control-registration'
$env:IDENTITY_REGISTRATION_KEYCLOAK_CLIENT_KEY_FILE = (Resolve-Path deploy/dev/keys/identity-control-registration.pem).Path
$env:IDENTITY_TOKEN_ISSUER           = 'http://127.0.0.1:8081/realms/scnehaux'
$env:IDENTITY_TOKEN_AUDIENCE         = 'identity-control'
$env:IDENTITY_JWKS_URL               = 'http://127.0.0.1:8081/realms/scnehaux/protocol/openid-connect/certs'
$env:LOG_LEVEL                       = 'debug'

go run ./cmd/identity-control
```

The service connects as `identity_app`, which inherits `identity_runtime`: DML and no DDL. A
migration attempted through this pool fails at the database rather than succeeding quietly.

`IDENTITY_JWKS_URL` is configuration and is never read from a token. A token that could name its
own key source would choose the key that validates it.

## 7. Exercise it

```powershell
$env:IDENTITY_CALLER_KEY_FILE = (Resolve-Path deploy/dev/keys/identity-control-caller.pem).Path
./scripts/dev-smoke.ps1
```

Expected output, abbreviated:

```
token: alg=PS256 principal_id=01a01526-... aud=identity-control,account lifetime=900s

1. unauthenticated mutation
  ok    refused (401)
2. probes without a credential
  ok    /healthz (200)
  ok    /readyz (200)
3. create a human Principal
  ok    created (201)
        {"principal_id":"01a0152a-...","subject_type":"human","realm":"scnehaux"}
4. replay the same Idempotency-Key
  ok    created (201)
  ok    identifier is unchanged
...
all cases passed.
```

## 8. Provider authority from Organization Control

Until this is done, the ceremony's Principal is the only provider, and no activation is honored
(`TDD-identity-control-006` §Operational Notes). It wires the three local services together:

```text
Organization Control ──deliveries, as organization-control-workload──▶ identity-control /v1/deliveries
identity-control ──snapshot, frontier, progress, as identity-control-workload──▶ Organization Control
```

Each arrow is a workload token from the kernel, whose `aud` is the other side's resource
registration (STD-IAM-002 §3.1). The order matters: Organization Control's own records are made
while it still verifies the dev issuer, and it is switched to the kernel only once they exist.

**Before you start.** identity-control runs with `IDENTITY_TOKEN_AUDIENCE=identity-control-api`
(§5), Organization Control runs locally on `127.0.0.1:8099` with `make issuer` beside it, and
`ORGANIZATION_TOKEN_AUDIENCE=organization-control-api` is in its `.env`.

### 8.1 Two workload keys

From the identity-kernel checkout, so each private key is made on this machine and only its public
JWK is sent anywhere (ADR-IAM-001 §5.12):

```powershell
$keys = (Resolve-Path ..\identity-control\deploy\dev\keys).Path
go run ./cmd/client-key new -out "$keys\organization-control-workload.pem"
go run ./cmd/client-key new -out "$keys\identity-control-workload.pem"
```

### 8.2 Register the resource and the workloads in identity-control

With a provider token from the running identity-control:

```powershell
. ./scripts/dev-token.ps1
$token = Get-ScnehauxToken -Username bootstrap-operator -Password $env:IDENTITY_CALLER_PASSWORD -KeyFile $env:IDENTITY_CALLER_KEY_FILE
$api = "http://127.0.0.1:8097"
function Send($method, $path, $body, $key) {
    $h = @{ Authorization = "Bearer $token"; "X-Administrative-Reason" = "wire provider authority locally" }
    if ($key) { $h["Idempotency-Key"] = $key }
    Invoke-RestMethod -Method $method -Uri "$api$path" -Headers $h -ContentType "application/json" -Body $body
}
$me = (Send GET "/v1/registrations:standing" $null $null)   # confirms the token is a provider's
```

Organization Control's resource, keyless (`TDD-organization-control-001` §Caller Authority):

```powershell
Send POST "/v1/registrations" '{"client_key":"organization-control-api","profile":"resource","audience_class":"privileged","application_ref":"organization-control","lifetime_class":"L0"}' "local-oc-resource"
```

The two workloads (`TDD-identity-control-004`), owned by the ceremony's Principal, each with the
other side's resource as its audience:

```powershell
$owner = "<bootstrap-operator's principal_id, from the ceremony's output>"
function Workload($key, $app, $audience, $purpose) {
    $jwk = Get-Content "$keys\$key.jwk.json" -Raw | ConvertFrom-Json
    $body = @{ display_name = $key; purpose = $purpose; workload_type = "service"; owner_principal_id = $owner
        client_key = $key; application_ref = $app; audience = @($audience); public_key = $jwk } | ConvertTo-Json -Depth 4 -Compress
    Send POST "/v1/workloads" $body "local-$key"
}
$oc = Workload "organization-control-workload" "organization-control" "identity-control-api" "Delivers provider grant events to the Identity Control API (ADR-GLB-018 §5.4)"
$ic = Workload "identity-control-workload" "identity-control" "organization-control-api" "Reads Organization Control's provider authority snapshot and frontier (TDD-identity-control-006)"
"organization-control-workload principal_id: $($oc.principal_id)"
"identity-control-workload     principal_id: $($ic.principal_id)"
```

### 8.3 Organization Control's records, while it still verifies the dev issuer

With `make token` (the dev provider) in the Organization Control checkout, and each body in a file.
`make api` sends the `X-Administrative-Reason` the provider routes require. If it answers `403`, the
dev provider holds no grant on this database: grant it once with `organization-control
bootstrap-provider`, as Organization Control's README §Driving the service by hand describes.

- `provider-grant.json`, an emergency `provider:identity-control` grant for the ceremony's
  Principal. Projected, it retires the ceremony's grant (`TDD-identity-control-006` §The Ceremony's
  Grant), and the Principal stays a provider through Organization's record:

  ```json
  {"principal_id":"<bootstrap-operator>","scope":"provider:identity-control","kind":"emergency"}
  ```

  `make api M=POST P=/v1/provider-grants B=provider-grant.json KEY=local-grant-ic`

- `consumer.json`, identity-control as a projection consumer, its principal the workload from 8.2
  (`TDD-identity-control-006` §Registration with Organization Control):

  ```json
  {"consumer_id":"identity-control","principal_id":"<identity-control-workload principal_id>",
   "projection_version":"v1","max_accepted_age_seconds":60,"stale_behavior":"fail_closed",
   "event_types":["com.scnehaux.organization.provider.lifecycle.granted","com.scnehaux.organization.provider.lifecycle.activated",
                  "com.scnehaux.organization.provider.security.ended","com.scnehaux.organization.provider.security.revoked"]}
  ```

  `make api M=POST P=/v1/projections/consumers B=consumer.json KEY=local-consumer-ic`

### 8.4 Switch Organization Control to the kernel

In its `.env`, then restart it (`make run`); `make issuer` is no longer needed:

```text
ORGANIZATION_TOKEN_ISSUER=http://127.0.0.1:8081/realms/scnehaux
ORGANIZATION_JWKS_URL=http://127.0.0.1:8081/realms/scnehaux/protocol/openid-connect/certs
ORGANIZATION_TOKEN_AUDIENCE=organization-control-api
ORGANIZATION_DELIVERY_TARGETS=identity-control=http://127.0.0.1:8097/v1/deliveries
ORGANIZATION_WORKLOAD_CLIENT_ID=organization-control-workload
ORGANIZATION_WORKLOAD_KEY_FILE=<absolute path to organization-control-workload.pem>
ORGANIZATION_WORKLOAD_TOKEN_URL=http://127.0.0.1:8081/realms/scnehaux/protocol/openid-connect/token
```

`ORGANIZATION_CONSUMER_DATABASE_URL` and `ORGANIZATION_DISPATCH_DATABASE_URL` must be set as
`.env.example` shows: the first admits identity-control's workload to the consumer routes, the
second runs the dispatcher.

### 8.5 Point identity-control at Organization Control

In its `.env`, then restart it (`make run`):

```text
IDENTITY_DELIVERY_PRINCIPAL_ID=<organization-control-workload principal_id>
IDENTITY_ORGANIZATION_BASE_URL=http://127.0.0.1:8099
IDENTITY_WORKLOAD_CLIENT_ID=identity-control-workload
IDENTITY_WORKLOAD_KEY_FILE=deploy/dev/keys/identity-control-workload.pem
IDENTITY_WORKLOAD_TOKEN_URL=http://127.0.0.1:8081/realms/scnehaux/protocol/openid-connect/token
IDENTITY_WORKLOAD_AUDIENCE=http://127.0.0.1:8081/realms/scnehaux
```

Then build the projection from the snapshot: `make provider-bootstrap`.

### 8.6 What you should see

- identity-control logs `the provider projection is fresh` within 15 seconds.
- Organization Control's dispatcher delivers the grant from 8.3; `identity.ceremony_grant_retirement`
  holds one row naming it, and the ceremony's Principal is a provider by `emergency` from now on
  (each request logs `emergency provider authority used`).
- Stopping Organization Control makes identity-control log the projection stale within a minute;
  the emergency grant still authorizes, an activation would not.

## Known limits of this harness

- **Setting the bootstrap credential is not a production step.** Step 2 of `dev-bootstrap.ps1`
  sets a password and clears `UPDATE_PASSWORD`. The ceremony itself is a production procedure and
  holds no credential; this step is the harness standing in for a human completing the kernel's
  credential flow.

  Earlier versions of this document listed the first Principal as a design gap, because
  `dev-keycloak.ps1` minted one out of band and `dev-database.ps1` inserted the row directly.
  Both are gone: `ADR-IAM-001 §5.11` decided the ceremony and `cmd/identity-bootstrap` implements
  it, so no step in this harness writes a Principal the authority did not issue.

- **No direct access grant.** An earlier version of this harness used one and cited a prohibition
  in STD-IAM-001 §3.2 that did not exist. The standard now prohibits the grant for every client,
  and the grant could not have produced a conformant `privileged` token anyway: `auth_time` exists
  only for an authentication ceremony, and a direct grant has none.

  `scripts/dev-token.ps1` performs Authorization Code with PKCE `S256` against the kernel's own
  login form, without a browser. One deviation remains inside it and is commented there: Keycloak
  marks its login cookies `Secure`, a browser accepts them on `http://localhost` because that is a
  secure context by specification, and `System.Net.CookieContainer` implements no such exception.
  The script re-adds them with the flag cleared. Over a real network the cookies stay `Secure` and
  that code path is never reached.

- **No TLS anywhere.** Keycloak in dev mode, `sslmode=disable` on both DSNs. Correct for a
  loopback harness and forbidden by STD-GLB-005 for anything else. It is also the reason for the
  cookie handling noted above.

- **No broker.** Week 3 adds event consumption and the Keycloak context projection, which needs
  Kafka. Nothing in this harness publishes or consumes.
