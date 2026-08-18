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

Every script reads its secrets from the environment and defaults none of them. Nothing below is
written to a file, which is why the scripts can live in the repository.

```powershell
$env:PGPASSWORD               = '<postgres superuser password>'
$env:IDENTITY_APP_PASSWORD    = '<a password for the identity_app login role>'
$env:KC_ADMIN_PASSWORD        = '<keycloak bootstrap admin password>'
$env:IDENTITY_CONTROL_SECRET  = '<the service Admin API client secret>'
$env:IDENTITY_CALLER_SECRET   = '<harness caller client secret>'
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

```powershell
./scripts/dev-keycloak.ps1
```

This creates the realm, adds a **PS256 / 3072-bit** signing key, declares the three
`scnehaux_*` user attributes, creates both clients with their protocol mappers, and mints the
bootstrap caller. It prints the bootstrap Principal identifier; carry it to the next step.

Two of those steps are not optional, and both were found by running the service rather than by
reading the configuration:

- **The signing key.** A fresh realm is provisioned with a 2048-bit RS256 key. The verifier
  permits exactly one algorithm, so every token signed with the default key is rejected. FAPI 2.0
  prohibits RS256 and ADR-IAM-002 follows it.
- **The attribute declaration.** Keycloak 24+ discards user attributes the user profile does not
  declare, and it does so without an error. The create call succeeds, the attribute never lands,
  and the symptom appears three steps later as a token with no `principal_id`.

## 4. Build the control database

```powershell
$env:BOOTSTRAP_PRINCIPAL_ID = '<printed by step 3>'
$env:BOOTSTRAP_KEYCLOAK_ID  = '<printed by step 3>'
./scripts/dev-database.ps1 -SeedBootstrapPrincipal
```

This runs the same four-source pipeline a deployment runs, in the same order, then asserts the
resulting privilege shape against the live database rather than trusting the grants ran.

The order is load-bearing. `grants.sql` opens with a guard that raises if the objects it grants
on are absent, because an earlier version of this pipeline ran it before Atlas and it granted
nothing at all — silently, with no error and no privileges.

## 5. Run the service

```powershell
$env:IDENTITY_DATABASE_URL           = "postgres://identity_app:$($env:IDENTITY_APP_PASSWORD)@127.0.0.1:5432/identity_control_dev?sslmode=disable"
$env:IDENTITY_LISTEN_ADDRESS         = ':8090'
$env:IDENTITY_KEYCLOAK_REALM         = 'scnehaux'
$env:IDENTITY_KEYCLOAK_BASE_URL      = 'http://127.0.0.1:8081'
$env:IDENTITY_KEYCLOAK_CLIENT_ID     = 'identity-control'
$env:IDENTITY_KEYCLOAK_CLIENT_SECRET = $env:IDENTITY_CONTROL_SECRET
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

## 6. Exercise it

```powershell
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

## Known limits of this harness

- **The first Principal cannot be created through the sanctioned path.**
  TDD-identity-control-001 closes every creation path except `POST /v1/principals`, and that
  endpoint requires a caller who already holds a `principal_id`. So `dev-keycloak.ps1` mints one
  out-of-band and `dev-database.ps1 -SeedBootstrapPrincipal` records it, which is precisely the
  out-of-band creation the design prohibits. This is a real gap in the design, not a shortcut in
  the harness: the estate needs a designed bootstrap — a break-glass identity, or an
  operator-initiated first-Principal ceremony with a recorded approval. Carried in `ROADMAP.md`.

- **Direct access grant is enabled on `identity-control-caller`.** It is the only way to get a
  token without a browser. STD-IAM-001 §3.2 forbids the flow outside development, and the client
  name says so.

- **No TLS anywhere.** Keycloak in dev mode, `sslmode=disable` on both DSNs. Correct for a
  loopback harness and forbidden by STD-GLB-005 for anything else.

- **No broker.** Week 3 adds event consumption and the Keycloak context projection, which needs
  Kafka. Nothing in this harness publishes or consumes.
