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
| No step writes a Principal out of band | ADR-ORG-001 §5.3 |

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
`scnehaux_*` user attributes, and creates both clients with their protocol mappers.

It creates no user. Issuing a `principal_id` is the Identity Control Service's authority and
nothing else's, per `ADR-IAM-001 §5.11`, so the first Principal comes from the ceremony in step 5.

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

## 7. Exercise it

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

- **Setting the bootstrap credential is not a production step.** Step 2 of `dev-bootstrap.ps1`
  sets a password and clears `UPDATE_PASSWORD`. The ceremony itself is a production procedure and
  holds no credential; this step is the harness standing in for a human completing the kernel's
  credential flow.

  Earlier versions of this document listed the first Principal as a design gap, because
  `dev-keycloak.ps1` minted one out of band and `dev-database.ps1` inserted the row directly.
  Both are gone: `ADR-IAM-001 §5.11` decided the ceremony and `cmd/identity-bootstrap` implements
  it, so no step in this harness writes a Principal the authority did not issue.

- **Direct access grant is enabled on `identity-control-caller`.** It is the only way to get a
  token without a browser. STD-IAM-001 §3.2 forbids the flow outside development, and the client
  name says so.

- **No TLS anywhere.** Keycloak in dev mode, `sslmode=disable` on both DSNs. Correct for a
  loopback harness and forbidden by STD-GLB-005 for anything else.

- **No broker.** Week 3 adds event consumption and the Keycloak context projection, which needs
  Kafka. Nothing in this harness publishes or consumes.
