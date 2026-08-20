// Declarative desired state for the `identity` schema, per ADR-GLB-004.
//
// SCOPE: this file describes the `identity` schema and nothing else. The `platform`
// schema is NOT declared here, and that omission is deliberate rather than incomplete.
// `platform` ships inside foundation-platform as versioned SQL and is applied by
// `cmd/identity-migrate`. Re-authoring it in HCL would fork the schema away from the Go
// code that queries it, which is the single failure the shared module exists to prevent:
// a column added to `platform.outbox` and a change to `outbox.Append` are one change.
//
// `atlas.hcl` therefore scopes every Atlas command to `identity` through a `search_path`
// on both urls. That scope is load-bearing rather than tidy: the first generated plan,
// produced in database scope, ended with `DROP SCHEMA "public" CASCADE` because `public`
// was undeclared here. Unscoped, the same reasoning would drop `platform`.
//
// The schema block therefore carries no attributes. A schema-scoped plan may not modify
// the schema it is scoped to, so the `identity` schema itself — and its comment — are
// created by `identity-migrate -stage=pre`, exactly as `platform` is. Atlas owns the
// objects inside the schema and not the schema object.

schema "identity" {
}

// The canonical Principal identifier and its binding to a Keycloak user.
//
// Keycloak enforces no uniqueness on user attributes, so the uniqueness invariant for
// `principal_id` is held here and nowhere else. `keycloak_user_id` is nullable while the
// mapping is `pending` — the row is written before the Admin API call so a crash between
// the call and the local commit leaves a recoverable checkpoint rather than an orphan.
table "principal_mapping" {
  schema  = schema.identity
  comment = "Canonical principal_id to Keycloak user mapping. TDD-identity-control-001."

  column "principal_id" {
    null    = false
    type    = uuid
    comment = "UUIDv7 minted by the Control Plane. The enterprise-wide reference."
  }

  column "keycloak_user_id" {
    null    = true
    type    = text
    comment = "Null while pending. Never leaves this module; absent from every response body."
  }

  column "realm" {
    null = false
    type = text
  }

  // The creation payload, held so a pending row can reconstruct its own kernel call.
  //
  // TDD-identity-control-001 specifies that recovery retries the create when the kernel
  // holds no matching user. Without these two columns that branch cannot be written: the
  // pending row would name an identifier and nothing else, and the caller's idempotency
  // key would stay in-progress forever with no path out. Recorded as a departure in that
  // design.
  //
  // These are Tier-2 identifiable PII under STD-GLB-007 and are encrypted at rest with the
  // rest of the Control Database. They are the payload of a call this service makes, not a
  // second authority for identity attributes: Keycloak owns the live values, and a change
  // made there is not reflected here.
  column "username" {
    null    = false
    type    = text
    comment = "Creation payload. Recovery reconstructs the kernel call from it; it is not the authoritative username."
  }

  column "email" {
    null = true
    type = text
  }

  column "subject_type" {
    null = false
    type = text
  }

  column "workload_owner" {
    null    = true
    type    = uuid
    comment = "The accountable human Principal. Required for a workload, prohibited for a human."
  }

  column "state" {
    null = false
    type = text
  }

  column "created_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  column "activated_at" {
    null = true
    type = timestamptz
  }

  column "quarantined_at" {
    null = true
    type = timestamptz
  }

  column "quarantine_reason" {
    null = true
    type = text
  }

  column "version" {
    null    = false
    type    = integer
    default = 1
  }

  primary_key {
    columns = [column.principal_id]
  }

  // Global uniqueness of the Keycloak identifier. PostgreSQL treats NULLs as distinct,
  // so this permits many pending rows while forbidding two mappings onto one user.
  index "principal_mapping_keycloak_user_id_key" {
    unique  = true
    columns = [column.keycloak_user_id]
  }

  // Named as a Week 1 deliverable by ROADMAP.md. It is implied by the constraint above
  // and is carried because TDD-identity-control-001 specifies both; the redundancy is
  // recorded in ROADMAP.md rather than silently resolved here.
  index "principal_mapping_realm_user" {
    unique  = true
    columns = [column.realm, column.keycloak_user_id]
    where   = "keycloak_user_id IS NOT NULL"
  }

  check "principal_mapping_state_check" {
    expr = "state IN ('pending', 'active', 'quarantined', 'retired')"
  }

  check "principal_mapping_subject_check" {
    expr = "subject_type IN ('human', 'workload')"
  }

  // Accountability is structural: a workload row cannot exist without a named owner,
  // and a human row cannot carry one. A workload whose owner nobody recorded is a
  // credential nobody will ever decide to revoke.
  check "principal_mapping_owner_check" {
    expr = "(subject_type = 'human' AND workload_owner IS NULL) OR (subject_type = 'workload' AND workload_owner IS NOT NULL)"
  }
}

// The record of the one ceremony that created the first Principal.
//
// `POST /v1/principals` requires a caller holding a principal_id and is the only path that
// issues one, so a fresh realm has no entry point. This table is how the ceremony that provides
// one is bounded. ADR-IAM-001 §5.8 and TDD-identity-control-001 carry the decision.
//
// Every guarantee here is structural rather than procedural, because a procedure is what gets
// skipped under deployment pressure.
table "bootstrap_ceremony" {
  schema  = schema.identity
  comment = "The single bootstrap ceremony record. Insert-only. ADR-IAM-001 §5.8."

  // `id = 1` under a primary key is what makes the ceremony single-use. A count() in Go would
  // be a check the next refactor could drop, and would race two concurrent ceremonies into two
  // Principals; a constraint refuses the second unconditionally.
  column "id" {
    null = false
    type = integer
  }

  column "operator" {
    null    = false
    type    = text
    comment = "The human who ran the ceremony. Not the process, and not a service account."
  }

  column "reason" {
    null = false
    type = text
  }

  // Held in the row rather than generated per invocation. A ceremony that crashed after the
  // kernel call resumes against the same key, so the API's existing recovery path applies and a
  // retry cannot mint a second Principal.
  column "idempotency_key" {
    null = false
    type = text
  }

  column "requested_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  primary_key {
    columns = [column.id]
  }

  check "bootstrap_ceremony_single_row" {
    expr = "id = 1"
  }

  check "bootstrap_ceremony_operator_named" {
    expr = "btrim(operator) <> '' AND btrim(reason) <> ''"
  }
}

// This service's own consumer position. The publisher registry lives in the Organization
// Database and is never read from here.
table "projection_cursor" {
  schema  = schema.identity
  comment = "Per-stream consumer watermark. TDD-identity-control-002."

  column "stream" {
    null = false
    type = text
  }

  column "projection_version" {
    null = false
    type = text
  }

  // An observability watermark, not a delivery checkpoint. The priority lane may deliver
  // a later position before an earlier lifecycle event, so delivery progress belongs to
  // the durable broker consumer and deduplication identity stays event_id in
  // platform.processed_event.
  column "max_applied_stream_position" {
    null    = false
    type    = bigint
    default = 0
  }

  column "last_snapshot_mark" {
    null = true
    type = bigint
  }

  column "last_reconciled_at" {
    null = true
    type = timestamptz
  }

  primary_key {
    columns = [column.stream]
  }
}
