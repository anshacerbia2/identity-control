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
    expr = "state IN ('pending', 'active', 'suspended', 'quarantined', 'retired')"
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

  // An active mapping with no Keycloak user is served by nothing and recovered by nothing, because
  // recovery reads only pending rows. Pending is the one state where the user may be absent, and
  // :relink is how an active mapping whose user is gone gets back there (TDD-identity-control-001).
  check "principal_mapping_active_linked_check" {
    expr = "state <> 'active' OR keycloak_user_id IS NOT NULL"
  }
}

// Every relink: who returned an active mapping to pending, why, and which Keycloak user it lost.
// Insert-only (grants.sql): a Principal's link to a new Keycloak user is exactly the kind of change
// whose record must not be rewritable by the process that made it.
table "principal_relink" {
  schema  = schema.identity
  comment = "Each relink of an active mapping back to pending. Insert-only. TDD-identity-control-001."

  column "relink_id" {
    null = false
    type = uuid
  }

  column "principal_id" {
    null = false
    type = uuid
  }

  column "previous_keycloak_user_id" {
    null = false
    type = text
  }

  column "relinked_by" {
    null = false
    type = uuid
  }

  column "reason" {
    null = false
    type = text
  }

  column "relinked_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  primary_key {
    columns = [column.relink_id]
  }

  foreign_key "principal_relink_principal_id_fkey" {
    columns     = [column.principal_id]
    ref_columns = [table.principal_mapping.column.principal_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  check "principal_relink_reason_named" {
    expr = "btrim(reason) <> ''"
  }
}

// A Principal whose Keycloak user no longer exists. The sweep records it and never relinks it: a
// user deleted on purpose must not come back by itself.
table "principal_finding" {
  schema  = schema.identity
  comment = "A dangling mapping: an active Principal whose Keycloak user is gone. TDD-identity-control-001."

  column "finding_id" {
    null = false
    type = uuid
  }

  column "principal_id" {
    null = false
    type = uuid
  }

  column "finding_class" {
    null = false
    type = text
  }

  column "keycloak_user_id" {
    null    = false
    type    = text
    comment = "The user the mapping pointed at when it was found missing."
  }

  column "detected_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  column "resolved_at" {
    null = true
    type = timestamptz
  }

  column "resolution" {
    null = true
    type = text
  }

  primary_key {
    columns = [column.finding_id]
  }

  foreign_key "principal_finding_principal_id_fkey" {
    columns     = [column.principal_id]
    ref_columns = [table.principal_mapping.column.principal_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  // One open finding per Principal: a later sweep that still finds the user missing keeps it.
  index "principal_finding_open" {
    unique  = true
    columns = [column.principal_id]
    where   = "resolved_at IS NULL"
  }

  check "principal_finding_class_check" {
    expr = "finding_class IN ('dangling')"
  }

  check "principal_finding_resolution_check" {
    expr = "(resolved_at IS NULL) = (resolution IS NULL) AND (resolution IS NULL OR resolution IN ('relinked', 'user_present'))"
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

  // Minted when the row is claimed, so the insert-only row names the Principal the ceremony
  // creates and a resumed ceremony creates the same one. The Principal is the ceremony's local
  // emergency grant (TDD-identity-control-006 §The Ceremony's Grant). Null only on a row claimed
  // before this column whose Principal was never created: that row's grant names no one.
  column "principal_id" {
    null    = true
    type    = uuid
    comment = "The ceremony's Principal: its local emergency grant until ceremony_grant_retirement. TDD-identity-control-006."
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

// Desired state for one protocol client or protected resource. TDD-identity-control-003.
//
// The reconciler applies whatever this row says, so it is a security control in its own right:
// written only through the registration API, every write carrying an accountable registered_by and
// a new version. A retired row is kept, which is why the runtime role holds no DELETE on it
// (grants.sql), and client_registration_key releases its client_key for reuse instead.
table "client_registration" {
  schema  = schema.identity
  comment = "Desired state for a protocol client or protected resource. TDD-identity-control-003."

  column "registration_id" {
    null = false
    type = uuid
  }

  column "kc_client_id" {
    null    = true
    type    = text
    comment = "Keycloak's internal client id. Null while pending."
  }

  column "realm" {
    null = false
    type = text
  }

  column "client_key" {
    null    = false
    type    = text
    comment = "The clientId as Keycloak and every caller name it."
  }

  column "profile" {
    null = false
    type = text
  }

  column "application_authority" {
    null = false
    type = text
  }

  column "application_ref" {
    null = false
    type = text
  }

  column "registered_by" {
    null    = false
    type    = uuid
    comment = "The accountable Principal. While application_authority is manual, accountability rests here."
  }

  column "audience_class" {
    null = false
    type = text
  }

  column "signing_algorithm" {
    null    = false
    type    = text
    default = "PS256"
  }

  column "algorithm_exception_owner" {
    null = true
    type = uuid
  }

  column "algorithm_exception_reason" {
    null = true
    type = text
  }

  column "algorithm_exception_expires_at" {
    null = true
    type = timestamptz
  }

  column "lifetime_class" {
    null = true
    type = text
  }

  column "audience" {
    null = true
    type = sql("text[]")
  }

  column "redirect_uris" {
    null = true
    type = sql("text[]")
  }

  column "state" {
    null = false
    type = text
  }

  column "version" {
    null    = false
    type    = bigint
    default = 1
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

  column "suspended_at" {
    null = true
    type = timestamptz
  }

  column "retired_at" {
    null = true
    type = timestamptz
  }

  primary_key {
    columns = [column.registration_id]
  }

  index "client_registration_kc_client_id_key" {
    unique  = true
    columns = [column.kc_client_id]
  }

  // A retired registration keeps its record and releases its key.
  index "client_registration_key" {
    unique  = true
    columns = [column.realm, column.client_key]
    where   = "state <> 'retired'"
  }

  check "client_profile_check" {
    expr = "profile IN ('confidential', 'public', 'workload', 'resource')"
  }

  check "client_audience_class_check" {
    expr = "audience_class IN ('internal', 'privileged', 'workload', 'external')"
  }

  check "client_signing_algorithm_check" {
    expr = "signing_algorithm IN ('PS256', 'RS256')"
  }

  // STD-IAM-002 §3.2.2: PS256 is the baseline, and RS256 exists only as an external
  // compatibility exception with a named owner, a reason, and an expiry.
  check "client_algorithm_profile_check" {
    expr = "(signing_algorithm = 'PS256' AND algorithm_exception_owner IS NULL AND algorithm_exception_reason IS NULL AND algorithm_exception_expires_at IS NULL) OR (signing_algorithm = 'RS256' AND audience_class = 'external' AND algorithm_exception_owner IS NOT NULL AND algorithm_exception_reason IS NOT NULL AND algorithm_exception_expires_at > created_at)"
  }

  check "client_workload_audience_check" {
    expr = "profile <> 'workload' OR audience_class = 'workload'"
  }

  check "client_state_check" {
    expr = "state IN ('pending', 'active', 'suspended', 'retired')"
  }

  // STD-IAM-002 §3.3 in the database: a protected resource without a lifetime class cannot be
  // stored, so no migration or repair script can create the one resource whose token lifetime
  // nobody chose.
  check "client_lifetime_class_required" {
    expr = "profile <> 'resource' OR lifetime_class IS NOT NULL"
  }

  check "client_lifetime_class_check" {
    expr = "lifetime_class IS NULL OR lifetime_class IN ('L0', 'L1', 'L2', 'L3')"
  }
}

// One reconciliation sweep. The last run is how the reconciler is observed: a run that never
// finished has a null outcome, and 'unresolved' is an outcome, not a missing one.
table "reconcile_run" {
  schema  = schema.identity
  comment = "One reconciliation sweep and its outcome. TDD-identity-control-003."

  column "run_id" {
    null = false
    type = uuid
  }

  column "sweep" {
    null = false
    type = text
  }

  column "started_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  column "finished_at" {
    null = true
    type = timestamptz
  }

  column "outcome" {
    null = true
    type = text
  }

  column "attribution" {
    null    = true
    type    = boolean
    comment = "Whether the run could read admin events. Without them no divergence is repaired automatically."
  }

  column "findings" {
    null    = false
    type    = integer
    default = 0
  }

  primary_key {
    columns = [column.run_id]
  }

  index "reconcile_run_latest" {
    columns = [column.sweep, column.started_at]
  }

  check "reconcile_run_sweep_check" {
    expr = "sweep IN ('registration')"
  }

  check "reconcile_run_outcome_check" {
    expr = "outcome IS NULL OR outcome IN ('converged', 'drift', 'unresolved')"
  }

  check "reconcile_run_finished_check" {
    expr = "(finished_at IS NULL) = (outcome IS NULL)"
  }
}

// One divergence between desired state and a Keycloak client, kept after it converges: the record
// of a console change is the evidence that it happened.
table "registration_finding" {
  schema  = schema.identity
  comment = "One divergence between desired state and Keycloak, retained after convergence. TDD-identity-control-003."

  column "finding_id" {
    null = false
    type = uuid
  }

  column "run_id" {
    null = false
    type = uuid
  }

  column "registration_id" {
    null    = true
    type    = uuid
    comment = "Null for an unmanaged client, which no registration describes."
  }

  column "kc_client_id" {
    null = false
    type = text
  }

  column "field_class" {
    null = true
    type = text
  }

  column "finding_class" {
    null = false
    type = text
  }

  column "desired" {
    null = true
    type = jsonb
  }

  column "observed" {
    null = true
    type = jsonb
  }

  column "actor" {
    null    = true
    type    = text
    comment = "The Keycloak user the attributing admin event names. Null when the change is unattributed."
  }

  column "changed_at" {
    null    = true
    type    = timestamptz
    comment = "The attributing admin event's time. converged_at - changed_at is the convergence time."
  }

  column "detected_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  column "converged_at" {
    null = true
    type = timestamptz
  }

  column "resolved_by" {
    null    = true
    type    = uuid
    comment = "The Principal whose reconcile applied desired state to a blocked or unattributed finding."
  }

  column "resolution_reason" {
    null = true
    type = text
  }

  primary_key {
    columns = [column.finding_id]
  }

  foreign_key "registration_finding_run_id_fkey" {
    columns     = [column.run_id]
    ref_columns = [table.reconcile_run.column.run_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  foreign_key "registration_finding_registration_id_fkey" {
    columns     = [column.registration_id]
    ref_columns = [table.client_registration.column.registration_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  // One divergence has one finding: a later sweep that still sees it updates this row. NULLS NOT
  // DISTINCT because an unmanaged or recreated client has no field class, and with distinct nulls
  // every sweep would open another finding for the same client.
  index "registration_finding_open" {
    unique         = true
    columns        = [column.kc_client_id, column.field_class]
    where          = "converged_at IS NULL"
    nulls_distinct = false
  }

  check "registration_finding_field_check" {
    expr = "field_class IS NULL OR field_class IN ('redirect_uris', 'token_lifespan', 'audience_scope', 'signing_algorithm', 'profile', 'client_keys', 'suspension', 'token_format')"
  }

  check "registration_finding_class_check" {
    expr = "finding_class IN ('repaired', 'blocked', 'sanctioned', 'unattributed', 'missing', 'recreated', 'unmanaged')"
  }

  // An operator's resolution names who and why, or it is not one.
  check "registration_finding_resolution_check" {
    expr = "(resolved_by IS NULL) = (resolution_reason IS NULL) AND (resolution_reason IS NULL OR btrim(resolution_reason) <> '')"
  }
}

// A time-bound permission for one person to change one field class of one client in the console.
// Insert-only (grants.sql): an exception that could be extended after the fact is one nobody
// granted for that long.
table "drift_exception" {
  schema  = schema.identity
  comment = "A time-bound, insert-only permission for a console change. TDD-identity-control-003."

  column "exception_id" {
    null = false
    type = uuid
  }

  column "registration_id" {
    null = false
    type = uuid
  }

  column "field_class" {
    null = false
    type = text
  }

  column "actor" {
    null    = false
    type    = text
    comment = "The Keycloak user the admin event will name."
  }

  column "reason" {
    null = false
    type = text
  }

  column "granted_by" {
    null = false
    type = uuid
  }

  column "granted_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  column "expires_at" {
    null = false
    type = timestamptz
  }

  primary_key {
    columns = [column.exception_id]
  }

  foreign_key "drift_exception_registration_id_fkey" {
    columns     = [column.registration_id]
    ref_columns = [table.client_registration.column.registration_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  check "drift_exception_field_check" {
    expr = "field_class IN ('redirect_uris', 'token_lifespan', 'audience_scope', 'signing_algorithm', 'profile')"
  }

  check "drift_exception_named_check" {
    expr = "btrim(actor) <> '' AND btrim(reason) <> ''"
  }

  check "drift_exception_window_check" {
    expr = "expires_at > granted_at AND expires_at <= granted_at + interval '24 hours'"
  }
}

// A confidential or workload client's public keys (ADR-IAM-001 §5.12). The client generated the
// pair and keeps the private half; this table holds the public half only, and refuses anything
// else. The kernel client's JWKS is rebuilt from the active and retiring rows, so this table is
// desired state for the keys. A key is never rewritten or deleted: a new key is a new row, and a
// revoked one stays the record of which key pair stopped authenticating the client.
table "client_key" {
  schema  = schema.identity
  comment = "A registered public key of a confidential or workload client. TDD-identity-control-003."

  column "key_id" {
    null = false
    type = uuid
  }

  column "registration_id" {
    null = false
    type = uuid
  }

  column "kid" {
    null    = false
    type    = text
    comment = "The key identifier the client's assertions name. Defaults to the thumbprint."
  }

  column "thumbprint" {
    null    = false
    type    = text
    comment = "RFC 7638 SHA-256 thumbprint. Unique across every client, revoked keys included."
  }

  column "public_jwk" {
    null = false
    type = jsonb
  }

  column "state" {
    null = false
    type = text
  }

  column "registered_by" {
    null = false
    type = uuid
  }

  column "registered_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  column "expires_at" {
    null = false
    type = timestamptz
  }

  column "retiring_at" {
    null    = true
    type    = timestamptz
    comment = "When a retiring key's rotation overlap ends and it is removed."
  }

  column "revoked_at" {
    null = true
    type = timestamptz
  }

  column "revoked_by" {
    null    = true
    type    = uuid
    comment = "The Principal who revoked the key. Null for a removal the schedule made."
  }

  column "revocation_reason" {
    null = true
    type = text
  }

  primary_key {
    columns = [column.key_id]
  }

  foreign_key "client_key_registration_id_fkey" {
    columns     = [column.registration_id]
    ref_columns = [table.client_registration.column.registration_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  index "client_key_kid" {
    unique  = true
    columns = [column.registration_id, column.kid]
  }

  // One key pair authenticates one client only, so a leaked key compromises one client. A revoked
  // key keeps its thumbprint taken: a key revoked because it leaked can never come back.
  index "client_key_thumbprint" {
    unique  = true
    columns = [column.thumbprint]
  }

  // At most one active and one retiring key: the overlap the pinned kernel was proven to accept.
  index "client_key_one_active" {
    unique  = true
    columns = [column.registration_id]
    where   = "state = 'active'"
  }

  index "client_key_one_retiring" {
    unique  = true
    columns = [column.registration_id]
    where   = "state = 'retiring'"
  }

  check "client_key_state_check" {
    expr = "state IN ('active', 'retiring', 'revoked')"
  }

  // The database refuses private material even if validation missed it: RSA's private exponent and
  // CRT values, the other-primes list, and a symmetric key's value.
  check "client_key_public_only" {
    expr = "NOT (public_jwk ?| ARRAY['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'])"
  }

  // A revoked key says when; a retiring key says when its overlap ends; neither date appears on a
  // key in another state.
  check "client_key_dates_check" {
    expr = "((state = 'revoked') = (revoked_at IS NOT NULL)) AND ((state = 'retiring') = (retiring_at IS NOT NULL) OR state = 'revoked') AND expires_at > registered_at"
  }
}

// A workload Principal: a service, job, connector or governed agent, and the human answerable for it
// (TDD-identity-control-004). Its principal_id is minted here, before either kernel call, together
// with the reservation of its client registration, so recovery can finish a partly realized
// workload and can never find one whose owner was not recorded. Its Keycloak user is its client's
// service-account user, the one a client credentials token is issued for.
table "workload" {
  schema  = schema.identity
  comment = "A workload Principal and its accountable owner. TDD-identity-control-004."

  column "principal_id" {
    null = false
    type = uuid
  }

  column "registration_id" {
    null = false
    type = uuid
  }

  column "display_name" {
    null = false
    type = text
  }

  column "purpose" {
    null    = false
    type    = text
    comment = "Why the workload exists. A workload whose purpose nobody wrote down is one nobody can decide to retire."
  }

  column "workload_type" {
    null = false
    type = text
  }

  column "owner_principal_id" {
    null    = false
    type    = uuid
    comment = "The accountable human Principal, projected into workload_owner."
  }

  column "team_reference" {
    null    = true
    type    = text
    comment = "The team or group answerable when the owner is not, as Entra's serviceManagementReference and CIS 5.5's department owner."
  }

  column "owner_recorded_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  column "state" {
    null = false
    type = text
  }

  column "orphaned_at" {
    null = true
    type = timestamptz
  }

  column "last_seen_at" {
    null = true
    type = timestamptz
  }

  column "created_by" {
    null = false
    type = uuid
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

  // The creating request's idempotency claim, held so recovery can complete it. Without it, a
  // creation that failed after the claim would leave the caller's key in progress forever.
  column "idempotency_scope" {
    null = false
    type = text
  }

  column "idempotency_key" {
    null = false
    type = text
  }

  column "request_digest" {
    null = false
    type = text
  }

  column "version" {
    null    = false
    type    = bigint
    default = 1
  }

  primary_key {
    columns = [column.principal_id]
  }

  foreign_key "workload_registration_id_fkey" {
    columns     = [column.registration_id]
    ref_columns = [table.client_registration.column.registration_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  index "workload_registration" {
    unique  = true
    columns = [column.registration_id]
  }

  index "workload_by_owner" {
    columns = [column.owner_principal_id]
    where   = "state <> 'retired'"
  }

  index "workload_orphaned" {
    columns = [column.orphaned_at]
    where   = "state = 'orphaned'"
  }

  check "workload_type_check" {
    expr = "workload_type IN ('service', 'job', 'connector', 'agent')"
  }

  check "workload_state_check" {
    expr = "state IN ('pending', 'active', 'orphaned', 'suspended', 'retired')"
  }

  check "workload_named_check" {
    expr = "btrim(display_name) <> '' AND btrim(purpose) <> ''"
  }

  // A workload cannot answer for itself.
  check "workload_owner_not_self_check" {
    expr = "owner_principal_id <> principal_id"
  }

  check "workload_orphaned_check" {
    expr = "state <> 'orphaned' OR orphaned_at IS NOT NULL"
  }
}

// Every change of a workload's owner: who moved it, from whom to whom, and why. Insert-only, so the
// record of who was answerable at a given time cannot be rewritten by whoever holds it now.
table "workload_owner_change" {
  schema  = schema.identity
  comment = "An insert-only record of a workload's change of owner. TDD-identity-control-004."

  column "change_id" {
    null = false
    type = uuid
  }

  column "principal_id" {
    null = false
    type = uuid
  }

  column "previous_owner" {
    null = false
    type = uuid
  }

  column "new_owner" {
    null = false
    type = uuid
  }

  column "changed_by" {
    null = false
    type = uuid
  }

  column "reason" {
    null = false
    type = text
  }

  column "changed_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  primary_key {
    columns = [column.change_id]
  }

  foreign_key "workload_owner_change_principal_id_fkey" {
    columns     = [column.principal_id]
    ref_columns = [table.workload.column.principal_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  index "workload_owner_change_by_workload" {
    columns = [column.principal_id, column.changed_at]
  }

  check "workload_owner_change_reason_check" {
    expr = "btrim(reason) <> ''"
  }
}

// How a client created before this service existed came under registration: who adopted it, when,
// why, what it held at that moment, and which repairable differences the adoption converged
// (ADR-IAM-001 §5.12). Insert-only, so the record outlives whoever adopted it.
table "registration_adoption" {
  schema  = schema.identity
  comment = "An insert-only record of a client's adoption. TDD-identity-control-003."

  column "adoption_id" {
    null = false
    type = uuid
  }

  column "registration_id" {
    null = false
    type = uuid
  }

  column "kc_client_id" {
    null = false
    type = text
  }

  column "adopted_by" {
    null = false
    type = uuid
  }

  column "reason" {
    null = false
    type = text
  }

  column "observed" {
    null    = false
    type    = jsonb
    comment = "What the client held when it was adopted, per compared field class."
  }

  column "converged" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }

  column "adopted_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  primary_key {
    columns = [column.adoption_id]
  }

  foreign_key "registration_adoption_registration_id_fkey" {
    columns     = [column.registration_id]
    ref_columns = [table.client_registration.column.registration_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  index "registration_adoption_registration" {
    unique  = true
    columns = [column.registration_id]
  }

  check "registration_adoption_reason_check" {
    expr = "btrim(reason) <> ''"
  }
}

// One row per suspension, restoration and retirement (ADR-IAM-001 §5.13). Insert-only: grants.sql
// revokes UPDATE and DELETE from the runtime role.
table "registration_state_change" {
  schema  = schema.identity
  comment = "An insert-only record of each suspension, restoration and retirement. TDD-identity-control-003."

  column "change_id" {
    null = false
    type = uuid
  }

  column "registration_id" {
    null = false
    type = uuid
  }

  column "from_state" {
    null = false
    type = text
  }

  column "to_state" {
    null = false
    type = text
  }

  column "changed_by" {
    null = false
    type = uuid
  }

  column "reason" {
    null = false
    type = text
  }

  column "changed_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  primary_key {
    columns = [column.change_id]
  }

  foreign_key "registration_state_change_registration_id_fkey" {
    columns     = [column.registration_id]
    ref_columns = [table.client_registration.column.registration_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  index "registration_state_change_registration" {
    columns = [column.registration_id, column.changed_at]
  }

  check "registration_state_change_reason_check" {
    expr = "btrim(reason) <> ''"
  }

  check "registration_state_change_transition_check" {
    expr = "(from_state = 'active' AND to_state IN ('suspended', 'retired')) OR (from_state = 'suspended' AND to_state IN ('active', 'retired'))"
  }
}

// The owners of a registration (ADR-IAM-003, TDD-identity-control-003 §Registration Ownership): the
// people who may act on it besides a provider. Nothing is deleted: grants.sql leaves the runtime role
// UPDATE on the three revocation columns only, so who was made an owner, by whom and why is never
// rewritten.
table "registration_owner" {
  schema  = schema.identity
  comment = "Who may act on a registration besides a provider, granted and revoked with a reason. TDD-identity-control-003."

  column "ownership_id" {
    null = false
    type = uuid
  }

  column "registration_id" {
    null = false
    type = uuid
  }

  column "principal_id" {
    null = false
    type = uuid
  }

  column "granted_by" {
    null = false
    type = uuid
  }

  column "grant_reason" {
    null = false
    type = text
  }

  column "granted_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  column "revoked_at" {
    null = true
    type = timestamptz
  }

  column "revoked_by" {
    null = true
    type = uuid
  }

  column "revoke_reason" {
    null = true
    type = text
  }

  primary_key {
    columns = [column.ownership_id]
  }

  foreign_key "registration_owner_registration_id_fkey" {
    columns     = [column.registration_id]
    ref_columns = [table.client_registration.column.registration_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  // One active ownership per Principal and registration, read by ON CONFLICT on a grant.
  index "registration_owner_active" {
    unique  = true
    columns = [column.registration_id, column.principal_id]
    where   = "revoked_at IS NULL"
  }

  // The owned-registrations read, by Principal.
  index "registration_owner_principal" {
    columns = [column.principal_id]
    where   = "revoked_at IS NULL"
  }

  check "registration_owner_reason_check" {
    expr = "btrim(grant_reason) <> ''"
  }

  check "registration_owner_revocation_check" {
    expr = "((revoked_at IS NULL) = (revoked_by IS NULL)) AND ((revoked_at IS NULL) = (revoke_reason IS NULL))"
  }
}

table "registration_change" {
  schema  = schema.identity
  comment = "A change to a registration's redirect URIs or audience, proposed, then applied or decided against. TDD-identity-control-003."

  column "change_id" {
    null = false
    type = uuid
  }

  column "registration_id" {
    null = false
    type = uuid
  }

  // The registration's version the change was proposed against. An approval of a change whose
  // registration has moved since records it superseded.
  column "base_version" {
    null = false
    type = bigint
  }

  // What the change is to. Each kind fills its own pair of columns and leaves the other null.
  column "kind" {
    null    = false
    type    = text
    default = "redirect_uris"
  }

  // The registered set when the change was proposed: the before of the preview the approver sees.
  column "previous_redirect_uris" {
    null = true
    type = sql("text[]")
  }

  column "redirect_uris" {
    null = true
    type = sql("text[]")
  }

  // The registered audience when the change was proposed, and the audience proposed, each sorted.
  column "previous_audience" {
    null = true
    type = sql("text[]")
  }

  column "audience" {
    null = true
    type = sql("text[]")
  }

  // Fixed when the change is proposed, from IDENTITY_ENVIRONMENT, so the record states the rule it
  // was held to.
  column "approval_required" {
    null = false
    type = boolean
  }

  column "proposed_by" {
    null = false
    type = uuid
  }

  column "proposal_reason" {
    null = false
    type = text
  }

  column "proposed_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  column "state" {
    null    = false
    type    = text
    default = "proposed"
  }

  column "decided_by" {
    null = true
    type = uuid
  }

  column "decision_reason" {
    null = true
    type = text
  }

  column "decided_at" {
    null = true
    type = timestamptz
  }

  primary_key {
    columns = [column.change_id]
  }

  foreign_key "registration_change_registration_id_fkey" {
    columns     = [column.registration_id]
    ref_columns = [table.client_registration.column.registration_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  // One open change per registration: a second would be approved against a version the first moves.
  index "registration_change_open" {
    unique  = true
    columns = [column.registration_id]
    where   = "state = 'proposed'"
  }

  // The approval queue, oldest first.
  index "registration_change_queue" {
    columns = [column.proposed_at]
    where   = "state = 'proposed'"
  }

  check "registration_change_state_check" {
    expr = "state IN ('proposed', 'applied', 'rejected', 'withdrawn', 'superseded')"
  }

  check "registration_change_redirects_check" {
    expr = "cardinality(redirect_uris) > 0"
  }

  check "registration_change_kind_check" {
    expr = "(kind = ANY (ARRAY['redirect_uris'::text, 'audience'::text])) AND ((kind = 'redirect_uris'::text) = ((redirect_uris IS NOT NULL) AND (previous_redirect_uris IS NOT NULL))) AND ((kind = 'audience'::text) = ((audience IS NOT NULL) AND (previous_audience IS NOT NULL)))"
  }

  check "registration_change_reason_check" {
    expr = "btrim(proposal_reason) <> ''"
  }

  check "registration_change_decision_check" {
    expr = "((state = 'proposed') = (decided_at IS NULL)) AND ((decided_at IS NULL) = (decided_by IS NULL)) AND ((decided_at IS NULL) = (decision_reason IS NULL))"
  }

  // NIST AC-5 in the database: a change that required approval is never recorded applied by its
  // proposer, whatever the code above it does.
  check "registration_change_separation_check" {
    expr = "(NOT approval_required) OR (state <> 'applied') OR (decided_by <> proposed_by)"
  }
}

table "application_developer" {
  schema  = schema.identity
  comment = "Who may create non-production registrations without provider authority, granted and revoked with a reason. TDD-identity-control-003."

  column "grant_id" {
    null = false
    type = uuid
  }

  column "principal_id" {
    null = false
    type = uuid
  }

  column "granted_by" {
    null = false
    type = uuid
  }

  column "grant_reason" {
    null = false
    type = text
  }

  column "granted_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  column "revoked_at" {
    null = true
    type = timestamptz
  }

  column "revoked_by" {
    null = true
    type = uuid
  }

  column "revoke_reason" {
    null = true
    type = text
  }

  primary_key {
    columns = [column.grant_id]
  }

  // One active grant per Principal, read by ON CONFLICT on a grant.
  index "application_developer_active" {
    unique  = true
    columns = [column.principal_id]
    where   = "revoked_at IS NULL"
  }

  check "application_developer_reason_check" {
    expr = "btrim(grant_reason) <> ''"
  }

  check "application_developer_revocation_check" {
    expr = "((revoked_at IS NULL) = (revoked_by IS NULL)) AND ((revoked_at IS NULL) = (revoke_reason IS NULL))"
  }
}

table "registration_request" {
  schema  = schema.identity
  comment = "A production registration asked for, then approved by a provider other than its proposer, or decided against. TDD-identity-control-003."

  column "request_id" {
    null = false
    type = uuid
  }

  column "realm" {
    null = false
    type = text
  }

  column "client_key" {
    null = false
    type = text
  }

  // The registration document as POST /v1/registrations takes it, a public key reduced to its
  // public members.
  column "request" {
    null = false
    type = jsonb
  }

  column "owners" {
    null = false
    type = sql("uuid[]")
  }

  column "proposed_by" {
    null = false
    type = uuid
  }

  column "proposal_reason" {
    null = false
    type = text
  }

  column "proposed_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  column "state" {
    null    = false
    type    = text
    default = "proposed"
  }

  column "decided_by" {
    null = true
    type = uuid
  }

  column "decision_reason" {
    null = true
    type = text
  }

  column "decided_at" {
    null = true
    type = timestamptz
  }

  column "registration_id" {
    null = true
    type = uuid
  }

  primary_key {
    columns = [column.request_id]
  }

  foreign_key "registration_request_registration_id_fkey" {
    columns     = [column.registration_id]
    ref_columns = [table.client_registration.column.registration_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  // One open request per client_key: two would race to register the same client.
  index "registration_request_open" {
    unique  = true
    columns = [column.realm, column.client_key]
    where   = "state = 'proposed'"
  }

  // A proposer's own requests.
  index "registration_request_proposer" {
    columns = [column.proposed_by]
  }

  check "registration_request_state_check" {
    expr = "state IN ('proposed', 'approved', 'rejected', 'withdrawn')"
  }

  check "registration_request_owners_check" {
    expr = "cardinality(owners) >= 2"
  }

  check "registration_request_reason_check" {
    expr = "btrim(proposal_reason) <> ''"
  }

  check "registration_request_decision_check" {
    expr = "((state = 'proposed') = (decided_at IS NULL)) AND ((decided_at IS NULL) = (decided_by IS NULL)) AND ((decided_at IS NULL) = (decision_reason IS NULL))"
  }

  check "registration_request_registration_check" {
    expr = "(state = 'approved') = (registration_id IS NOT NULL)"
  }

  // NIST AC-5 in the database: a production registration is never recorded approved by its
  // proposer.
  check "registration_request_separation_check" {
    expr = "(state <> 'approved') OR (decided_by <> proposed_by)"
  }
}

// One row per provider:identity-control grant, as Organization Control's events and snapshot carry
// it (TDD-identity-control-006 §Data Model). Replaced by version, never deleted: a revoked grant
// stays, so a late older event cannot revive it.
table "provider_grant" {
  schema  = schema.identity
  comment = "Organization's provider:identity-control grants, projected by version. TDD-identity-control-006."

  column "grant_id" {
    null = false
    type = uuid
  }
  column "principal_id" {
    null = false
    type = uuid
  }
  column "kind" {
    null = false
    type = text
  }
  column "grant_status" {
    null = false
    type = text
  }
  column "grant_version" {
    null = false
    type = bigint
  }
  column "activation_id" {
    null = true
    type = uuid
  }
  column "activation_ends_at" {
    null = true
    type = timestamptz
  }
  column "applied_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  primary_key {
    columns = [column.grant_id]
  }

  // The per-request decision reads a caller's active grants by principal_id.
  index "provider_grant_principal" {
    columns = [column.principal_id]
    where   = "grant_status = 'active'"
  }

  check "provider_grant_kind_check" {
    expr = "kind IN ('eligible', 'emergency')"
  }
  check "provider_grant_status_check" {
    expr = "grant_status IN ('active', 'revoked')"
  }
  check "provider_grant_version_check" {
    expr = "grant_version > 0"
  }
  check "provider_grant_activation_complete" {
    expr = "(activation_id IS NULL) = (activation_ends_at IS NULL)"
  }
  check "provider_grant_revoked_inactive" {
    expr = "grant_status = 'active' OR activation_id IS NULL"
  }
}

// The snapshot this projection was built from and the highest stream position applied. No row is
// no bootstrap, and no activation is honored (TDD-identity-control-006 §Freshness).
table "provider_projection" {
  schema  = schema.identity
  comment = "The provider authority projection's bootstrap and progress. TDD-identity-control-006."

  column "id" {
    null = false
    type = integer
  }
  column "snapshot_mark" {
    null = false
    type = bigint
  }
  column "bootstrapped_at" {
    null = false
    type = timestamptz
  }
  column "applied_mark" {
    null = false
    type = bigint
  }

  primary_key {
    columns = [column.id]
  }

  check "provider_projection_single_row" {
    expr = "id = 1"
  }
}

// The ceremony grant's single recorded end: written once, in the transaction that projects the
// first active emergency provider:identity-control grant, and never changed (TDD-identity-control-006
// §The Ceremony's Grant). Insert-only, like the ceremony row.
table "ceremony_grant_retirement" {
  schema  = schema.identity
  comment = "The ceremony grant's retirement. Insert-only. TDD-identity-control-006."

  column "id" {
    null = false
    type = integer
  }
  column "retired_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }
  column "by_grant_id" {
    null    = false
    type    = uuid
    comment = "The emergency grant whose projection retired the ceremony grant."
  }

  primary_key {
    columns = [column.id]
  }

  check "ceremony_grant_retirement_single_row" {
    expr = "id = 1"
  }
}

// Every administrative read and command, written in the transaction that serves or records it
// (TDD-identity-control-005 §Evidence). Insert-only: grants.sql revokes UPDATE, DELETE and TRUNCATE.
table "privileged_access" {
  schema  = schema.identity
  comment = "Every administrative read and command, insert-only (NIST SP 800-53 AU-3, AU-9). TDD-identity-control-005."

  column "access_id" {
    null = false
    type = uuid
  }
  column "actor_principal_id" {
    null = false
    type = uuid
  }
  column "subject_principal_id" {
    null = true
    type = uuid
  }
  column "action" {
    null = false
    type = text
  }
  column "route" {
    null = false
    type = text
  }
  column "reason" {
    null = true
    type = text
  }
  column "query" {
    null = true
    type = text
  }
  column "result_count" {
    null = true
    type = integer
  }
  column "outcome" {
    null = false
    type = text
  }
  column "correlation_id" {
    null = false
    type = text
  }
  column "emergency" {
    null = false
    type = boolean
  }
  column "recorded_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  primary_key {
    columns = [column.access_id]
  }

  index "privileged_access_subject" {
    columns = [column.subject_principal_id, column.recorded_at]
  }
  index "privileged_access_actor" {
    columns = [column.actor_principal_id, column.recorded_at]
  }

  check "privileged_access_outcome_check" {
    expr = "outcome = ANY (ARRAY['served'::text, 'applied'::text, 'refused'::text])"
  }
  check "privileged_access_action_check" {
    expr = "btrim(action) <> ''::text"
  }
}

// The serialization point of one Principal's security commands (TDD-identity-control-005 §Data
// Model). A command locks the row, compares expected_version, takes next_sequence and increments
// both, so two commands on one Principal are ordered and an outdated one is refused.
table "security_subject_state" {
  schema  = schema.identity
  comment = "Version and sequence of one Principal's security commands. TDD-identity-control-005."

  column "principal_id" {
    null = false
    type = uuid
  }
  column "version" {
    null    = false
    type    = bigint
    default = 1
  }
  column "next_sequence" {
    null    = false
    type    = bigint
    default = 1
  }
  column "updated_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  primary_key {
    columns = [column.principal_id]
  }

  foreign_key "security_subject_state_principal_id_fkey" {
    columns     = [column.principal_id]
    ref_columns = [table.principal_mapping.column.principal_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }
}

// An accepted security command, durable before any kernel call (STD-GLB-011 §3.3). It holds the
// sealed reference, never a kernel identifier.
table "security_operation" {
  schema  = schema.identity
  comment = "Accepted security commands and their execution state. TDD-identity-control-005 §Containment as Built."

  column "operation_id" {
    null = false
    type = uuid
  }
  column "principal_id" {
    null = false
    type = uuid
  }
  column "subject_sequence" {
    null = false
    type = bigint
  }
  column "actor_principal_id" {
    null = false
    type = uuid
  }
  column "idempotency_key" {
    null = false
    type = text
  }
  column "request_digest" {
    null = false
    type = text
  }
  column "operation_type" {
    null = false
    type = text
  }
  column "sealed_object_ref" {
    null = true
    type = text
  }
  column "expected_version" {
    null = false
    type = bigint
  }
  column "reason" {
    null = true
    type = text
  }
  column "correlation_id" {
    null = false
    type = text
  }
  column "assurance" {
    null = false
    type = text
  }
  column "emergency" {
    null = false
    type = boolean
  }
  column "state" {
    null    = false
    type    = text
    default = "pending"
  }
  column "attempts" {
    null    = false
    type    = integer
    default = 0
  }
  column "next_attempt_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }
  column "result_code" {
    null = true
    type = text
  }
  column "last_error_class" {
    null = true
    type = text
  }
  column "created_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }
  column "applied_at" {
    null = true
    type = timestamptz
  }
  // The attempt count at the last re-drive: the executor parks the operation again after
  // IDENTITY_SECURITY_MAX_ATTEMPTS attempts past it (TDD-identity-control-005 §Operating the Executor).
  column "redriven_at" {
    null    = false
    type    = integer
    default = 0
  }

  primary_key {
    columns = [column.operation_id]
  }

  foreign_key "security_operation_principal_id_fkey" {
    columns     = [column.principal_id]
    ref_columns = [table.security_subject_state.column.principal_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  index "security_operation_principal_id_subject_sequence_key" {
    unique  = true
    columns = [column.principal_id, column.subject_sequence]
  }
  index "security_operation_actor_principal_id_idempotency_key_key" {
    unique  = true
    columns = [column.actor_principal_id, column.idempotency_key]
  }
  index "security_operation_claim" {
    columns = [column.next_attempt_at, column.created_at]
    where   = "state IN ('pending', 'retrying')"
  }

  check "security_operation_state_check" {
    expr = "state IN ('pending', 'retrying', 'applied', 'refused', 'unresolved')"
  }
  check "security_operation_type_check" {
    expr = "operation_type IN ('suspend', 'restore', 'sessions.terminate-all', 'authenticator.revoke', 'session.terminate', 'authenticator.remove')"
  }
}

// One row per claim of an operation: the operation is the job and the row its attempt
// (STD-GLB-011 §3.4). Insert-only but for the attempt's own finish.
table "security_operation_attempt" {
  schema  = schema.identity
  comment = "Each claim of a security operation. STD-GLB-011 §3.4."

  column "operation_id" {
    null = false
    type = uuid
  }
  column "attempt" {
    null = false
    type = integer
  }
  column "claimed_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }
  column "lease_until" {
    null = false
    type = timestamptz
  }
  column "finished_at" {
    null = true
    type = timestamptz
  }
  column "outcome" {
    null = true
    type = text
  }
  column "error_class" {
    null = true
    type = text
  }

  primary_key {
    columns = [column.operation_id, column.attempt]
  }

  foreign_key "security_operation_attempt_operation_id_fkey" {
    columns     = [column.operation_id]
    ref_columns = [table.security_operation.column.operation_id]
    on_update   = NO_ACTION
    on_delete   = NO_ACTION
  }

  check "security_operation_attempt_outcome_check" {
    expr = "outcome IS NULL OR outcome IN ('applied', 'refused', 'retry', 'unresolved')"
  }
}
