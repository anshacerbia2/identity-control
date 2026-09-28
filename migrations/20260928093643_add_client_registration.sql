-- Create "client_registration" table
CREATE TABLE "client_registration" (
  "registration_id" uuid NOT NULL,
  "kc_client_id" text NULL,
  "realm" text NOT NULL,
  "client_key" text NOT NULL,
  "profile" text NOT NULL,
  "application_authority" text NOT NULL,
  "application_ref" text NOT NULL,
  "registered_by" uuid NOT NULL,
  "audience_class" text NOT NULL,
  "signing_algorithm" text NOT NULL DEFAULT 'PS256',
  "algorithm_exception_owner" uuid NULL,
  "algorithm_exception_reason" text NULL,
  "algorithm_exception_expires_at" timestamptz NULL,
  "lifetime_class" text NULL,
  "audience" text[] NULL,
  "redirect_uris" text[] NULL,
  "state" text NOT NULL,
  "version" bigint NOT NULL DEFAULT 1,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "activated_at" timestamptz NULL,
  "suspended_at" timestamptz NULL,
  "retired_at" timestamptz NULL,
  PRIMARY KEY ("registration_id"),
  CONSTRAINT "client_algorithm_profile_check" CHECK (((signing_algorithm = 'PS256'::text) AND (algorithm_exception_owner IS NULL) AND (algorithm_exception_reason IS NULL) AND (algorithm_exception_expires_at IS NULL)) OR ((signing_algorithm = 'RS256'::text) AND (audience_class = 'external'::text) AND (algorithm_exception_owner IS NOT NULL) AND (algorithm_exception_reason IS NOT NULL) AND (algorithm_exception_expires_at > created_at))),
  CONSTRAINT "client_audience_class_check" CHECK (audience_class = ANY (ARRAY['internal'::text, 'privileged'::text, 'workload'::text, 'external'::text])),
  CONSTRAINT "client_lifetime_class_check" CHECK ((lifetime_class IS NULL) OR (lifetime_class = ANY (ARRAY['L0'::text, 'L1'::text, 'L2'::text, 'L3'::text]))),
  CONSTRAINT "client_lifetime_class_required" CHECK ((profile <> 'resource'::text) OR (lifetime_class IS NOT NULL)),
  CONSTRAINT "client_profile_check" CHECK (profile = ANY (ARRAY['confidential'::text, 'public'::text, 'workload'::text, 'resource'::text])),
  CONSTRAINT "client_signing_algorithm_check" CHECK (signing_algorithm = ANY (ARRAY['PS256'::text, 'RS256'::text])),
  CONSTRAINT "client_state_check" CHECK (state = ANY (ARRAY['pending'::text, 'active'::text, 'suspended'::text, 'retired'::text])),
  CONSTRAINT "client_workload_audience_check" CHECK ((profile <> 'workload'::text) OR (audience_class = 'workload'::text))
);
-- Create index "client_registration_kc_client_id_key" to table: "client_registration"
CREATE UNIQUE INDEX "client_registration_kc_client_id_key" ON "client_registration" ("kc_client_id");
-- Create index "client_registration_key" to table: "client_registration"
CREATE UNIQUE INDEX "client_registration_key" ON "client_registration" ("realm", "client_key") WHERE (state <> 'retired'::text);
-- Set comment to table: "client_registration"
COMMENT ON TABLE "client_registration" IS 'Desired state for a protocol client or protected resource. TDD-identity-control-003.';
-- Set comment to column: "kc_client_id" on table: "client_registration"
COMMENT ON COLUMN "client_registration"."kc_client_id" IS 'Keycloak''s internal client id. Null while pending.';
-- Set comment to column: "client_key" on table: "client_registration"
COMMENT ON COLUMN "client_registration"."client_key" IS 'The clientId as Keycloak and every caller name it.';
-- Set comment to column: "registered_by" on table: "client_registration"
COMMENT ON COLUMN "client_registration"."registered_by" IS 'The accountable Principal. While application_authority is manual, accountability rests here.';
-- Create "drift_exception" table
CREATE TABLE "drift_exception" (
  "exception_id" uuid NOT NULL,
  "registration_id" uuid NOT NULL,
  "field_class" text NOT NULL,
  "actor" text NOT NULL,
  "reason" text NOT NULL,
  "granted_by" uuid NOT NULL,
  "granted_at" timestamptz NOT NULL DEFAULT now(),
  "expires_at" timestamptz NOT NULL,
  PRIMARY KEY ("exception_id"),
  CONSTRAINT "drift_exception_registration_id_fkey" FOREIGN KEY ("registration_id") REFERENCES "client_registration" ("registration_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "drift_exception_field_check" CHECK (field_class = ANY (ARRAY['redirect_uris'::text, 'token_lifespan'::text, 'audience_scope'::text, 'signing_algorithm'::text, 'profile'::text])),
  CONSTRAINT "drift_exception_named_check" CHECK ((btrim(actor) <> ''::text) AND (btrim(reason) <> ''::text)),
  CONSTRAINT "drift_exception_window_check" CHECK ((expires_at > granted_at) AND (expires_at <= (granted_at + '24:00:00'::interval)))
);
-- Set comment to table: "drift_exception"
COMMENT ON TABLE "drift_exception" IS 'A time-bound, insert-only permission for a console change. TDD-identity-control-003.';
-- Set comment to column: "actor" on table: "drift_exception"
COMMENT ON COLUMN "drift_exception"."actor" IS 'The Keycloak user the admin event will name.';
-- Create "reconcile_run" table
CREATE TABLE "reconcile_run" (
  "run_id" uuid NOT NULL,
  "sweep" text NOT NULL,
  "started_at" timestamptz NOT NULL DEFAULT now(),
  "finished_at" timestamptz NULL,
  "outcome" text NULL,
  "attribution" boolean NULL,
  "findings" integer NOT NULL DEFAULT 0,
  PRIMARY KEY ("run_id"),
  CONSTRAINT "reconcile_run_finished_check" CHECK ((finished_at IS NULL) = (outcome IS NULL)),
  CONSTRAINT "reconcile_run_outcome_check" CHECK ((outcome IS NULL) OR (outcome = ANY (ARRAY['converged'::text, 'drift'::text, 'unresolved'::text]))),
  CONSTRAINT "reconcile_run_sweep_check" CHECK (sweep = 'registration'::text)
);
-- Create index "reconcile_run_latest" to table: "reconcile_run"
CREATE INDEX "reconcile_run_latest" ON "reconcile_run" ("sweep", "started_at");
-- Set comment to table: "reconcile_run"
COMMENT ON TABLE "reconcile_run" IS 'One reconciliation sweep and its outcome. TDD-identity-control-003.';
-- Set comment to column: "attribution" on table: "reconcile_run"
COMMENT ON COLUMN "reconcile_run"."attribution" IS 'Whether the run could read admin events. Without them no divergence is repaired automatically.';
-- Create "registration_finding" table
CREATE TABLE "registration_finding" (
  "finding_id" uuid NOT NULL,
  "run_id" uuid NOT NULL,
  "registration_id" uuid NULL,
  "kc_client_id" text NOT NULL,
  "field_class" text NULL,
  "finding_class" text NOT NULL,
  "desired" jsonb NULL,
  "observed" jsonb NULL,
  "actor" text NULL,
  "changed_at" timestamptz NULL,
  "detected_at" timestamptz NOT NULL DEFAULT now(),
  "converged_at" timestamptz NULL,
  "resolved_by" uuid NULL,
  "resolution_reason" text NULL,
  PRIMARY KEY ("finding_id"),
  CONSTRAINT "registration_finding_registration_id_fkey" FOREIGN KEY ("registration_id") REFERENCES "client_registration" ("registration_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "registration_finding_run_id_fkey" FOREIGN KEY ("run_id") REFERENCES "reconcile_run" ("run_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "registration_finding_class_check" CHECK (finding_class = ANY (ARRAY['repaired'::text, 'blocked'::text, 'sanctioned'::text, 'unattributed'::text, 'recreated'::text, 'unmanaged'::text])),
  CONSTRAINT "registration_finding_field_check" CHECK ((field_class IS NULL) OR (field_class = ANY (ARRAY['redirect_uris'::text, 'token_lifespan'::text, 'audience_scope'::text, 'signing_algorithm'::text, 'profile'::text]))),
  CONSTRAINT "registration_finding_resolution_check" CHECK (((resolved_by IS NULL) = (resolution_reason IS NULL)) AND ((resolution_reason IS NULL) OR (btrim(resolution_reason) <> ''::text)))
);
-- Create index "registration_finding_open" to table: "registration_finding"
CREATE UNIQUE INDEX "registration_finding_open" ON "registration_finding" ("kc_client_id", "field_class") NULLS NOT DISTINCT WHERE (converged_at IS NULL);
-- Set comment to table: "registration_finding"
COMMENT ON TABLE "registration_finding" IS 'One divergence between desired state and Keycloak, retained after convergence. TDD-identity-control-003.';
-- Set comment to column: "registration_id" on table: "registration_finding"
COMMENT ON COLUMN "registration_finding"."registration_id" IS 'Null for an unmanaged client, which no registration describes.';
-- Set comment to column: "actor" on table: "registration_finding"
COMMENT ON COLUMN "registration_finding"."actor" IS 'The Keycloak user the attributing admin event names. Null when the change is unattributed.';
-- Set comment to column: "changed_at" on table: "registration_finding"
COMMENT ON COLUMN "registration_finding"."changed_at" IS 'The attributing admin event''s time. converged_at - changed_at is the convergence time.';
-- Set comment to column: "resolved_by" on table: "registration_finding"
COMMENT ON COLUMN "registration_finding"."resolved_by" IS 'The Principal whose reconcile applied desired state to a blocked or unattributed finding.';
