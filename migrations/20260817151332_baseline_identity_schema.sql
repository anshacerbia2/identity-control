-- Create "principal_mapping" table
CREATE TABLE "principal_mapping" (
  "principal_id" uuid NOT NULL,
  "keycloak_user_id" text NULL,
  "realm" text NOT NULL,
  "subject_type" text NOT NULL,
  "workload_owner" uuid NULL,
  "state" text NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "activated_at" timestamptz NULL,
  "quarantined_at" timestamptz NULL,
  "quarantine_reason" text NULL,
  "version" integer NOT NULL DEFAULT 1,
  PRIMARY KEY ("principal_id"),
  CONSTRAINT "principal_mapping_owner_check" CHECK (((subject_type = 'human'::text) AND (workload_owner IS NULL)) OR ((subject_type = 'workload'::text) AND (workload_owner IS NOT NULL))),
  CONSTRAINT "principal_mapping_state_check" CHECK (state = ANY (ARRAY['pending'::text, 'active'::text, 'quarantined'::text, 'retired'::text])),
  CONSTRAINT "principal_mapping_subject_check" CHECK (subject_type = ANY (ARRAY['human'::text, 'workload'::text]))
);
-- Create index "principal_mapping_keycloak_user_id_key" to table: "principal_mapping"
CREATE UNIQUE INDEX "principal_mapping_keycloak_user_id_key" ON "principal_mapping" ("keycloak_user_id");
-- Create index "principal_mapping_realm_user" to table: "principal_mapping"
CREATE UNIQUE INDEX "principal_mapping_realm_user" ON "principal_mapping" ("realm", "keycloak_user_id") WHERE (keycloak_user_id IS NOT NULL);
-- Set comment to table: "principal_mapping"
COMMENT ON TABLE "principal_mapping" IS 'Canonical principal_id to Keycloak user mapping. TDD-identity-control-001.';
-- Set comment to column: "principal_id" on table: "principal_mapping"
COMMENT ON COLUMN "principal_mapping"."principal_id" IS 'UUIDv7 minted by the Control Plane. The enterprise-wide reference.';
-- Set comment to column: "keycloak_user_id" on table: "principal_mapping"
COMMENT ON COLUMN "principal_mapping"."keycloak_user_id" IS 'Null while pending. Never leaves this module; absent from every response body.';
-- Set comment to column: "workload_owner" on table: "principal_mapping"
COMMENT ON COLUMN "principal_mapping"."workload_owner" IS 'The accountable human Principal. Required for a workload, prohibited for a human.';
-- Create "projection_cursor" table
CREATE TABLE "projection_cursor" (
  "stream" text NOT NULL,
  "projection_version" text NOT NULL,
  "max_applied_stream_position" bigint NOT NULL DEFAULT 0,
  "last_snapshot_mark" bigint NULL,
  "last_reconciled_at" timestamptz NULL,
  PRIMARY KEY ("stream")
);
-- Set comment to table: "projection_cursor"
COMMENT ON TABLE "projection_cursor" IS 'Per-stream consumer watermark. TDD-identity-control-002.';
