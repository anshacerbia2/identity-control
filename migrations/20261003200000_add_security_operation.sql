-- Modify "principal_mapping" table
ALTER TABLE "principal_mapping" DROP CONSTRAINT "principal_mapping_state_check", ADD CONSTRAINT "principal_mapping_state_check" CHECK (state = ANY (ARRAY['pending'::text, 'active'::text, 'suspended'::text, 'quarantined'::text, 'retired'::text])); -- atlas:destructive-approved: widening a CHECK, reviewed 2026-10-03
-- Create "security_subject_state" table
CREATE TABLE "security_subject_state" (
  "principal_id" uuid NOT NULL,
  "version" bigint NOT NULL DEFAULT 1,
  "next_sequence" bigint NOT NULL DEFAULT 1,
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("principal_id"),
  CONSTRAINT "security_subject_state_principal_id_fkey" FOREIGN KEY ("principal_id") REFERENCES "principal_mapping" ("principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION
);
-- Set comment to table: "security_subject_state"
COMMENT ON TABLE "security_subject_state" IS 'Version and sequence of one Principal''s security commands. TDD-identity-control-005.';
-- Create "security_operation" table
CREATE TABLE "security_operation" (
  "operation_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "subject_sequence" bigint NOT NULL,
  "actor_principal_id" uuid NOT NULL,
  "idempotency_key" text NOT NULL,
  "request_digest" text NOT NULL,
  "operation_type" text NOT NULL,
  "sealed_object_ref" text NULL,
  "expected_version" bigint NOT NULL,
  "reason" text NULL,
  "correlation_id" text NOT NULL,
  "assurance" text NOT NULL,
  "emergency" boolean NOT NULL,
  "state" text NOT NULL DEFAULT 'pending',
  "attempts" integer NOT NULL DEFAULT 0,
  "next_attempt_at" timestamptz NOT NULL DEFAULT now(),
  "result_code" text NULL,
  "last_error_class" text NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "applied_at" timestamptz NULL,
  PRIMARY KEY ("operation_id"),
  CONSTRAINT "security_operation_principal_id_fkey" FOREIGN KEY ("principal_id") REFERENCES "security_subject_state" ("principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "security_operation_state_check" CHECK (state = ANY (ARRAY['pending'::text, 'retrying'::text, 'applied'::text, 'refused'::text, 'unresolved'::text])),
  CONSTRAINT "security_operation_type_check" CHECK (operation_type = ANY (ARRAY['suspend'::text, 'restore'::text, 'sessions.terminate-all'::text, 'authenticator.revoke'::text]))
);
-- Create index "security_operation_actor_principal_id_idempotency_key_key" to table: "security_operation"
CREATE UNIQUE INDEX "security_operation_actor_principal_id_idempotency_key_key" ON "security_operation" ("actor_principal_id", "idempotency_key");
-- Create index "security_operation_claim" to table: "security_operation"
CREATE INDEX "security_operation_claim" ON "security_operation" ("next_attempt_at", "created_at") WHERE (state = ANY (ARRAY['pending'::text, 'retrying'::text]));
-- Create index "security_operation_principal_id_subject_sequence_key" to table: "security_operation"
CREATE UNIQUE INDEX "security_operation_principal_id_subject_sequence_key" ON "security_operation" ("principal_id", "subject_sequence");
-- Set comment to table: "security_operation"
COMMENT ON TABLE "security_operation" IS 'Accepted security commands and their execution state. TDD-identity-control-005 §Containment as Built.';
-- Create "security_operation_attempt" table
CREATE TABLE "security_operation_attempt" (
  "operation_id" uuid NOT NULL,
  "attempt" integer NOT NULL,
  "claimed_at" timestamptz NOT NULL DEFAULT now(),
  "lease_until" timestamptz NOT NULL,
  "finished_at" timestamptz NULL,
  "outcome" text NULL,
  "error_class" text NULL,
  PRIMARY KEY ("operation_id", "attempt"),
  CONSTRAINT "security_operation_attempt_operation_id_fkey" FOREIGN KEY ("operation_id") REFERENCES "security_operation" ("operation_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "security_operation_attempt_outcome_check" CHECK ((outcome IS NULL) OR (outcome = ANY (ARRAY['applied'::text, 'refused'::text, 'retry'::text, 'unresolved'::text])))
);
-- Set comment to table: "security_operation_attempt"
COMMENT ON TABLE "security_operation_attempt" IS 'Each claim of a security operation. STD-GLB-011 §3.4.';
