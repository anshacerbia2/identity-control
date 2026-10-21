-- Enrolment from an invitation (ADR-IAM-011 §5.1 to §5.9, TDD-identity-control-001 1.27.0): the BFF
-- workloads admitted to the two routes, each enrolment and its messages, and the limits' counts.
-- Written by `atlas migrate diff`; the timeouts and the retention triggers are added by hand
-- (.squawk.toml, TDD-identity-control-001 §Audit Retention).
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
-- Create "enrolment_count" table
CREATE TABLE "enrolment_count" (
  "key_hash" text NOT NULL,
  "rule" text NOT NULL,
  "window_ends_at" timestamptz NOT NULL,
  "count" integer NOT NULL,
  PRIMARY KEY ("key_hash", "rule"),
  CONSTRAINT "enrolment_count_positive" CHECK (count > 0),
  CONSTRAINT "enrolment_count_rule_check" CHECK (rule = ANY (ARRAY['request:minute'::text, 'request:hour'::text, 'verify:minute'::text, 'verify:hour'::text, 'message:hour'::text, 'message:day'::text, 'failure:day'::text]))
);
-- Create index "enrolment_count_window" to table: "enrolment_count"
CREATE INDEX "enrolment_count_window" ON "enrolment_count" ("window_ends_at");
-- Set comment to table: "enrolment_count"
COMMENT ON TABLE "enrolment_count" IS 'Enrolment rate-limit counts by keyed hash and rule, deleted when their window ends. ADR-IAM-011 §5.8.';
-- Create "enrolment_message" table
CREATE TABLE "enrolment_message" (
  "message_id" uuid NOT NULL,
  "enrolment_id" uuid NULL,
  "kind" text NOT NULL,
  "address" text NULL,
  "sealed_secret" text NULL,
  "state" text NOT NULL DEFAULT 'requested',
  "attempts" integer NOT NULL DEFAULT 0,
  "next_attempt_at" timestamptz NOT NULL DEFAULT now(),
  "platform_ref" text NULL,
  "last_error" text NULL,
  "requested_at" timestamptz NOT NULL DEFAULT now(),
  "submitted_at" timestamptz NULL,
  PRIMARY KEY ("message_id"),
  CONSTRAINT "enrolment_message_held_check" CHECK ((state = 'requested'::text) = (address IS NOT NULL)),
  CONSTRAINT "enrolment_message_kind_check" CHECK (((kind = 'code'::text) AND (enrolment_id IS NOT NULL)) OR ((kind = 'account_exists'::text) AND (enrolment_id IS NULL))),
  CONSTRAINT "enrolment_message_state_check" CHECK (state = ANY (ARRAY['requested'::text, 'submitted'::text, 'failed'::text]))
);
-- Create index "enrolment_message_due" to table: "enrolment_message"
CREATE INDEX "enrolment_message_due" ON "enrolment_message" ("next_attempt_at") WHERE (state = 'requested'::text);
-- Set comment to table: "enrolment_message"
COMMENT ON TABLE "enrolment_message" IS 'Each enrolment message to an invited address, until handed over. ADR-IAM-011, TDD-identity-control-001 1.27.0.';
-- Create "enrolment" table
CREATE TABLE "enrolment" (
  "enrolment_id" uuid NOT NULL,
  "invitation_id" uuid NOT NULL,
  "address_hash" text NOT NULL,
  "address" text NULL,
  "code_hash" text NULL,
  "code_expires_at" timestamptz NOT NULL,
  "attempts" integer NOT NULL DEFAULT 0,
  "state" text NOT NULL DEFAULT 'open',
  "verifying_until" timestamptz NULL,
  "caller_principal_id" uuid NOT NULL,
  "principal_id" uuid NULL,
  "issuance_id" uuid NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "closed_at" timestamptz NULL,
  PRIMARY KEY ("enrolment_id"),
  CONSTRAINT "enrolment_principal_id_fkey" FOREIGN KEY ("principal_id") REFERENCES "principal_mapping" ("principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "enrolment_attempts_check" CHECK ((attempts >= 0) AND (attempts <= 5)),
  CONSTRAINT "enrolment_completed_names_principal" CHECK ((state = 'completed'::text) = ((principal_id IS NOT NULL) AND (issuance_id IS NOT NULL))),
  CONSTRAINT "enrolment_open_holds_code" CHECK ((state = 'open'::text) = ((code_hash IS NOT NULL) AND (address IS NOT NULL) AND (closed_at IS NULL))),
  CONSTRAINT "enrolment_state_check" CHECK (state = ANY (ARRAY['open'::text, 'completed'::text, 'refused'::text]))
);
-- Create index "enrolment_invitation" to table: "enrolment"
CREATE INDEX "enrolment_invitation" ON "enrolment" ("invitation_id", "created_at");
-- Set comment to table: "enrolment"
COMMENT ON TABLE "enrolment" IS 'Each enrolment from an invitation: the invitation, the address hash, the code, the Principal created. ADR-IAM-011, TDD-identity-control-001 1.27.0.';
-- Create "enrolment_caller" table
CREATE TABLE "enrolment_caller" (
  "principal_id" uuid NOT NULL,
  "purpose" text NOT NULL,
  "registered_by" uuid NOT NULL,
  "register_reason" text NOT NULL,
  "registered_at" timestamptz NOT NULL DEFAULT now(),
  "retired_by" uuid NULL,
  "retire_reason" text NULL,
  "retired_at" timestamptz NULL,
  PRIMARY KEY ("principal_id"),
  CONSTRAINT "enrolment_caller_principal_id_fkey" FOREIGN KEY ("principal_id") REFERENCES "principal_mapping" ("principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "enrolment_caller_named" CHECK ((btrim(purpose) <> ''::text) AND (btrim(register_reason) <> ''::text)),
  CONSTRAINT "enrolment_caller_retirement" CHECK (((retired_at IS NULL) = (retired_by IS NULL)) AND ((retired_at IS NULL) = (retire_reason IS NULL)))
);
-- Set comment to table: "enrolment_caller"
COMMENT ON TABLE "enrolment_caller" IS 'Workloads admitted to POST /v1/enrolments and :verify. ADR-IAM-011 §5.8, TDD-identity-control-001 1.27.0.';

-- The three evidence tables keep their rows for 7 years, as every audit table does (STD-GLB-007 1.3.0
-- §Data Retention Lifecycle, migration 20261020200000). enrolment_count is not evidence: its rows are
-- deleted when their window ends (ADR-IAM-011 §5.8).
CREATE TRIGGER "enrolment_caller_retention" BEFORE DELETE ON "enrolment_caller"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('registered_at', 'retired_at');
CREATE TRIGGER "enrolment_caller_no_truncate" BEFORE TRUNCATE ON "enrolment_caller" -- atlas:destructive-approved 2026-10-21: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "enrolment_retention" BEFORE DELETE ON "enrolment"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('code_expires_at', 'verifying_until', 'created_at', 'closed_at');
CREATE TRIGGER "enrolment_no_truncate" BEFORE TRUNCATE ON "enrolment" -- atlas:destructive-approved 2026-10-21: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "enrolment_message_retention" BEFORE DELETE ON "enrolment_message"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('next_attempt_at', 'requested_at', 'submitted_at');
CREATE TRIGGER "enrolment_message_no_truncate" BEFORE TRUNCATE ON "enrolment_message" -- atlas:destructive-approved 2026-10-21: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
