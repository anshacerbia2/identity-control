-- The realm signing keys' registry (ADR-IAM-002 §5.5 Q5 to Q9, amended 2026-10-24;
-- TDD-identity-control-001 1.29.0 §The Signing Key Registry): each key, each approval of one of its
-- transitions, and each transition. Written by `atlas migrate diff`; the timeouts and the retention
-- triggers are added by hand (.squawk.toml, TDD-identity-control-001 §Audit Retention).
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
-- Create "signing_key" table
CREATE TABLE "signing_key" (
  "kid" text NOT NULL,
  "realm" text NOT NULL,
  "algorithm" text NOT NULL,
  "public_jwk" jsonb NOT NULL,
  "custody_ref" text NOT NULL,
  "operator" text NOT NULL,
  "witness" text NOT NULL,
  "reason" text NOT NULL,
  "correlation_id" text NOT NULL,
  "staged_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("kid"),
  CONSTRAINT "signing_key_algorithm_check" CHECK (algorithm = 'PS256'::text),
  CONSTRAINT "signing_key_kid_form" CHECK (kid ~ '^[A-Za-z0-9_-]{43}$'::text),
  CONSTRAINT "signing_key_named" CHECK ((btrim(realm) <> ''::text) AND (btrim(custody_ref) <> ''::text) AND (btrim(operator) <> ''::text) AND (btrim(reason) <> ''::text) AND (btrim(correlation_id) <> ''::text)),
  CONSTRAINT "signing_key_witness_check" CHECK ((btrim(witness) <> ''::text) AND (lower(btrim(witness)) <> lower(btrim(operator))))
);
-- Set comment to table: "signing_key"
COMMENT ON TABLE "signing_key" IS 'Each realm signing key, written once when it is staged. Insert-only. ADR-IAM-002 §5.5 Q5.';
-- Set comment to column: "kid" on table: "signing_key"
COMMENT ON COLUMN "signing_key"."kid" IS 'The RFC 7638 thumbprint of public_jwk, checked when the row is written.';
-- Set comment to column: "public_jwk" on table: "signing_key"
COMMENT ON COLUMN "signing_key"."public_jwk" IS 'The public key, kept as evidence after the key is destroyed. Never a private key.';
-- Set comment to column: "custody_ref" on table: "signing_key"
COMMENT ON COLUMN "signing_key"."custody_ref" IS 'Where the key''s custody is: the secrets'' names or the development keys directory. Never the material.';
-- Create "signing_key_approval" table
CREATE TABLE "signing_key_approval" (
  "approval_id" uuid NOT NULL,
  "kid" text NOT NULL,
  "transition" text NOT NULL,
  "operator" text NOT NULL,
  "approver" text NOT NULL,
  "emergency" boolean NOT NULL DEFAULT false,
  "reason" text NOT NULL,
  "correlation_id" text NOT NULL,
  "approved_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("approval_id"),
  CONSTRAINT "signing_key_approval_emergency_check" CHECK ((NOT emergency) OR (transition = 'activate'::text)),
  CONSTRAINT "signing_key_approval_independent" CHECK ((btrim(approver) <> ''::text) AND (lower(btrim(approver)) <> lower(btrim(operator)))),
  CONSTRAINT "signing_key_approval_named" CHECK ((btrim(operator) <> ''::text) AND (btrim(reason) <> ''::text) AND (btrim(correlation_id) <> ''::text)),
  CONSTRAINT "signing_key_approval_transition_check" CHECK (transition = ANY (ARRAY['activate'::text, 'retire'::text, 'abandon'::text, 'revoke'::text]))
);
-- Create index "signing_key_approval_kid_idx" to table: "signing_key_approval"
CREATE INDEX "signing_key_approval_kid_idx" ON "signing_key_approval" ("kid", "transition");
-- Set comment to table: "signing_key_approval"
COMMENT ON TABLE "signing_key_approval" IS 'Each approval of one transition of one signing key. Insert-only. ADR-IAM-002 §5.5 Q9.';
-- Set comment to column: "operator" on table: "signing_key_approval"
COMMENT ON COLUMN "signing_key_approval"."operator" IS 'The operator of the step this approval is for.';
-- Set comment to column: "approver" on table: "signing_key_approval"
COMMENT ON COLUMN "signing_key_approval"."approver" IS 'A holder of the ceremony role who is not the operator. STD-IAM-001 §3.10.';
-- Set comment to column: "emergency" on table: "signing_key_approval"
COMMENT ON COLUMN "signing_key_approval"."emergency" IS 'An activation after a compromise, which does not wait the cache window. ADR-IAM-002 §5.5 Q7.';
-- Create "signing_key_transition" table
CREATE TABLE "signing_key_transition" (
  "transition_id" uuid NOT NULL,
  "kid" text NOT NULL,
  "step" text NOT NULL,
  "from_state" text NULL,
  "to_state" text NOT NULL,
  "actor" text NOT NULL,
  "approval_id" uuid NULL,
  "reason" text NOT NULL,
  "correlation_id" text NOT NULL,
  "outcome" text NOT NULL,
  "evidence" text NULL,
  "occurred_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("transition_id"),
  CONSTRAINT "signing_key_transition_approved" CHECK ((step = 'stage'::text) = (approval_id IS NULL)),
  CONSTRAINT "signing_key_transition_evidence" CHECK (((outcome = 'failed'::text) OR (to_state = ANY (ARRAY['retired'::text, 'revoked'::text]))) = ((evidence IS NOT NULL) AND (btrim(evidence) <> ''::text))),
  CONSTRAINT "signing_key_transition_named" CHECK ((btrim(actor) <> ''::text) AND (btrim(reason) <> ''::text) AND (btrim(correlation_id) <> ''::text)),
  CONSTRAINT "signing_key_transition_outcome_check" CHECK (outcome = ANY (ARRAY['completed'::text, 'failed'::text])),
  CONSTRAINT "signing_key_transition_state_check" CHECK ((to_state = ANY (ARRAY['staged'::text, 'active'::text, 'retiring'::text, 'retired'::text, 'revoked'::text])) AND ((from_state IS NULL) OR (from_state = ANY (ARRAY['staged'::text, 'active'::text, 'retiring'::text])))),
  CONSTRAINT "signing_key_transition_step_check" CHECK (step = ANY (ARRAY['stage'::text, 'activate'::text, 'demote'::text, 'retire'::text, 'abandon'::text, 'revoke'::text]))
);
-- Create index "signing_key_transition_approval_once" to table: "signing_key_transition"
CREATE UNIQUE INDEX "signing_key_transition_approval_once" ON "signing_key_transition" ("approval_id", "kid") WHERE (outcome = 'completed'::text);
-- Create index "signing_key_transition_kid_idx" to table: "signing_key_transition"
CREATE INDEX "signing_key_transition_kid_idx" ON "signing_key_transition" ("kid", "occurred_at");
-- Create index "signing_key_transition_state_once" to table: "signing_key_transition"
CREATE UNIQUE INDEX "signing_key_transition_state_once" ON "signing_key_transition" ("kid", "to_state") WHERE (outcome = 'completed'::text);
-- Set comment to table: "signing_key_transition"
COMMENT ON TABLE "signing_key_transition" IS 'Each transition of a signing key, and each failed attempt at one. Insert-only. A key''s state is its latest completed row. ADR-IAM-002 §5.5 Q5, Q9.';
-- Set comment to column: "approval_id" on table: "signing_key_transition"
COMMENT ON COLUMN "signing_key_transition"."approval_id" IS 'The approval the step ran under. Null for staging, which the ceremony''s witness attests.';
-- Set comment to column: "evidence" on table: "signing_key_transition"
COMMENT ON COLUMN "signing_key_transition"."evidence" IS 'For a destruction, its proof (CloudTrail DeleteSecret events, or the files removed); for a failure, the error.';
-- The three are audit records (STD-GLB-007 1.3.0 §Data Retention Lifecycle, migration 20261020200000):
-- a key's rows are kept while it is in force and 7 years after its end.
CREATE TRIGGER "signing_key_retention" BEFORE DELETE ON "signing_key"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('staged_at');
CREATE TRIGGER "signing_key_no_truncate" BEFORE TRUNCATE ON "signing_key" -- atlas:destructive-approved 2026-10-25: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "signing_key_approval_retention" BEFORE DELETE ON "signing_key_approval"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('approved_at');
CREATE TRIGGER "signing_key_approval_no_truncate" BEFORE TRUNCATE ON "signing_key_approval" -- atlas:destructive-approved 2026-10-25: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
CREATE TRIGGER "signing_key_transition_retention" BEFORE DELETE ON "signing_key_transition"
    FOR EACH ROW EXECUTE FUNCTION identity.refuse_young_audit_delete('occurred_at');
CREATE TRIGGER "signing_key_transition_no_truncate" BEFORE TRUNCATE ON "signing_key_transition" -- atlas:destructive-approved 2026-10-25: refuses it, removes nothing
    FOR EACH STATEMENT EXECUTE FUNCTION identity.refuse_young_audit_delete();
