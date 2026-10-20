-- A provider's temporary password, recorded without its value, and how it ended (ADR-IAM-010,
-- TDD-identity-control-005 2.12.0 §A First Credential). Both tables are insert-only (grants.sql).
-- Create "temporary_password_issuance" table
CREATE TABLE "identity"."temporary_password_issuance" (
  "issuance_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "issued_by" uuid NOT NULL,
  "reason" text NOT NULL,
  "correlation_id" text NOT NULL,
  "emergency" boolean NOT NULL,
  "assurance" text NOT NULL,
  "issued_at" timestamptz NOT NULL DEFAULT now(),
  "lapses_at" timestamptz NOT NULL,
  PRIMARY KEY ("issuance_id"),
  CONSTRAINT "temporary_password_issuance_principal_id_fkey" FOREIGN KEY ("principal_id") REFERENCES "identity"."principal_mapping" ("principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "temporary_password_issuance_lapse_bounded" CHECK ((lapses_at > issued_at) AND (lapses_at <= (issued_at + '24:00:00'::interval))),
  CONSTRAINT "temporary_password_issuance_not_self" CHECK (issued_by <> principal_id),
  CONSTRAINT "temporary_password_issuance_reason_named" CHECK (btrim(reason) <> ''::text)
);
-- Create index "temporary_password_issuance_lapse" to table: "temporary_password_issuance"
CREATE INDEX "temporary_password_issuance_lapse" ON "identity"."temporary_password_issuance" ("lapses_at");
-- Create index "temporary_password_issuance_principal" to table: "temporary_password_issuance"
CREATE INDEX "temporary_password_issuance_principal" ON "identity"."temporary_password_issuance" ("principal_id", "issued_at");
-- Set comment to table: "temporary_password_issuance"
COMMENT ON TABLE "identity"."temporary_password_issuance" IS 'Each temporary password a provider issued, never its value. Insert-only. ADR-IAM-010, TDD-identity-control-005 2.12.0.';
-- Create "temporary_password_outcome" table
CREATE TABLE "identity"."temporary_password_outcome" (
  "issuance_id" uuid NOT NULL,
  "outcome" text NOT NULL,
  "recorded_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("issuance_id"),
  CONSTRAINT "temporary_password_outcome_issuance_id_fkey" FOREIGN KEY ("issuance_id") REFERENCES "identity"."temporary_password_issuance" ("issuance_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "temporary_password_outcome_check" CHECK (outcome = ANY (ARRAY['used'::text, 'lapsed'::text, 'replaced'::text, 'failed'::text]))
);
-- Set comment to table: "temporary_password_outcome"
COMMENT ON TABLE "identity"."temporary_password_outcome" IS 'How each temporary password ended, once. Insert-only. ADR-IAM-010, TDD-identity-control-005 2.12.0.';
