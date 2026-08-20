-- Create "bootstrap_ceremony" table
CREATE TABLE "bootstrap_ceremony" (
  "id" integer NOT NULL,
  "operator" text NOT NULL,
  "reason" text NOT NULL,
  "idempotency_key" text NOT NULL,
  "requested_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "bootstrap_ceremony_operator_named" CHECK ((btrim(operator) <> ''::text) AND (btrim(reason) <> ''::text)),
  CONSTRAINT "bootstrap_ceremony_single_row" CHECK (id = 1)
);
-- Set comment to table: "bootstrap_ceremony"
COMMENT ON TABLE "bootstrap_ceremony" IS 'The single bootstrap ceremony record. Insert-only. ADR-IAM-001 §5.8.';
-- Set comment to column: "operator" on table: "bootstrap_ceremony"
COMMENT ON COLUMN "bootstrap_ceremony"."operator" IS 'The human who ran the ceremony. Not the process, and not a service account.';
