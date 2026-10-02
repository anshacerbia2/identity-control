-- Modify "bootstrap_ceremony" table
ALTER TABLE "identity"."bootstrap_ceremony" ADD COLUMN "principal_id" uuid NULL;
-- Set comment to column: "principal_id" on table: "bootstrap_ceremony"
COMMENT ON COLUMN "identity"."bootstrap_ceremony"."principal_id" IS 'The ceremony''s Principal: its local emergency grant until ceremony_grant_retirement. TDD-identity-control-006.';
-- A ceremony performed before this column created the first Principal into an empty registry, so
-- the earliest mapping is its Principal. A row whose Principal was never created stays null.
UPDATE "identity"."bootstrap_ceremony"
   SET "principal_id" = (SELECT "principal_id" FROM "identity"."principal_mapping"
                          ORDER BY "created_at", "principal_id" LIMIT 1)
 WHERE "principal_id" IS NULL;
-- Create "ceremony_grant_retirement" table
CREATE TABLE "identity"."ceremony_grant_retirement" (
  "id" integer NOT NULL,
  "retired_at" timestamptz NOT NULL DEFAULT now(),
  "by_grant_id" uuid NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "ceremony_grant_retirement_single_row" CHECK (id = 1)
);
-- Set comment to table: "ceremony_grant_retirement"
COMMENT ON TABLE "identity"."ceremony_grant_retirement" IS 'The ceremony grant''s retirement. Insert-only. TDD-identity-control-006.';
-- Set comment to column: "by_grant_id" on table: "ceremony_grant_retirement"
COMMENT ON COLUMN "identity"."ceremony_grant_retirement"."by_grant_id" IS 'The emergency grant whose projection retired the ceremony grant.';
