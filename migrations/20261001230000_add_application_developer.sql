-- Create "application_developer" table
CREATE TABLE "identity"."application_developer" (
  "grant_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "granted_by" uuid NOT NULL,
  "grant_reason" text NOT NULL,
  "granted_at" timestamptz NOT NULL DEFAULT now(),
  "revoked_at" timestamptz NULL,
  "revoked_by" uuid NULL,
  "revoke_reason" text NULL,
  PRIMARY KEY ("grant_id"),
  CONSTRAINT "application_developer_reason_check" CHECK (btrim(grant_reason) <> ''::text),
  CONSTRAINT "application_developer_revocation_check" CHECK (((revoked_at IS NULL) = (revoked_by IS NULL)) AND ((revoked_at IS NULL) = (revoke_reason IS NULL)))
);
-- Create index "application_developer_active" to table: "application_developer"
CREATE UNIQUE INDEX "application_developer_active" ON "identity"."application_developer" ("principal_id") WHERE (revoked_at IS NULL);
-- Set comment to table: "application_developer"
COMMENT ON TABLE "identity"."application_developer" IS 'Who may create non-production registrations without provider authority, granted and revoked with a reason. TDD-identity-control-003.';
