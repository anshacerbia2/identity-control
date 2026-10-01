-- Create "registration_owner" table
CREATE TABLE "identity"."registration_owner" (
  "ownership_id" uuid NOT NULL,
  "registration_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "granted_by" uuid NOT NULL,
  "grant_reason" text NOT NULL,
  "granted_at" timestamptz NOT NULL DEFAULT now(),
  "revoked_at" timestamptz NULL,
  "revoked_by" uuid NULL,
  "revoke_reason" text NULL,
  PRIMARY KEY ("ownership_id"),
  CONSTRAINT "registration_owner_registration_id_fkey" FOREIGN KEY ("registration_id") REFERENCES "identity"."client_registration" ("registration_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "registration_owner_reason_check" CHECK (btrim(grant_reason) <> ''::text),
  CONSTRAINT "registration_owner_revocation_check" CHECK (((revoked_at IS NULL) = (revoked_by IS NULL)) AND ((revoked_at IS NULL) = (revoke_reason IS NULL)))
);
-- Create index "registration_owner_active" to table: "registration_owner"
CREATE UNIQUE INDEX "registration_owner_active" ON "identity"."registration_owner" ("registration_id", "principal_id") WHERE (revoked_at IS NULL);
-- Create index "registration_owner_principal" to table: "registration_owner"
CREATE INDEX "registration_owner_principal" ON "identity"."registration_owner" ("principal_id") WHERE (revoked_at IS NULL);
-- Set comment to table: "registration_owner"
COMMENT ON TABLE "identity"."registration_owner" IS 'Who may act on a registration besides a provider, granted and revoked with a reason. TDD-identity-control-003.';
