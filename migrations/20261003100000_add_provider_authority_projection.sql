-- Create "provider_grant" table
CREATE TABLE "identity"."provider_grant" (
  "grant_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "kind" text NOT NULL,
  "grant_status" text NOT NULL,
  "grant_version" bigint NOT NULL,
  "activation_id" uuid NULL,
  "activation_ends_at" timestamptz NULL,
  "applied_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("grant_id"),
  CONSTRAINT "provider_grant_activation_complete" CHECK ((activation_id IS NULL) = (activation_ends_at IS NULL)),
  CONSTRAINT "provider_grant_kind_check" CHECK (kind = ANY (ARRAY['eligible'::text, 'emergency'::text])),
  CONSTRAINT "provider_grant_revoked_inactive" CHECK ((grant_status = 'active'::text) OR (activation_id IS NULL)),
  CONSTRAINT "provider_grant_status_check" CHECK (grant_status = ANY (ARRAY['active'::text, 'revoked'::text])),
  CONSTRAINT "provider_grant_version_check" CHECK (grant_version > 0)
);
-- Create index "provider_grant_principal" to table: "provider_grant"
CREATE INDEX "provider_grant_principal" ON "identity"."provider_grant" ("principal_id") WHERE (grant_status = 'active'::text);
-- Set comment to table: "provider_grant"
COMMENT ON TABLE "identity"."provider_grant" IS 'Organization''s provider:identity-control grants, projected by version. TDD-identity-control-006.';
-- Create "provider_projection" table
CREATE TABLE "identity"."provider_projection" (
  "id" integer NOT NULL,
  "snapshot_mark" bigint NOT NULL,
  "bootstrapped_at" timestamptz NOT NULL,
  "applied_mark" bigint NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "provider_projection_single_row" CHECK (id = 1)
);
-- Set comment to table: "provider_projection"
COMMENT ON TABLE "identity"."provider_projection" IS 'The provider authority projection''s bootstrap and progress. TDD-identity-control-006.';
