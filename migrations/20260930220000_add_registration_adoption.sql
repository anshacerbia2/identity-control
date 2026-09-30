-- Create "registration_adoption" table
CREATE TABLE "registration_adoption" (
  "adoption_id" uuid NOT NULL,
  "registration_id" uuid NOT NULL,
  "kc_client_id" text NOT NULL,
  "adopted_by" uuid NOT NULL,
  "reason" text NOT NULL,
  "observed" jsonb NOT NULL,
  "converged" text[] NOT NULL DEFAULT '{}'::text[],
  "adopted_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("adoption_id"),
  CONSTRAINT "registration_adoption_registration_id_fkey" FOREIGN KEY ("registration_id") REFERENCES "client_registration" ("registration_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "registration_adoption_reason_check" CHECK (btrim(reason) <> ''::text)
);
-- Create index "registration_adoption_registration" to table: "registration_adoption"
CREATE UNIQUE INDEX "registration_adoption_registration" ON "registration_adoption" ("registration_id");
-- Set comment to table: "registration_adoption"
COMMENT ON TABLE "registration_adoption" IS 'An insert-only record of a client''s adoption. TDD-identity-control-003.';
-- Set comment to column: "observed" on table: "registration_adoption"
COMMENT ON COLUMN "registration_adoption"."observed" IS 'What the client held when it was adopted, per compared field class.';
