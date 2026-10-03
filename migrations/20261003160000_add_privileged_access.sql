-- Create "privileged_access" table
CREATE TABLE "identity"."privileged_access" (
  "access_id" uuid NOT NULL,
  "actor_principal_id" uuid NOT NULL,
  "subject_principal_id" uuid NULL,
  "action" text NOT NULL,
  "route" text NOT NULL,
  "reason" text NULL,
  "query" text NULL,
  "result_count" integer NULL,
  "outcome" text NOT NULL,
  "correlation_id" text NOT NULL,
  "emergency" boolean NOT NULL,
  "recorded_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("access_id"),
  CONSTRAINT "privileged_access_outcome_check" CHECK (outcome = ANY (ARRAY['served'::text, 'applied'::text, 'refused'::text])),
  CONSTRAINT "privileged_access_action_check" CHECK (btrim(action) <> ''::text)
);
-- Create index "privileged_access_subject" to table: "privileged_access"
CREATE INDEX "privileged_access_subject" ON "identity"."privileged_access" ("subject_principal_id", "recorded_at");
-- Create index "privileged_access_actor" to table: "privileged_access"
CREATE INDEX "privileged_access_actor" ON "identity"."privileged_access" ("actor_principal_id", "recorded_at");
-- Set comment to table: "privileged_access"
COMMENT ON TABLE "identity"."privileged_access" IS 'Every administrative read and command, insert-only (NIST SP 800-53 AU-3, AU-9). TDD-identity-control-005.';
