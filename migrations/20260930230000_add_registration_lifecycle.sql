-- Create "registration_state_change" table
CREATE TABLE "registration_state_change" (
  "change_id" uuid NOT NULL,
  "registration_id" uuid NOT NULL,
  "from_state" text NOT NULL,
  "to_state" text NOT NULL,
  "changed_by" uuid NOT NULL,
  "reason" text NOT NULL,
  "changed_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("change_id"),
  CONSTRAINT "registration_state_change_registration_id_fkey" FOREIGN KEY ("registration_id") REFERENCES "client_registration" ("registration_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "registration_state_change_reason_check" CHECK (btrim(reason) <> ''::text),
  CONSTRAINT "registration_state_change_transition_check" CHECK (((from_state = 'active'::text) AND (to_state = ANY (ARRAY['suspended'::text, 'retired'::text]))) OR ((from_state = 'suspended'::text) AND (to_state = ANY (ARRAY['active'::text, 'retired'::text]))))
);
-- Create index "registration_state_change_registration" to table: "registration_state_change"
CREATE INDEX "registration_state_change_registration" ON "registration_state_change" ("registration_id", "changed_at");
-- Set comment to table: "registration_state_change"
COMMENT ON TABLE "registration_state_change" IS 'An insert-only record of each suspension, restoration and retirement. TDD-identity-control-003.';
-- Modify "registration_finding" table
-- Widens the field classes by one value, 'suspension'. Every row that satisfied the old CHECK satisfies
-- the new one, so dropping and re-adding it can refuse nothing and loses nothing.
ALTER TABLE "registration_finding" DROP CONSTRAINT "registration_finding_field_check", ADD CONSTRAINT "registration_finding_field_check" CHECK ((field_class IS NULL) OR (field_class = ANY (ARRAY['redirect_uris'::text, 'token_lifespan'::text, 'audience_scope'::text, 'signing_algorithm'::text, 'profile'::text, 'client_keys'::text, 'suspension'::text]))); -- atlas:destructive-approved: widening a CHECK, reviewed 2026-09-30
