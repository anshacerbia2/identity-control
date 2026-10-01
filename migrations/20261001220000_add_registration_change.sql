-- Create "registration_change" table
CREATE TABLE "identity"."registration_change" (
  "change_id" uuid NOT NULL,
  "registration_id" uuid NOT NULL,
  "base_version" bigint NOT NULL,
  "previous_redirect_uris" text[] NOT NULL,
  "redirect_uris" text[] NOT NULL,
  "approval_required" boolean NOT NULL,
  "proposed_by" uuid NOT NULL,
  "proposal_reason" text NOT NULL,
  "proposed_at" timestamptz NOT NULL DEFAULT now(),
  "state" text NOT NULL DEFAULT 'proposed',
  "decided_by" uuid NULL,
  "decision_reason" text NULL,
  "decided_at" timestamptz NULL,
  PRIMARY KEY ("change_id"),
  CONSTRAINT "registration_change_registration_id_fkey" FOREIGN KEY ("registration_id") REFERENCES "identity"."client_registration" ("registration_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "registration_change_decision_check" CHECK (((state = 'proposed'::text) = (decided_at IS NULL)) AND ((decided_at IS NULL) = (decided_by IS NULL)) AND ((decided_at IS NULL) = (decision_reason IS NULL))),
  CONSTRAINT "registration_change_reason_check" CHECK (btrim(proposal_reason) <> ''::text),
  CONSTRAINT "registration_change_redirects_check" CHECK (cardinality(redirect_uris) > 0),
  CONSTRAINT "registration_change_separation_check" CHECK ((NOT approval_required) OR (state <> 'applied'::text) OR (decided_by <> proposed_by)),
  CONSTRAINT "registration_change_state_check" CHECK (state = ANY (ARRAY['proposed'::text, 'applied'::text, 'rejected'::text, 'withdrawn'::text, 'superseded'::text]))
);
-- Create index "registration_change_open" to table: "registration_change"
CREATE UNIQUE INDEX "registration_change_open" ON "identity"."registration_change" ("registration_id") WHERE (state = 'proposed'::text);
-- Create index "registration_change_queue" to table: "registration_change"
CREATE INDEX "registration_change_queue" ON "identity"."registration_change" ("proposed_at") WHERE (state = 'proposed'::text);
-- Set comment to table: "registration_change"
COMMENT ON TABLE "identity"."registration_change" IS 'A change to a registration''s redirect URIs, proposed, then applied or decided against. TDD-identity-control-003.';
