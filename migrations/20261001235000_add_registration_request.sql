-- Create "registration_request" table
CREATE TABLE "identity"."registration_request" (
  "request_id" uuid NOT NULL,
  "realm" text NOT NULL,
  "client_key" text NOT NULL,
  "request" jsonb NOT NULL,
  "owners" uuid[] NOT NULL,
  "proposed_by" uuid NOT NULL,
  "proposal_reason" text NOT NULL,
  "proposed_at" timestamptz NOT NULL DEFAULT now(),
  "state" text NOT NULL DEFAULT 'proposed',
  "decided_by" uuid NULL,
  "decision_reason" text NULL,
  "decided_at" timestamptz NULL,
  "registration_id" uuid NULL,
  PRIMARY KEY ("request_id"),
  CONSTRAINT "registration_request_registration_id_fkey" FOREIGN KEY ("registration_id") REFERENCES "identity"."client_registration" ("registration_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "registration_request_decision_check" CHECK (((state = 'proposed'::text) = (decided_at IS NULL)) AND ((decided_at IS NULL) = (decided_by IS NULL)) AND ((decided_at IS NULL) = (decision_reason IS NULL))),
  CONSTRAINT "registration_request_owners_check" CHECK (cardinality(owners) >= 2),
  CONSTRAINT "registration_request_reason_check" CHECK (btrim(proposal_reason) <> ''::text),
  CONSTRAINT "registration_request_registration_check" CHECK ((state = 'approved'::text) = (registration_id IS NOT NULL)),
  CONSTRAINT "registration_request_separation_check" CHECK ((state <> 'approved'::text) OR (decided_by <> proposed_by)),
  CONSTRAINT "registration_request_state_check" CHECK (state = ANY (ARRAY['proposed'::text, 'approved'::text, 'rejected'::text, 'withdrawn'::text]))
);
-- Create index "registration_request_open" to table: "registration_request"
CREATE UNIQUE INDEX "registration_request_open" ON "identity"."registration_request" ("realm", "client_key") WHERE (state = 'proposed'::text);
-- Create index "registration_request_proposer" to table: "registration_request"
CREATE INDEX "registration_request_proposer" ON "identity"."registration_request" ("proposed_by");
-- Set comment to table: "registration_request"
COMMENT ON TABLE "identity"."registration_request" IS 'A production registration asked for, then approved by a provider other than its proposer, or decided against. TDD-identity-control-003.';
