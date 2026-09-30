-- Create "workload" table
CREATE TABLE "workload" (
  "principal_id" uuid NOT NULL,
  "registration_id" uuid NOT NULL,
  "display_name" text NOT NULL,
  "purpose" text NOT NULL,
  "workload_type" text NOT NULL,
  "owner_principal_id" uuid NOT NULL,
  "team_reference" text NULL,
  "owner_recorded_at" timestamptz NOT NULL DEFAULT now(),
  "state" text NOT NULL,
  "orphaned_at" timestamptz NULL,
  "last_seen_at" timestamptz NULL,
  "created_by" uuid NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "activated_at" timestamptz NULL,
  "idempotency_scope" text NOT NULL,
  "idempotency_key" text NOT NULL,
  "request_digest" text NOT NULL,
  "version" bigint NOT NULL DEFAULT 1,
  PRIMARY KEY ("principal_id"),
  CONSTRAINT "workload_registration_id_fkey" FOREIGN KEY ("registration_id") REFERENCES "client_registration" ("registration_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "workload_named_check" CHECK ((btrim(display_name) <> ''::text) AND (btrim(purpose) <> ''::text)),
  CONSTRAINT "workload_orphaned_check" CHECK ((state <> 'orphaned'::text) OR (orphaned_at IS NOT NULL)),
  CONSTRAINT "workload_owner_not_self_check" CHECK (owner_principal_id <> principal_id),
  CONSTRAINT "workload_state_check" CHECK (state = ANY (ARRAY['pending'::text, 'active'::text, 'orphaned'::text, 'suspended'::text, 'retired'::text])),
  CONSTRAINT "workload_type_check" CHECK (workload_type = ANY (ARRAY['service'::text, 'job'::text, 'connector'::text, 'agent'::text]))
);
-- Create index "workload_by_owner" to table: "workload"
CREATE INDEX "workload_by_owner" ON "workload" ("owner_principal_id") WHERE (state <> 'retired'::text);
-- Create index "workload_orphaned" to table: "workload"
CREATE INDEX "workload_orphaned" ON "workload" ("orphaned_at") WHERE (state = 'orphaned'::text);
-- Create index "workload_registration" to table: "workload"
CREATE UNIQUE INDEX "workload_registration" ON "workload" ("registration_id");
-- Set comment to table: "workload"
COMMENT ON TABLE "workload" IS 'A workload Principal and its accountable owner. TDD-identity-control-004.';
-- Set comment to column: "purpose" on table: "workload"
COMMENT ON COLUMN "workload"."purpose" IS 'Why the workload exists. A workload whose purpose nobody wrote down is one nobody can decide to retire.';
-- Set comment to column: "owner_principal_id" on table: "workload"
COMMENT ON COLUMN "workload"."owner_principal_id" IS 'The accountable human Principal, projected into workload_owner.';
-- Set comment to column: "team_reference" on table: "workload"
COMMENT ON COLUMN "workload"."team_reference" IS 'The team or group answerable when the owner is not, as Entra''s serviceManagementReference and CIS 5.5''s department owner.';
-- Create "workload_owner_change" table
CREATE TABLE "workload_owner_change" (
  "change_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "previous_owner" uuid NOT NULL,
  "new_owner" uuid NOT NULL,
  "changed_by" uuid NOT NULL,
  "reason" text NOT NULL,
  "changed_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("change_id"),
  CONSTRAINT "workload_owner_change_principal_id_fkey" FOREIGN KEY ("principal_id") REFERENCES "workload" ("principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "workload_owner_change_reason_check" CHECK (btrim(reason) <> ''::text)
);
-- Create index "workload_owner_change_by_workload" to table: "workload_owner_change"
CREATE INDEX "workload_owner_change_by_workload" ON "workload_owner_change" ("principal_id", "changed_at");
-- Set comment to table: "workload_owner_change"
COMMENT ON TABLE "workload_owner_change" IS 'An insert-only record of a workload''s change of owner. TDD-identity-control-004.';
