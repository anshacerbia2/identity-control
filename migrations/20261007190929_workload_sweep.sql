-- The workload sweep, review and automatic suspension (TDD-identity-control-004 1.5.0, TDD-identity-control-003 1.34.0).
-- Modify "registration_state_change" table
ALTER TABLE "registration_state_change" ADD CONSTRAINT "registration_state_change_actor_check" CHECK ((changed_by IS NULL) = automatic), ALTER COLUMN "changed_by" DROP NOT NULL, ADD COLUMN "automatic" boolean NOT NULL DEFAULT false;
-- Create "workload_finding" table
CREATE TABLE "workload_finding" (
  "finding_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "finding_class" text NOT NULL,
  "detected_at" timestamptz NOT NULL DEFAULT now(),
  "resolved_at" timestamptz NULL,
  "resolution" text NULL,
  PRIMARY KEY ("finding_id"),
  CONSTRAINT "workload_finding_principal_id_fkey" FOREIGN KEY ("principal_id") REFERENCES "workload" ("principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "workload_finding_class_check" CHECK (finding_class = ANY (ARRAY['unused'::text, 'review_overdue'::text])),
  CONSTRAINT "workload_finding_resolution_check" CHECK (((resolved_at IS NULL) = (resolution IS NULL)) AND ((resolution IS NULL) OR (resolution = ANY (ARRAY['seen'::text, 'reviewed'::text, 'stopped'::text]))))
);
-- Create index "workload_finding_open" to table: "workload_finding"
CREATE UNIQUE INDEX "workload_finding_open" ON "workload_finding" ("principal_id", "finding_class") WHERE (resolved_at IS NULL);
-- Set comment to table: "workload_finding"
COMMENT ON TABLE "workload_finding" IS 'A workload unused past the threshold, or whose owner review is overdue. TDD-identity-control-004 1.5.0.';
-- Create "workload_review" table
CREATE TABLE "workload_review" (
  "review_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "reviewed_by" uuid NOT NULL,
  "statement" text NOT NULL,
  "reviewed_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("review_id"),
  CONSTRAINT "workload_review_principal_id_fkey" FOREIGN KEY ("principal_id") REFERENCES "workload" ("principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "workload_review_statement_check" CHECK (btrim(statement) <> ''::text)
);
-- Create index "workload_review_by_workload" to table: "workload_review"
CREATE INDEX "workload_review_by_workload" ON "workload_review" ("principal_id", "reviewed_at");
-- Set comment to table: "workload_review"
COMMENT ON TABLE "workload_review" IS 'An insert-only record of an owner''s review of a workload. TDD-identity-control-004 1.5.0.';
