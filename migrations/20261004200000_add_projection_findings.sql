-- Modify "tenant_convergence" table
ALTER TABLE "identity"."tenant_convergence" ADD COLUMN "sweep" boolean NOT NULL DEFAULT false;
-- Create "projection_finding" table
CREATE TABLE "identity"."projection_finding" (
  "finding_id" uuid NOT NULL,
  "finding_class" text NOT NULL,
  "tenant_id" uuid NULL,
  "principal_id" uuid NULL,
  "detail" jsonb NOT NULL,
  "detected_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("finding_id"),
  CONSTRAINT "projection_finding_class_check" CHECK (finding_class = ANY (ARRAY['missing_member'::text, 'extra_member'::text, 'organization_state'::text, 'unknown_organization'::text]))
);
-- Create index "projection_finding_detected" to table: "projection_finding"
CREATE INDEX "projection_finding_detected" ON "identity"."projection_finding" ("detected_at");
-- Set comment to table: "projection_finding"
COMMENT ON TABLE "identity"."projection_finding" IS 'What a reconciliation sweep had to change in the kernel, kept as evidence. TDD-identity-control-002 2.1.0.';
