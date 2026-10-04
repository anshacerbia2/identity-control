-- Create "membership_desired" table
CREATE TABLE "identity"."membership_desired" (
  "membership_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "tenant_id" uuid NOT NULL,
  "membership_status" text NOT NULL,
  "membership_version" bigint NOT NULL,
  "source_event_id" uuid NULL,
  "accepted_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("membership_id"),
  CONSTRAINT "membership_desired_status_check" CHECK (membership_status = ANY (ARRAY['active'::text, 'suspended'::text, 'revoked'::text, 'absent'::text])),
  CONSTRAINT "membership_desired_version_check" CHECK (membership_version > 0)
);
-- Create index "membership_desired_tenant" to table: "membership_desired"
CREATE INDEX "membership_desired_tenant" ON "identity"."membership_desired" ("tenant_id");
-- Set comment to table: "membership_desired"
COMMENT ON TABLE "identity"."membership_desired" IS 'The newest accepted state of each Membership, by membership_version. TDD-identity-control-002 2.0.0.';
-- Create "tenant_convergence" table
CREATE TABLE "identity"."tenant_convergence" (
  "tenant_id" uuid NOT NULL,
  "priority" boolean NOT NULL DEFAULT false,
  "marked_at" timestamptz NOT NULL DEFAULT now(),
  "next_attempt_at" timestamptz NOT NULL DEFAULT now(),
  "lease_until" timestamptz NULL,
  "attempts" integer NOT NULL DEFAULT 0,
  "state" text NOT NULL DEFAULT 'pending',
  "last_error_class" text NULL,
  "kernel_org_id" text NULL,
  "converged_at" timestamptz NULL,
  PRIMARY KEY ("tenant_id"),
  CONSTRAINT "tenant_convergence_state_check" CHECK (state = ANY (ARRAY['pending'::text, 'converged'::text, 'unresolved'::text]))
);
-- Create index "tenant_convergence_claim" to table: "tenant_convergence"
CREATE INDEX "tenant_convergence_claim" ON "identity"."tenant_convergence" ("priority", "next_attempt_at") WHERE (state = 'pending'::text);
-- Set comment to table: "tenant_convergence"
COMMENT ON TABLE "identity"."tenant_convergence" IS 'Tenants whose kernel Organization is to be made to match the desired state, one at a time. TDD-identity-control-002 2.0.0.';
-- Create "tenant_desired" table
CREATE TABLE "identity"."tenant_desired" (
  "tenant_id" uuid NOT NULL,
  "tenant_status" text NOT NULL,
  "tenant_version" bigint NOT NULL,
  "tenant_security_version" bigint NOT NULL,
  "source_event_id" uuid NULL,
  "accepted_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("tenant_id"),
  CONSTRAINT "tenant_desired_status_check" CHECK (tenant_status = ANY (ARRAY['active'::text, 'suspended'::text, 'offboarding'::text, 'retired'::text])),
  CONSTRAINT "tenant_desired_version_check" CHECK (tenant_version > 0)
);
-- Set comment to table: "tenant_desired"
COMMENT ON TABLE "identity"."tenant_desired" IS 'The newest accepted state of each Tenant, by tenant_version. TDD-identity-control-002 2.0.0.';
