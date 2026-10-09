-- Modify "reconcile_run" table
-- The Tenant context sweep records its runs (TDD-identity-control-002 2.5.0, TDD-identity-control-003 1.38.0).
ALTER TABLE "identity"."reconcile_run" DROP CONSTRAINT "reconcile_run_sweep_check", ADD CONSTRAINT "reconcile_run_sweep_check" CHECK (sweep = ANY (ARRAY['registration'::text, 'tenant_context'::text])); -- atlas:destructive-approved: widening a CHECK, reviewed 2026-10-09
-- Modify "tenant_convergence" table
-- The earliest delivery not yet converged, for the delivery-to-converged metric (TDD-identity-control-002 2.5.0).
ALTER TABLE "identity"."tenant_convergence" ADD COLUMN "delivered_at" timestamptz NULL;
-- Create "principal_release" table
-- A quarantined mapping released to suspended (TDD-identity-control-001 1.18.0 §Leaving Quarantine).
CREATE TABLE "identity"."principal_release" (
  "release_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "previous_keycloak_user_id" text NULL,
  "keycloak_user_id" text NOT NULL,
  "quarantine_reason" text NULL,
  "released_by" uuid NOT NULL,
  "reason" text NOT NULL,
  "released_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("release_id"),
  CONSTRAINT "principal_release_principal_id_fkey" FOREIGN KEY ("principal_id") REFERENCES "identity"."principal_mapping" ("principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "principal_release_reason_named" CHECK (btrim(reason) <> ''::text)
);
-- Set comment to table: "principal_release"
COMMENT ON TABLE "identity"."principal_release" IS 'Each release of a quarantined mapping to suspended. Insert-only. TDD-identity-control-001 1.18.0.';
