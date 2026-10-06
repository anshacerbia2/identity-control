-- Modify "provider_grant" table
ALTER TABLE "identity"."provider_grant" ADD COLUMN "first_applied_at" timestamptz NOT NULL DEFAULT now();
-- Create "provider_emergency_use" table
CREATE TABLE "identity"."provider_emergency_use" (
  "grant_id" uuid NOT NULL,
  "first_used_at" timestamptz NOT NULL DEFAULT now(),
  "last_used_at" timestamptz NOT NULL DEFAULT now(),
  "uses" bigint NOT NULL DEFAULT 1,
  PRIMARY KEY ("grant_id"),
  CONSTRAINT "provider_emergency_use_grant_fk" FOREIGN KEY ("grant_id") REFERENCES "identity"."provider_grant" ("grant_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "provider_emergency_use_order_check" CHECK (first_used_at <= last_used_at),
  CONSTRAINT "provider_emergency_use_uses_check" CHECK (uses > 0)
);
-- Set comment to table: "provider_emergency_use"
COMMENT ON TABLE "identity"."provider_emergency_use" IS 'The last use of each projected emergency grant, recorded by every request it authorizes. ADR-ORG-002 §5.2, TDD-identity-control-006.';
