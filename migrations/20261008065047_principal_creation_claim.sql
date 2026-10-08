-- The creating request's idempotency claim on the mapping, so recovery completes it (TDD-identity-control-001 1.14.0).
-- Modify "principal_mapping" table
ALTER TABLE "principal_mapping" ADD COLUMN "idempotency_scope" text NULL, ADD COLUMN "idempotency_key" text NULL, ADD COLUMN "request_digest" text NULL;
