-- Modify "principal_mapping" table
ALTER TABLE "principal_mapping" ADD COLUMN "username" text NOT NULL, ADD COLUMN "email" text NULL;
-- Set comment to column: "username" on table: "principal_mapping"
COMMENT ON COLUMN "principal_mapping"."username" IS 'Creation payload. Recovery reconstructs the kernel call from it; it is not the authoritative username.';
