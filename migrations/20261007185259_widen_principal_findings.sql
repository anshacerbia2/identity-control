-- The Principal sweep's unmapped, orphan and duplicate branches (TDD-identity-control-001 1.13.0).
-- Replace index "principal_finding_open" on table "principal_finding" with one keyed on the user
DROP INDEX "principal_finding_open"; -- atlas:destructive-approved: replaced by principal_finding_open_user below, reviewed 2026-10-07
-- Modify "principal_finding" table
ALTER TABLE "principal_finding" DROP CONSTRAINT "principal_finding_class_check", ADD CONSTRAINT "principal_finding_class_check" CHECK (finding_class = ANY (ARRAY['dangling'::text, 'unmapped'::text, 'orphan'::text, 'duplicate'::text])), DROP CONSTRAINT "principal_finding_resolution_check", ADD CONSTRAINT "principal_finding_resolution_check" CHECK (((resolved_at IS NULL) = (resolution IS NULL)) AND ((resolution IS NULL) OR (resolution = ANY (ARRAY['relinked'::text, 'user_present'::text, 'user_absent'::text])))), ADD CONSTRAINT "principal_finding_subject_check" CHECK (((finding_class = ANY (ARRAY['dangling'::text, 'duplicate'::text])) AND (principal_id IS NOT NULL) AND (claimed_principal_id IS NULL)) OR ((finding_class = 'unmapped'::text) AND (principal_id IS NULL) AND (claimed_principal_id IS NULL)) OR ((finding_class = 'orphan'::text) AND (principal_id IS NULL) AND (claimed_principal_id IS NOT NULL))), ALTER COLUMN "principal_id" DROP NOT NULL, ADD COLUMN "realm" text NULL, ADD COLUMN "claimed_principal_id" text NULL, ADD COLUMN "username" text NULL, ADD COLUMN "user_disabled" boolean NOT NULL DEFAULT false; -- atlas:destructive-approved: widening CHECKs, reviewed 2026-10-07
-- Every finding until now was a dangling mapping, whose realm is its Principal's.
UPDATE "principal_finding" f SET "realm" = m."realm" FROM "principal_mapping" m WHERE m."principal_id" = f."principal_id";
ALTER TABLE "principal_finding" ALTER COLUMN "realm" SET NOT NULL;
-- Create index "principal_finding_open_user" to table: "principal_finding"
CREATE UNIQUE INDEX "principal_finding_open_user" ON "principal_finding" ("realm", "finding_class", "keycloak_user_id") WHERE (resolved_at IS NULL);
-- Create index "principal_finding_principal" to table: "principal_finding"
CREATE INDEX "principal_finding_principal" ON "principal_finding" ("principal_id") WHERE (principal_id IS NOT NULL);
-- Set comment to table: "principal_finding"
COMMENT ON TABLE "principal_finding" IS 'What the Principal sweep found: a dangling mapping, or an unmapped, orphan or duplicate kernel user. TDD-identity-control-001 1.13.0.';
-- Set comment to column: "keycloak_user_id" on table: "principal_finding"
COMMENT ON COLUMN "principal_finding"."keycloak_user_id" IS 'The kernel user the finding is about: the mapping''s missing user, or the user no mapping accounts for.';
-- Set comment to column: "claimed_principal_id" on table: "principal_finding"
COMMENT ON COLUMN "principal_finding"."claimed_principal_id" IS 'An orphan''s identifier: what the user carries, which no mapping holds and which may not parse.';
-- Set comment to column: "username" on table: "principal_finding"
COMMENT ON COLUMN "principal_finding"."username" IS 'The kernel user''s username when found, so whoever triages it can find the user.';
