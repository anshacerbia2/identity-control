-- Modify "bootstrap_ceremony" table
--
-- The witness (STD-IAM-001 2.9.0 §3.10). Added nullable, written on a row claimed before it existed,
-- then made NOT NULL, so the migration also applies to a database whose ceremony already ran. That
-- row names no witness because none was recorded, and says so rather than naming someone.
ALTER TABLE "bootstrap_ceremony" ADD COLUMN "witness" text NULL;
UPDATE "bootstrap_ceremony" SET "witness" = 'not recorded: the ceremony ran before a witness was recorded'
 WHERE "witness" IS NULL;
ALTER TABLE "bootstrap_ceremony" ALTER COLUMN "witness" SET NOT NULL;
ALTER TABLE "bootstrap_ceremony" ADD CONSTRAINT "bootstrap_ceremony_witness_check" CHECK ((btrim(witness) <> ''::text) AND (lower(btrim(witness)) <> lower(btrim(operator))));
-- Create index "bootstrap_ceremony_review_key" to table: "bootstrap_ceremony"
CREATE UNIQUE INDEX "bootstrap_ceremony_review_key" ON "bootstrap_ceremony" ("id", "operator", "witness", "principal_id");
-- Set comment to column: "witness" on table: "bootstrap_ceremony"
COMMENT ON COLUMN "bootstrap_ceremony"."witness" IS 'The second named person who witnessed the ceremony. Never the operator. STD-IAM-001 §3.10.';
-- Modify "registration_finding" table
ALTER TABLE "registration_finding" DROP CONSTRAINT "registration_finding_field_check", ADD CONSTRAINT "registration_finding_field_check" CHECK ((field_class IS NULL) OR (field_class = ANY (ARRAY['redirect_uris'::text, 'token_lifespan'::text, 'audience_scope'::text, 'signing_algorithm'::text, 'profile'::text, 'client_keys'::text, 'suspension'::text, 'token_format'::text, 'audience'::text, 'logout'::text, 'consent'::text]))); -- atlas:destructive-approved: widening a CHECK, reviewed 2026-10-20
-- Modify "security_operation" table
ALTER TABLE "security_operation" DROP CONSTRAINT "security_operation_type_check", ADD CONSTRAINT "security_operation_type_check" CHECK (operation_type = ANY (ARRAY['suspend'::text, 'restore'::text, 'sessions.terminate-all'::text, 'authenticator.revoke'::text, 'session.terminate'::text, 'authenticator.remove'::text, 'consent.withdraw'::text])); -- atlas:destructive-approved: widening a CHECK, reviewed 2026-10-20
-- Create "bootstrap_ceremony_review" table
CREATE TABLE "bootstrap_ceremony_review" (
  "review_id" uuid NOT NULL,
  "ceremony_id" integer NOT NULL,
  "operator" text NOT NULL,
  "witness" text NOT NULL,
  "ceremony_principal_id" uuid NOT NULL,
  "reviewer" text NOT NULL,
  "reviewer_principal_id" uuid NOT NULL,
  "outcome" text NOT NULL,
  "statement" text NOT NULL,
  "correlation_id" text NOT NULL,
  "reviewed_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("review_id"),
  CONSTRAINT "bootstrap_ceremony_review_ceremony_fkey" FOREIGN KEY ("ceremony_id", "operator", "witness", "ceremony_principal_id") REFERENCES "bootstrap_ceremony" ("id", "operator", "witness", "principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "bootstrap_ceremony_review_independent" CHECK ((lower(btrim(reviewer)) <> lower(btrim(operator))) AND (lower(btrim(reviewer)) <> lower(btrim(witness))) AND (reviewer_principal_id <> ceremony_principal_id)),
  CONSTRAINT "bootstrap_ceremony_review_named" CHECK ((btrim(reviewer) <> ''::text) AND (btrim(statement) <> ''::text) AND (btrim(correlation_id) <> ''::text)),
  CONSTRAINT "bootstrap_ceremony_review_outcome_check" CHECK (outcome = ANY (ARRAY['satisfactory'::text, 'findings'::text]))
);
-- Set comment to table: "bootstrap_ceremony_review"
COMMENT ON TABLE "bootstrap_ceremony_review" IS 'Each independent review of the bootstrap ceremony''s record. Insert-only. STD-IAM-001 §3.10, ADR-IAM-001 §5.11.';
-- Set comment to column: "reviewer" on table: "bootstrap_ceremony_review"
COMMENT ON COLUMN "bootstrap_ceremony_review"."reviewer" IS 'The reviewer''s name, a member of Security or of the Architecture Authority.';
-- Set comment to column: "reviewer_principal_id" on table: "bootstrap_ceremony_review"
COMMENT ON COLUMN "bootstrap_ceremony_review"."reviewer_principal_id" IS 'The Principal whose token recorded the review.';
-- Modify "principal_finding" table
ALTER TABLE "principal_finding" DROP CONSTRAINT "principal_finding_resolution_check", ADD CONSTRAINT "principal_finding_resolution_check" CHECK (((resolved_at IS NULL) = (resolution IS NULL)) AND ((resolution IS NULL) OR (resolution = ANY (ARRAY['relinked'::text, 'user_present'::text, 'user_absent'::text, 'adopted'::text])))); -- atlas:destructive-approved: widening a CHECK, reviewed 2026-10-20
-- Create "principal_adoption" table
CREATE TABLE "principal_adoption" (
  "adoption_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "finding_id" uuid NOT NULL,
  "realm" text NOT NULL,
  "keycloak_user_id" text NOT NULL,
  "identifier_time" timestamptz NOT NULL,
  "newest_mapping_at" timestamptz NULL,
  "creation_event_id" text NOT NULL,
  "creation_event_at" timestamptz NOT NULL,
  "adopted_by" uuid NOT NULL,
  "reason" text NOT NULL,
  "adopted_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("adoption_id"),
  CONSTRAINT "principal_adoption_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "principal_finding" ("finding_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "principal_adoption_principal_id_fkey" FOREIGN KEY ("principal_id") REFERENCES "principal_mapping" ("principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "principal_adoption_newer_check" CHECK ((newest_mapping_at IS NULL) OR (identifier_time > newest_mapping_at)),
  CONSTRAINT "principal_adoption_not_self" CHECK (adopted_by <> principal_id),
  CONSTRAINT "principal_adoption_reason_named" CHECK ((btrim(reason) <> ''::text) AND (btrim(creation_event_id) <> ''::text))
);
-- Create index "principal_adoption_finding_key" to table: "principal_adoption"
CREATE UNIQUE INDEX "principal_adoption_finding_key" ON "principal_adoption" ("finding_id");
-- Set comment to table: "principal_adoption"
COMMENT ON TABLE "principal_adoption" IS 'Each re-adoption of an orphan''s identifier after a restore to an older point. Insert-only. ADR-IAM-001 §5.11, TDD-identity-control-001 1.23.0.';
-- Set comment to column: "finding_id" on table: "principal_adoption"
COMMENT ON COLUMN "principal_adoption"."finding_id" IS 'The open orphan finding that named the identifier.';
