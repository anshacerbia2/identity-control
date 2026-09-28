-- Modify "principal_mapping" table
ALTER TABLE "principal_mapping" ADD CONSTRAINT "principal_mapping_active_linked_check" CHECK ((state <> 'active'::text) OR (keycloak_user_id IS NOT NULL));
-- Create "principal_finding" table
CREATE TABLE "principal_finding" (
  "finding_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "finding_class" text NOT NULL,
  "keycloak_user_id" text NOT NULL,
  "detected_at" timestamptz NOT NULL DEFAULT now(),
  "resolved_at" timestamptz NULL,
  "resolution" text NULL,
  PRIMARY KEY ("finding_id"),
  CONSTRAINT "principal_finding_principal_id_fkey" FOREIGN KEY ("principal_id") REFERENCES "principal_mapping" ("principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "principal_finding_class_check" CHECK (finding_class = 'dangling'::text),
  CONSTRAINT "principal_finding_resolution_check" CHECK (((resolved_at IS NULL) = (resolution IS NULL)) AND ((resolution IS NULL) OR (resolution = ANY (ARRAY['relinked'::text, 'user_present'::text]))))
);
-- Create index "principal_finding_open" to table: "principal_finding"
CREATE UNIQUE INDEX "principal_finding_open" ON "principal_finding" ("principal_id") WHERE (resolved_at IS NULL);
-- Set comment to table: "principal_finding"
COMMENT ON TABLE "principal_finding" IS 'A dangling mapping: an active Principal whose Keycloak user is gone. TDD-identity-control-001.';
-- Set comment to column: "keycloak_user_id" on table: "principal_finding"
COMMENT ON COLUMN "principal_finding"."keycloak_user_id" IS 'The user the mapping pointed at when it was found missing.';
-- Create "principal_relink" table
CREATE TABLE "principal_relink" (
  "relink_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "previous_keycloak_user_id" text NOT NULL,
  "relinked_by" uuid NOT NULL,
  "reason" text NOT NULL,
  "relinked_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("relink_id"),
  CONSTRAINT "principal_relink_principal_id_fkey" FOREIGN KEY ("principal_id") REFERENCES "principal_mapping" ("principal_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "principal_relink_reason_named" CHECK (btrim(reason) <> ''::text)
);
-- Set comment to table: "principal_relink"
COMMENT ON TABLE "principal_relink" IS 'Each relink of an active mapping back to pending. Insert-only. TDD-identity-control-001.';
