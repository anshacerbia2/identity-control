-- Modify "client_registration" table
ALTER TABLE "identity"."client_registration" ADD COLUMN "privileged_form" text NULL;
-- Every privileged registration before TDD-identity-control-003 1.29.0 is the provider-scope form:
-- it holds scnehaux-provider, the only privileged scope the kernel declared. Recorded before the
-- check, which requires the form exactly when the class is privileged.
UPDATE "identity"."client_registration" SET "privileged_form" = 'provider-scope' WHERE "audience_class" = 'privileged';
-- Add the check
ALTER TABLE "identity"."client_registration" ADD CONSTRAINT "client_privileged_form_check" CHECK (((audience_class = 'privileged'::text) = (privileged_form IS NOT NULL)) AND ((privileged_form IS NULL) OR (privileged_form = ANY (ARRAY['provider-scope'::text, 'tenant-scoped'::text]))));
