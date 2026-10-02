-- Modify "registration_change" table
ALTER TABLE "identity"."registration_change" ADD COLUMN "kind" text NOT NULL DEFAULT 'redirect_uris',
  ALTER COLUMN "previous_redirect_uris" DROP NOT NULL,
  ALTER COLUMN "redirect_uris" DROP NOT NULL,
  ADD COLUMN "previous_audience" text[] NULL,
  ADD COLUMN "audience" text[] NULL,
  ADD CONSTRAINT "registration_change_kind_check" CHECK ((kind = ANY (ARRAY['redirect_uris'::text, 'audience'::text])) AND ((kind = 'redirect_uris'::text) = ((redirect_uris IS NOT NULL) AND (previous_redirect_uris IS NOT NULL))) AND ((kind = 'audience'::text) = ((audience IS NOT NULL) AND (previous_audience IS NOT NULL))));
-- Set comment to table: "registration_change"
COMMENT ON TABLE "identity"."registration_change" IS 'A change to a registration''s redirect URIs or audience, proposed, then applied or decided against. TDD-identity-control-003.';
