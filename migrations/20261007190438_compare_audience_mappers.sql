-- Modify "registration_finding" table
-- The audience field class (TDD-identity-control-003 1.33.0).
ALTER TABLE "registration_finding" DROP CONSTRAINT "registration_finding_field_check", ADD CONSTRAINT "registration_finding_field_check" CHECK ((field_class IS NULL) OR (field_class = ANY (ARRAY['redirect_uris'::text, 'token_lifespan'::text, 'audience_scope'::text, 'signing_algorithm'::text, 'profile'::text, 'client_keys'::text, 'suspension'::text, 'token_format'::text, 'audience'::text]))); -- atlas:destructive-approved: widening a CHECK, reviewed 2026-10-07
