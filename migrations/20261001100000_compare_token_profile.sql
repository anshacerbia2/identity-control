-- Modify "registration_finding" table
-- Widens the field classes by one value, 'token_format'. Every row that satisfied the old CHECK satisfies
-- the new one, so dropping and re-adding it can refuse nothing and loses nothing.
ALTER TABLE "registration_finding" DROP CONSTRAINT "registration_finding_field_check", ADD CONSTRAINT "registration_finding_field_check" CHECK ((field_class IS NULL) OR (field_class = ANY (ARRAY['redirect_uris'::text, 'token_lifespan'::text, 'audience_scope'::text, 'signing_algorithm'::text, 'profile'::text, 'client_keys'::text, 'suspension'::text, 'token_format'::text]))); -- atlas:destructive-approved: widening a CHECK, reviewed 2026-10-01
