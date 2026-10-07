-- Modify "client_registration" table
-- The per-sign-in privileged form (ADR-IAM-008 §5.1, TDD-identity-control-003 1.32.0).
ALTER TABLE "identity"."client_registration" DROP CONSTRAINT "client_privileged_form_check", ADD CONSTRAINT "client_privileged_form_check" CHECK (((audience_class = 'privileged'::text) = (privileged_form IS NOT NULL)) AND ((privileged_form IS NULL) OR (privileged_form = ANY (ARRAY['provider-scope'::text, 'tenant-scoped'::text, 'per-sign-in'::text])))); -- atlas:destructive-approved: widening a CHECK, reviewed 2026-10-07
