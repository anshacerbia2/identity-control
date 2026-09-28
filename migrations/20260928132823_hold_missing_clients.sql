-- Modify "registration_finding" table
-- Widens the finding classes by one value, 'missing'. Every row that satisfied the old CHECK satisfies
-- the new one, so dropping and re-adding it can refuse nothing and loses nothing.
ALTER TABLE "registration_finding" DROP CONSTRAINT "registration_finding_class_check", ADD CONSTRAINT "registration_finding_class_check" CHECK (finding_class = ANY (ARRAY['repaired'::text, 'blocked'::text, 'sanctioned'::text, 'unattributed'::text, 'missing'::text, 'recreated'::text, 'unmanaged'::text])); -- atlas:destructive-approved: widening a CHECK, reviewed 2026-09-28
