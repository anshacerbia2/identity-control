-- principal_mapping_realm_user, a partial unique index on (realm, keycloak_user_id), is redundant with
-- principal_mapping_keycloak_user_id_key, which already holds every non-null keycloak_user_id unique
-- (TDD-identity-control-001 1.18.0). An index holds no data, and no statement names it.
DROP INDEX "identity"."principal_mapping_realm_user"; -- atlas:destructive-approved: a redundant index, the invariant kept by the column's unique constraint, reviewed 2026-10-09
