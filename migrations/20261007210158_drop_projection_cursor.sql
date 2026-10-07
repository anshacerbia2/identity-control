-- identity.projection_cursor was TDD-identity-control-002 1.0.0's per-stream watermark for a broker
-- consumer. 2.0.0 takes delivery at POST /v1/deliveries instead, and no version of this service has
-- read or written the table. Dropping it is the contract step of STD-GLB-002's expand/migrate/contract
-- with nothing left to migrate (TDD-identity-control-002 2.4.0).
-- Drop "projection_cursor" table
DROP TABLE "projection_cursor"; -- atlas:destructive-approved: no code reads or writes it (TDD-identity-control-002 2.4.0)
