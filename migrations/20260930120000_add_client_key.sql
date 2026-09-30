-- Create "client_key" table
CREATE TABLE "client_key" (
  "key_id" uuid NOT NULL,
  "registration_id" uuid NOT NULL,
  "kid" text NOT NULL,
  "thumbprint" text NOT NULL,
  "public_jwk" jsonb NOT NULL,
  "state" text NOT NULL,
  "registered_by" uuid NOT NULL,
  "registered_at" timestamptz NOT NULL DEFAULT now(),
  "expires_at" timestamptz NOT NULL,
  "retiring_at" timestamptz NULL,
  "revoked_at" timestamptz NULL,
  "revoked_by" uuid NULL,
  "revocation_reason" text NULL,
  PRIMARY KEY ("key_id"),
  CONSTRAINT "client_key_registration_id_fkey" FOREIGN KEY ("registration_id") REFERENCES "client_registration" ("registration_id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "client_key_dates_check" CHECK (((state = 'revoked'::text) = (revoked_at IS NOT NULL)) AND (((state = 'retiring'::text) = (retiring_at IS NOT NULL)) OR (state = 'revoked'::text)) AND (expires_at > registered_at)),
  CONSTRAINT "client_key_public_only" CHECK (NOT (public_jwk ?| ARRAY['d'::text, 'p'::text, 'q'::text, 'dp'::text, 'dq'::text, 'qi'::text, 'oth'::text, 'k'::text])),
  CONSTRAINT "client_key_state_check" CHECK (state = ANY (ARRAY['active'::text, 'retiring'::text, 'revoked'::text]))
);
-- Create index "client_key_kid" to table: "client_key"
CREATE UNIQUE INDEX "client_key_kid" ON "client_key" ("registration_id", "kid");
-- Create index "client_key_one_active" to table: "client_key"
CREATE UNIQUE INDEX "client_key_one_active" ON "client_key" ("registration_id") WHERE (state = 'active'::text);
-- Create index "client_key_one_retiring" to table: "client_key"
CREATE UNIQUE INDEX "client_key_one_retiring" ON "client_key" ("registration_id") WHERE (state = 'retiring'::text);
-- Create index "client_key_thumbprint" to table: "client_key"
CREATE UNIQUE INDEX "client_key_thumbprint" ON "client_key" ("thumbprint");
-- Set comment to table: "client_key"
COMMENT ON TABLE "client_key" IS 'A registered public key of a confidential or workload client. TDD-identity-control-003.';
-- Set comment to column: "kid" on table: "client_key"
COMMENT ON COLUMN "client_key"."kid" IS 'The key identifier the client''s assertions name. Defaults to the thumbprint.';
-- Set comment to column: "thumbprint" on table: "client_key"
COMMENT ON COLUMN "client_key"."thumbprint" IS 'RFC 7638 SHA-256 thumbprint. Unique across every client, revoked keys included.';
-- Set comment to column: "retiring_at" on table: "client_key"
COMMENT ON COLUMN "client_key"."retiring_at" IS 'When a retiring key''s rotation overlap ends and it is removed.';
-- Set comment to column: "revoked_by" on table: "client_key"
COMMENT ON COLUMN "client_key"."revoked_by" IS 'The Principal who revoked the key. Null for a removal the schedule made.';
