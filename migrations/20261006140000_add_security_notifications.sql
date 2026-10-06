-- Create "notification_address" table
CREATE TABLE "identity"."notification_address" (
  "address_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "channel" text NOT NULL,
  "address" text NOT NULL,
  "origin" text NOT NULL,
  "state" text NOT NULL,
  "added_at" timestamptz NOT NULL DEFAULT now(),
  "verified_at" timestamptz NULL,
  "removed_at" timestamptz NULL,
  PRIMARY KEY ("address_id"),
  CONSTRAINT "notification_address_channel_check" CHECK (channel = 'email'::text),
  CONSTRAINT "notification_address_origin_check" CHECK (origin = ANY (ARRAY['creation'::text, 'added'::text])),
  CONSTRAINT "notification_address_removed_check" CHECK ((state = 'removed'::text) = (removed_at IS NOT NULL)),
  CONSTRAINT "notification_address_state_check" CHECK (state = ANY (ARRAY['pending'::text, 'active'::text, 'removed'::text]))
);
-- Create index "notification_address_held" to table: "notification_address"
CREATE UNIQUE INDEX "notification_address_held" ON "identity"."notification_address" ("principal_id", (lower(address))) WHERE (state <> 'removed'::text);
-- Set comment to table: "notification_address"
COMMENT ON TABLE "identity"."notification_address" IS 'A Principal''s notification addresses: the creation email first, others proven. ADR-IAM-007 §5.2, TDD-identity-control-008.';
-- Create "security_notification" table
CREATE TABLE "identity"."security_notification" (
  "notification_id" uuid NOT NULL,
  "principal_id" uuid NOT NULL,
  "event" text NOT NULL,
  "source_key" text NOT NULL,
  "occurred_at" timestamptz NOT NULL,
  "details" jsonb NOT NULL DEFAULT '{}'::jsonb,
  "recipients" uuid[] NOT NULL,
  "state" text NOT NULL,
  "attempts" integer NOT NULL DEFAULT 0,
  "next_attempt_at" timestamptz NOT NULL DEFAULT now(),
  "platform_ref" text NULL,
  "last_error" text NULL,
  "requested_at" timestamptz NOT NULL DEFAULT now(),
  "submitted_at" timestamptz NULL,
  PRIMARY KEY ("notification_id"),
  CONSTRAINT "security_notification_event_check" CHECK (event = ANY (ARRAY['authenticator_bound'::text, 'authenticator_removed'::text, 'recovery_codes_issued'::text, 'account_recovered'::text, 'notification_address_changed'::text])),
  CONSTRAINT "security_notification_state_check" CHECK (state = ANY (ARRAY['requested'::text, 'submitted'::text, 'failed'::text, 'no_address'::text])),
  CONSTRAINT "security_notification_submitted_check" CHECK ((state = 'submitted'::text) = (submitted_at IS NOT NULL))
);
-- Create index "security_notification_due" to table: "security_notification"
CREATE INDEX "security_notification_due" ON "identity"."security_notification" ("next_attempt_at") WHERE (state = 'requested'::text);
-- Create index "security_notification_principal" to table: "security_notification"
CREATE INDEX "security_notification_principal" ON "identity"."security_notification" ("principal_id", "occurred_at");
-- Create index "security_notification_source" to table: "security_notification"
CREATE UNIQUE INDEX "security_notification_source" ON "identity"."security_notification" ("source_key");
-- Set comment to table: "security_notification"
COMMENT ON TABLE "identity"."security_notification" IS 'Each account security notification requested, once per event, with its recipients at the event. ADR-IAM-007, TDD-identity-control-008.';
-- The creation address of every human Principal made before this design (TDD-identity-control-008
-- §Data Model): the email it was created with is its first notification address.
INSERT INTO "identity"."notification_address" ("address_id", "principal_id", "channel", "address", "origin", "state", "added_at")
SELECT gen_random_uuid(), "principal_id", 'email', "email", 'creation', 'active', now()
FROM "identity"."principal_mapping"
WHERE "subject_type" = 'human' AND "email" IS NOT NULL AND btrim("email") <> ''
ON CONFLICT DO NOTHING;
