-- Create "kernel_event" table
CREATE TABLE "identity"."kernel_event" (
  "realm" text NOT NULL,
  "kind" text NOT NULL,
  "kc_event_id" text NOT NULL,
  "occurred_at" timestamptz NOT NULL,
  "event_type" text NOT NULL,
  "kc_user_id" text NULL,
  "principal_id" uuid NULL,
  "client_id" text NULL,
  "session_id" text NULL,
  "ip_address" text NULL,
  "error" text NULL,
  "resource_type" text NULL,
  "resource_path" text NULL,
  "details" jsonb NOT NULL DEFAULT '{}'::jsonb,
  "recorded_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("realm", "kind", "kc_event_id"),
  CONSTRAINT "kernel_event_kind_check" CHECK (kind = ANY (ARRAY['user'::text, 'admin'::text]))
);
-- Create index "kernel_event_occurred" to table: "kernel_event"
CREATE INDEX "kernel_event_occurred" ON "identity"."kernel_event" ("occurred_at");
-- Create index "kernel_event_principal" to table: "kernel_event"
CREATE INDEX "kernel_event_principal" ON "identity"."kernel_event" ("principal_id", "occurred_at");
-- Set comment to table: "kernel_event"
COMMENT ON TABLE "identity"."kernel_event" IS 'Every kernel user and admin event, read from the native store. Insert-only. TDD-identity-control-007.';
-- Create "kernel_event_mark" table
CREATE TABLE "identity"."kernel_event_mark" (
  "realm" text NOT NULL,
  "kind" text NOT NULL,
  "read_through" timestamptz NOT NULL,
  "swept_at" timestamptz NOT NULL,
  "last_read" integer NOT NULL,
  "last_recorded" integer NOT NULL,
  PRIMARY KEY ("realm", "kind"),
  CONSTRAINT "kernel_event_mark_kind_check" CHECK (kind = ANY (ARRAY['user'::text, 'admin'::text]))
);
-- Set comment to table: "kernel_event_mark"
COMMENT ON TABLE "identity"."kernel_event_mark" IS 'The newest kernel event time a complete sweep of each kind read. TDD-identity-control-007.';
