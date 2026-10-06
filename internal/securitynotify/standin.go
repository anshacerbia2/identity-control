package securitynotify

import (
	"context"
	"log/slog"
)

// StandIn is the development server's Notification Platform: it accepts every request and logs its
// event and recipient count, never an address (TDD-identity-control-008 §The Adapter). Production
// refuses it, so no deployment there believes a notification was delivered when it was not.
type StandIn struct{ Logger *slog.Logger }

// Deliver accepts the request.
func (s StandIn) Deliver(ctx context.Context, r Request) (string, error) {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.InfoContext(ctx, "the stand-in accepted an account security notification; nothing was delivered",
		slog.String("notification_id", r.NotificationID.String()), slog.String("event", r.Event),
		slog.Int("recipients", len(r.Addresses)))
	return "standin:" + r.NotificationID.String(), nil
}
