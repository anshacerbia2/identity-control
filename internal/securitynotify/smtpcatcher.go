package securitynotify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"sort"
	"strings"
	"time"
)

// SMTPCatcher is the development server's second adapter (ADR-IAM-007 §5.3, 2026-10-19;
// TDD-identity-control-008 1.7.0 §The Adapter). It renders each request as a plain message and hands
// it by SMTP to a mail catcher in the development stack, such as Mailpit, which delivers nothing. It
// is the one way a proof code reaches a reader there, as it will reach an inbox in production.
//
// Startup refuses it unless IDENTITY_ENVIRONMENT is development. It logs the notification, its event
// and the number of recipients, never an address and never a code: the catcher's mailbox is the only
// place the code is readable.
type SMTPCatcher struct {
	// Address is the catcher's SMTP listener, host:port, on the stack's internal network.
	Address string
	// From is the sender the messages name.
	From string
	// Timeout bounds one message's SMTP exchange.
	Timeout time.Duration
	Logger  *slog.Logger
}

// Deliver sends one message per recipient, so no recipient sees another's address.
func (c SMTPCatcher) Deliver(ctx context.Context, r Request) (string, error) {
	logger := c.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if c.Address == "" || c.From == "" {
		return "", errors.New("securitynotify: the mail catcher's address and sender are required")
	}
	if len(r.Addresses) == 0 {
		return "", errors.New("securitynotify: the request has no recipient")
	}
	subject, body := render(r)
	for _, to := range r.Addresses {
		if err := c.send(ctx, to, subject, body); err != nil {
			// The error names the step and never the recipient or the message.
			return "", err
		}
	}
	logger.InfoContext(ctx, "the development mail catcher received an account security notification",
		slog.String("notification_id", r.NotificationID.String()), slog.String("event", r.Event),
		slog.Int("recipients", len(r.Addresses)))
	return "smtp-catcher:" + r.NotificationID.String(), nil
}

func (c SMTPCatcher) send(ctx context.Context, to, subject, body string) error {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.Address)
	if err != nil {
		return fmt.Errorf("securitynotify: reach the mail catcher: %w", err)
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	host, _, _ := net.SplitHostPort(c.Address)
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("securitynotify: greet the mail catcher: %w", err)
	}
	defer func() { _ = client.Close() }()
	if err := client.Mail(c.From); err != nil {
		return errors.New("securitynotify: the mail catcher refused the sender")
	}
	if err := client.Rcpt(to); err != nil {
		return errors.New("securitynotify: the mail catcher refused a recipient")
	}
	w, err := client.Data()
	if err != nil {
		return errors.New("securitynotify: the mail catcher refused the message")
	}
	message := strings.Join([]string{
		"From: " + headerValue(c.From),
		"To: " + headerValue(to),
		"Subject: " + headerValue(subject),
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"",
		body,
	}, "\r\n")
	if _, err := w.Write([]byte(message)); err != nil {
		_ = w.Close()
		return errors.New("securitynotify: the message could not be written to the mail catcher")
	}
	if err := w.Close(); err != nil {
		return errors.New("securitynotify: the mail catcher did not accept the message")
	}
	return client.Quit()
}

// headerValue keeps a header on one line.
func headerValue(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}

// subjects names each event as the person reads it.
var subjects = map[string]string{
	EventAuthenticatorBound:   "A sign-in method was added to your account",
	EventAuthenticatorRemoved: "A sign-in method was removed from your account",
	EventRecoveryCodesIssued:  "New recovery codes were issued for your account",
	EventAccountRecovered:     "Your account was recovered",
	EventAddressChanged:       "Your notification addresses changed",
	EventAddressProof:         "Your code to prove this address",
}

// render writes the plain message: what happened and when, the bounded details the request carries,
// how to repudiate it, and, for an address proof, the code. It is development-only rendering; in
// production the Notification Platform owns templates (ADR-IAM-007 §5.3).
func render(r Request) (subject, body string) {
	subject = subjects[r.Event]
	if subject == "" {
		subject = "Your account changed"
	}
	subject = "[development] " + subject
	var b strings.Builder
	b.WriteString("This message is from a Scnehaux development server. It was captured by the development\r\n")
	b.WriteString("mail catcher and was not delivered to any inbox.\r\n\r\n")
	if r.Event == EventAddressProof {
		fmt.Fprintf(&b, "Your code is %s\r\n\r\n", r.Code)
		b.WriteString("Enter it in the account application to prove that you read this address. It is good for\r\n")
		b.WriteString("a few minutes and five attempts. If you did not ask for it, ignore this message.\r\n")
		return subject, b.String()
	}
	fmt.Fprintf(&b, "What happened: %s\r\n", r.Event)
	fmt.Fprintf(&b, "When: %s\r\n", r.OccurredAt.UTC().Format(time.RFC3339))
	keys := make([]string, 0, len(r.Details))
	for k := range r.Details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, r.Details[k])
	}
	b.WriteString("\r\nIf you did not make this change, contact your administrator at once and ask them to\r\n")
	b.WriteString("suspend your account.\r\n")
	return subject, b.String()
}
