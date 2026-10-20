package securitynotify

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"
)

// catcher is a minimal SMTP listener that records each message, as Mailpit would.
type catcher struct {
	mu       sync.Mutex
	messages []string
	rcpts    []string
}

func startCatcher(t *testing.T) (string, *catcher) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	c := &catcher{}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go c.serve(conn)
		}
	}()
	return l.Addr().String(), c
}

func (c *catcher) held() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.messages...)
}

func (c *catcher) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
	write("220 catcher ready")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(command, "EHLO"), strings.HasPrefix(command, "HELO"):
			write("250 catcher")
		case strings.HasPrefix(command, "MAIL FROM"):
			write("250 ok")
		case strings.HasPrefix(command, "RCPT TO"):
			c.mu.Lock()
			c.rcpts = append(c.rcpts, strings.TrimSpace(line[len("RCPT TO:"):]))
			c.mu.Unlock()
			write("250 ok")
		case command == "DATA":
			write("354 go ahead")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			c.mu.Lock()
			c.messages = append(c.messages, b.String())
			c.mu.Unlock()
			write("250 queued")
		case command == "QUIT":
			write("221 bye")
			return
		default:
			write("250 ok")
		}
	}
}

func TestTheCatcherReceivesOneMessagePerRecipientAndTheLogCarriesNoCodeOrAddress(t *testing.T) {
	address, c := startCatcher(t)
	var logs bytes.Buffer
	adapter := SMTPCatcher{Address: address, From: "identity-control@scnehaux.local", Timeout: 5 * time.Second,
		Logger: slog.New(slog.NewTextHandler(&logs, nil))}
	notification, _ := id.NewV7()
	ref, err := adapter.Deliver(context.Background(), Request{NotificationID: notification, Event: EventAddressProof,
		OccurredAt: time.Now(), Details: map[string]string{"address": "p***@example.test"},
		Addresses: []string{"person@example.test"}, Code: "12345678"})
	if err != nil || ref != "smtp-catcher:"+notification.String() {
		t.Fatalf("deliver: %q, %v", ref, err)
	}
	if got := c.held(); len(got) != 1 || !strings.Contains(got[0], "Your code is 12345678") ||
		!strings.Contains(got[0], "To: person@example.test") {
		t.Fatalf("the catcher holds %q", got)
	}
	if strings.Contains(logs.String(), "12345678") || strings.Contains(logs.String(), "person@example.test") {
		t.Fatalf("the log carries the code or the address: %s", logs.String())
	}

	// Two recipients: two messages, each naming one.
	if _, err := adapter.Deliver(context.Background(), Request{NotificationID: notification, Event: EventAuthenticatorBound,
		OccurredAt: time.Now(), Details: map[string]string{"authenticator": "password", "actor": ActorAdministrator},
		Addresses: []string{"a@example.test", "b@example.test"}}); err != nil {
		t.Fatal(err)
	}
	got := c.held()
	if len(got) != 3 || strings.Contains(got[1], "b@example.test") || strings.Contains(got[2], "a@example.test") {
		t.Fatalf("each recipient must get its own message: %q", got)
	}
	if !strings.Contains(got[1], "authenticator: password") || !strings.Contains(got[1], "contact your administrator") {
		t.Fatalf("the message does not say what happened and how to repudiate it: %q", got[1])
	}
}

func TestTheCatcherRefusesWhatItCannotSend(t *testing.T) {
	adapter := SMTPCatcher{Address: "127.0.0.1:1", From: "x@example.test", Timeout: time.Second}
	if _, err := adapter.Deliver(context.Background(), Request{Addresses: []string{"a@example.test"}}); err == nil {
		t.Fatal("an unreachable catcher accepted a message")
	}
	if _, err := (SMTPCatcher{}).Deliver(context.Background(), Request{Addresses: []string{"a@example.test"}}); err == nil {
		t.Fatal("an unconfigured catcher accepted a message")
	}
	if _, err := (SMTPCatcher{Address: "127.0.0.1:1", From: "x@example.test"}).Deliver(context.Background(), Request{}); err == nil {
		t.Fatal("a request with no recipient was accepted")
	}
	if got := headerValue("a\r\nBcc: x@example.test"); strings.ContainsAny(got, "\r\n") {
		t.Fatalf("a header value kept a line break: %q", got)
	}
}
