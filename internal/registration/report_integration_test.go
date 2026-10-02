package registration

// The report of a production registration a provider created alone (ADR-IAM-003 §5.3, §5.7).

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func (h *harness) captureLogs() *bytes.Buffer {
	var logs bytes.Buffer
	h.service.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return &logs
}

const directReport = "a provider registered a production client directly"

func TestAProvidersDirectProductionRegistrationIsReported(t *testing.T) {
	h := newHarness(t)
	logs := h.captureLogs()
	ctx := context.Background()

	// Outside production nothing is reported.
	if _, err := h.service.Register(ctx, h.request("report-dev", ProfilePublic)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), directReport) {
		t.Fatalf("a non-production registration was reported: %s", logs)
	}

	h.service.cfg.Production = true
	registered, err := h.service.Register(ctx, h.request("report-prod", ProfilePublic))
	if err != nil {
		t.Fatal(err)
	}
	line := logs.String()
	for _, want := range []string{directReport, "client_key=report-prod", "path=registration",
		"registered_by=" + h.caller.String(), "registration_id=" + registered.ID.String()} {
		if !strings.Contains(line, want) {
			t.Errorf("the report lacks %q: %s", want, line)
		}
	}
}

func TestAnApprovedRequestIsNotReportedAsDirect(t *testing.T) {
	h := newHarness(t)
	h.service.cfg.Production = true
	ctx := context.Background()
	developer, colleague, approver := h.developer(), h.person("human"), h.person("human")
	request, _, err := h.service.ProposeRegistration(ctx, h.proposalBy(developer, h.request("report-approved", ProfilePublic), developer, colleague))
	if err != nil {
		t.Fatal(err)
	}
	logs := h.captureLogs()
	if _, err := h.service.DecideRegistration(ctx, h.requestDecision(request, DecisionApprove, approver), true); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), directReport) {
		t.Errorf("an approved request was reported as a direct registration: %s", logs)
	}
}
