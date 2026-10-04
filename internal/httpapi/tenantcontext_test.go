package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/tenantcontext"
)

type reporter struct {
	report tenantcontext.Report
	err    error
}

func (r reporter) Report(context.Context) (tenantcontext.Report, error) { return r.report, r.err }

// The report is served to an authenticated caller in organization-control's reconcile shape.
func TestTheTenantReportIsServed(t *testing.T) {
	membership, err := id.Parse("019235f4-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	want := tenantcontext.Report{ConsumerID: "identity-control", Mark: 41,
		Rows: []tenantcontext.ReportedRow{{MembershipID: membership, MembershipVersion: 7}}}
	r := httptest.NewRequest(http.MethodGet, "/v1/projections/tenant-context/report", nil)
	r = r.WithContext(WithCallerScope(r.Context(), "principal:019235f1-0000-7000-8000-000000000001"))
	w := httptest.NewRecorder()
	tenantReport(reporter{report: want})(w, r)
	var got tenantcontext.Report
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusOK || got.Mark != 41 ||
		len(got.Rows) != 1 || got.ConsumerID != "identity-control" {
		t.Errorf("%d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	tenantReport(reporter{err: errors.New("down")})(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("a failed read answered %d", w.Code)
	}
	w = httptest.NewRecorder()
	tenantReport(reporter{report: want})(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no caller answered %d", w.Code)
	}
}
