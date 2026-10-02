package httpapi

// X-Administrative-Reason is refused unless it is visible US-ASCII (STD-GLB-001 §Request Header
// Values, RFC 9110 §5.5).

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAReasonOutsideVisibleASCIIIsRefusedBeforeTheHandler(t *testing.T) {
	for name, c := range map[string]struct {
		value  string
		set    bool
		status int
	}{
		"absent":                 {"", false, http.StatusNoContent},
		"ascii":                  {"move to the API's own resource (STD-IAM-002 section 3.1)", true, http.StatusNoContent},
		"with a tab":             {"rotate\tthe key", true, http.StatusNoContent},
		"utf-8 section sign":     {"STD-IAM-002 §3.1", true, http.StatusBadRequest},
		"latin-1 section sign":   {"STD-IAM-002 \xa73.1", true, http.StatusBadRequest},
		"a control character":    {"reason\x01", true, http.StatusBadRequest},
		"an indonesian sentence": {"pindah ke resource API sendiri", true, http.StatusNoContent},
	} {
		t.Run(name, func(t *testing.T) {
			reached := false
			handler := reasonHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			}))
			r := httptest.NewRequest(http.MethodPost, "/v1/registrations/x/changes", nil)
			if c.set {
				r.Header[AdministrativeReasonHeader] = []string{c.value}
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != c.status || reached != (c.status == http.StatusNoContent) {
				t.Errorf("answered %d (handler reached %t), want %d", w.Code, reached, c.status)
			}
		})
	}
}
