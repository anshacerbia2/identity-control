package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/anshacerbia2/foundation-platform/idempotency"
)

// mutatingRoute is one route routes.go registers, and the wrapper it is registered with.
type mutatingRoute struct {
	pattern  string
	cmd      bool
	replayed bool
}

// mutatingRoutes reads routes.go for every POST, PUT, PATCH and DELETE it registers.
//
// Read from the source rather than asked of the mux: ServeMux does not list its patterns, and the
// question is what the author wrote, k.cmd( or k.replay( or neither, which is what a reviewer reads
// too. The text after a pattern up to the next registration is its wrapper.
func mutatingRoutes(t *testing.T) []mutatingRoute {
	t.Helper()
	source, err := os.ReadFile("routes.go")
	if err != nil {
		t.Fatalf("read routes.go: %v", err)
	}
	text := string(source)
	pattern := regexp.MustCompile(`(?:api\.HandleFunc|root\.Handle)\("((?:POST|PUT|PATCH|DELETE) [^"]+)",`)
	matches := pattern.FindAllStringSubmatchIndex(text, -1)
	var routes []mutatingRoute
	for i, match := range matches {
		end := len(text)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		// Only the registration statement: its lines up to the one that closes it.
		var statement strings.Builder
		for _, line := range strings.Split(text[match[1]:end], "\n") {
			statement.WriteString(line)
			if strings.HasSuffix(strings.TrimSpace(line), ")") {
				break
			}
		}
		wrapper := statement.String()
		routes = append(routes, mutatingRoute{
			pattern:  text[match[2]:match[3]],
			cmd:      strings.Contains(wrapper, "k.cmd("),
			replayed: strings.Contains(wrapper, "k.replay("),
		})
	}
	// A broken pattern would find nothing and pass everything below.
	if len(routes) < len(serviceKeyed)+len(replayedKey)+len(keyOptional) {
		t.Fatalf("found %d mutating routes in routes.go; the source walk is not working", len(routes))
	}
	return routes
}

// TestEveryMutatingRouteIsClassified holds every mutating route to one decision (STD-GLB-001 1.4.0):
// a command its service keys, a command keyed here, the adoption, or a route keyOptional names with
// its reason. Never two, never none, and each registered with the wrapper its class requires.
func TestEveryMutatingRouteIsClassified(t *testing.T) {
	registered := map[string]bool{}
	for _, route := range mutatingRoutes(t) {
		registered[route.pattern] = true
		classes := 0
		_, service := serviceKeyed[route.pattern]
		_, replayed := replayedKey[route.pattern]
		optional := strings.TrimSpace(keyOptional[route.pattern]) != ""
		adopt := route.pattern == adoptKey
		for _, in := range []bool{service, replayed, optional, adopt} {
			if in {
				classes++
			}
		}
		switch {
		case classes == 0:
			t.Errorf("%s is in no class: wrap it in k.cmd or k.replay and name it, or name it in keyOptional "+
				"with the reason a repeat cannot act twice", route.pattern)
		case classes > 1:
			t.Errorf("%s is in %d classes", route.pattern, classes)
		case service && (!route.cmd || route.replayed):
			t.Errorf("%s is keyed by its service and must be registered through k.cmd", route.pattern)
		case replayed && (!route.replayed || route.cmd):
			t.Errorf("%s is keyed here and must be registered through k.replay", route.pattern)
		case (optional || adopt) && (route.cmd || route.replayed):
			t.Errorf("%s needs no key at the route and is registered through a key wrapper", route.pattern)
		}
	}
	for _, table := range []map[string]string{serviceKeyed, replayedKey, keyOptional} {
		for route := range table {
			if !registered[route] {
				t.Errorf("%s is classified, and routes.go does not register it", route)
			}
		}
	}
	if !registered[adoptKey] {
		t.Errorf("%s is classified, and routes.go does not register it", adoptKey)
	}
}

// memoryLedger keeps keys in memory, as platform.idempotency_key does.
type memoryLedger struct {
	claims   map[string]keyClaim
	answers  map[string]*storedAnswer
	released int
}

func newMemoryLedger() *memoryLedger {
	return &memoryLedger{claims: map[string]keyClaim{}, answers: map[string]*storedAnswer{}}
}

func (m *memoryLedger) take(_ context.Context, k keyClaim) (*storedAnswer, error) {
	id := k.scope + "\x00" + k.key
	held, ok := m.claims[id]
	if !ok {
		m.claims[id] = k
		return nil, nil
	}
	if held.digest != k.digest {
		return nil, idempotency.ErrConflict
	}
	if answer := m.answers[id]; answer != nil {
		return answer, nil
	}
	return nil, idempotency.ErrInProgress
}

func (m *memoryLedger) complete(_ context.Context, k keyClaim, status int, body []byte) error {
	recorded := json.RawMessage("null")
	if len(strings.TrimSpace(string(body))) > 0 && json.Valid(body) {
		recorded = json.RawMessage(strings.TrimSpace(string(body)))
	}
	m.answers[k.scope+"\x00"+k.key] = &storedAnswer{status: status, body: recorded}
	return nil
}

func (m *memoryLedger) release(_ context.Context, k keyClaim) error {
	delete(m.claims, k.scope+"\x00"+k.key)
	m.released++
	return nil
}

func keyedRequest(key, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/registrations/r1/owners", strings.NewReader(body))
	if key != "\x00" {
		r.Header.Set(IdempotencyHeader, key)
	}
	return r.WithContext(WithCallerScope(r.Context(), "principal:operator"))
}

// A command without a usable key is refused 400 naming the header, before its handler runs.
func TestACommandWithoutAKeyIsRefusedNamingTheHeader(t *testing.T) {
	k := commands{ledger: newMemoryLedger()}
	for name, key := range map[string]string{"absent": "\x00", "empty": "", "blank": "   ", "too long": strings.Repeat("k", 256)} {
		for wrapper, wrap := range map[string]func(http.HandlerFunc) http.HandlerFunc{"cmd": k.cmd, "replay": k.replay} {
			ran := false
			w := httptest.NewRecorder()
			wrap(func(http.ResponseWriter, *http.Request) { ran = true })(w, keyedRequest(key, `{}`))
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), IdempotencyHeader) || ran {
				t.Errorf("%s, %s key: answered %d (handler ran: %v), want 400 naming %s:\n%s",
					wrapper, name, w.Code, ran, IdempotencyHeader, w.Body.String())
			}
		}
	}
}

// A retried command is answered what its first request got, and runs once.
func TestARetriedCommandIsAnsweredFromItsKey(t *testing.T) {
	ledger := newMemoryLedger()
	runs := 0
	handler := commands{ledger: ledger}.replay(func(w http.ResponseWriter, _ *http.Request) {
		runs++
		writeJSON(w, http.StatusCreated, map[string]int{"run": runs})
	})
	var answers []string
	for range 2 {
		w := httptest.NewRecorder()
		handler(w, keyedRequest("grant-1", `{"principal_id":"p"}`))
		if w.Code != http.StatusCreated {
			t.Fatalf("answered %d, want 201", w.Code)
		}
		answers = append(answers, strings.TrimSpace(w.Body.String()))
	}
	if runs != 1 || answers[0] != answers[1] {
		t.Errorf("the command ran %d times and answered %q then %q; want once, and the same answer", runs, answers[0], answers[1])
	}

	w := httptest.NewRecorder()
	handler(w, keyedRequest("grant-1", `{"principal_id":"another"}`))
	if w.Code == http.StatusCreated || runs != 1 {
		t.Errorf("the same key on another body answered %d and ran the command; want a conflict", w.Code)
	}
}

// A refusal releases the key, so a corrected retry runs rather than being told the refusal again.
func TestARefusedCommandReleasesItsKey(t *testing.T) {
	ledger := newMemoryLedger()
	refuse := true
	handler := commands{ledger: ledger}.replay(func(w http.ResponseWriter, _ *http.Request) {
		if refuse {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	w := httptest.NewRecorder()
	handler(w, keyedRequest("revoke-1", ``))
	if w.Code != http.StatusConflict || ledger.released != 1 {
		t.Fatalf("a refusal answered %d and released %d key(s); want 409 and 1", w.Code, ledger.released)
	}
	refuse = false
	for range 2 {
		w = httptest.NewRecorder()
		handler(w, keyedRequest("revoke-1", ``))
		if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
			t.Errorf("the retry answered %d with %q, want 204 and no body", w.Code, w.Body.String())
		}
	}
}

// Without a ledger, as in a handler's unit test, the key is still required and the command runs.
func TestWithoutALedgerTheKeyIsRequiredAndNotRecorded(t *testing.T) {
	ran := 0
	handler := commands{}.replay(func(w http.ResponseWriter, _ *http.Request) { ran++; w.WriteHeader(http.StatusNoContent) })
	for range 2 {
		handler(httptest.NewRecorder(), keyedRequest("k", ``))
	}
	if ran != 2 {
		t.Errorf("ran %d times, want 2", ran)
	}
}
