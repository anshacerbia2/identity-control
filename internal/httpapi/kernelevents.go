package httpapi

// The kernel event record's sweep on request (TDD-identity-control-007 §API): the scheduled sweep,
// run now, answering what it read and recorded per kind.

import (
	"context"
	"net/http"

	httpapi "github.com/anshacerbia2/foundation-platform/httpapi"

	"github.com/anshacerbia2/identity-control/internal/kernelevents"
)

// KernelEventSweeper sweeps the kernel's event store into the record.
type KernelEventSweeper interface {
	Sweep(ctx context.Context) (kernelevents.Result, error)
}

// kernelEventSweep handles POST /v1/kernel-events:sweep.
func kernelEventSweep(sweeper KernelEventSweeper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := callerPrincipal(r); !ok {
			httpapi.Problem(w, r, httpapi.AuthenticationRequired, "The request carries no authenticated caller")
			return
		}
		result, err := sweeper.Sweep(r.Context())
		if err != nil {
			// The kernel or the database could not be read; the next sweep reads the same window.
			httpapi.Problem(w, r, httpapi.DependencyUnavailable, "The kernel's events could not be swept")
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}
