package httpapi

// A person's own notification addresses (ADR-IAM-007 §5.2, TDD-identity-control-008 1.2.0). Route
// class self: the subject is the Principal in the token. Adding and removing need a recent aal2, as
// removing an authenticator does; proving an address needs only its code.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/anshacerbia2/foundation-platform/httpapi"
	"github.com/anshacerbia2/foundation-platform/id"

	"github.com/anshacerbia2/identity-control/internal/securitynotify"
)

// AddressService serves a person's own addresses: *securitynotify.Addresses.
type AddressService interface {
	List(ctx context.Context, principal id.UUID) ([]securitynotify.Address, error)
	Add(ctx context.Context, principal id.UUID, address string) (securitynotify.Address, error)
	Verify(ctx context.Context, principal, addressID id.UUID, code string) error
	Remove(ctx context.Context, principal, addressID id.UUID) error
}

// UseAddresses mounts the address routes on the self handler.
func (h *Me) UseAddresses(service AddressService) { h.addresses = service }

func writeAddressError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, securitynotify.ErrInvalidAddress):
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The address is not one email address, such as name@example.com")
	case errors.Is(err, securitynotify.ErrNoSuchAddress):
		httpapi.Problem(w, r, httpapi.NotFound, "No such notification address")
	case errors.Is(err, securitynotify.ErrAddressHeld):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, "The address is held already")
	case errors.Is(err, securitynotify.ErrTooMany):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, "Five notification addresses are held already; remove one first")
	case errors.Is(err, securitynotify.ErrLastAddress):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, "The last active notification address cannot be removed; add and prove another first")
	case errors.Is(err, securitynotify.ErrNotPending):
		httpapi.Problem(w, r, httpapi.StateTransitionRefused, "The address is not waiting for a code")
	case errors.Is(err, securitynotify.ErrWrongCode):
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The code is wrong, has expired, or has been tried too often")
	default:
		httpapi.Problem(w, r, httpapi.Internal, "The notification addresses could not be changed")
	}
}

// stepUp answers the challenge when the caller has not authenticated at aal2 recently.
func (h *Me) stepUp(w http.ResponseWriter, r *http.Request) bool {
	_, authTime, ok := Assurance(r.Context())
	if !ok || !h.assurance.meets(r, levelAAL2) || h.now().Sub(authTime) > h.stepUpMaxAge {
		stepUpChallenge(w, r, AcrAAL2, h.stepUpMaxAge)
		return false
	}
	return true
}

// NotificationAddresses handles GET /v1/me/notification-addresses.
func (h *Me) NotificationAddresses(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.caller(w, r)
	if !ok {
		return
	}
	addresses, err := h.addresses.List(r.Context(), principal)
	if err != nil {
		writeAddressError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"notification_addresses": addresses})
}

type addAddressRequest struct {
	Address string `json:"address"`
}

// AddNotificationAddress handles POST /v1/me/notification-addresses.
func (h *Me) AddNotificationAddress(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.caller(w, r)
	if !ok {
		return
	}
	if _, ok := idempotencyKey(r); !ok {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "A non-empty Idempotency-Key header of at most 255 characters is required")
		return
	}
	if !h.stepUp(w, r) {
		return
	}
	var body addAddressRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		httpapi.Problem(w, r, httpapi.ValidationFailed, "The body is not {\"address\": \"...\"}")
		return
	}
	address, err := h.addresses.Add(r.Context(), principal, body.Address)
	if err != nil {
		writeAddressError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"notification_address": address})
}

type verifyAddressRequest struct {
	Code string `json:"code"`
}

// NotificationAddressAction handles POST /v1/me/notification-addresses/{address_id}:verify and
// .../{address_id}:remove.
func (h *Me) NotificationAddressAction(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.caller(w, r)
	if !ok {
		return
	}
	raw, verb, found := strings.Cut(r.PathValue("address_action"), ":")
	addressID, err := id.Parse(raw)
	if !found || err != nil {
		httpapi.Problem(w, r, httpapi.NotFound, "No such notification address")
		return
	}
	switch verb {
	case "verify":
		var body verifyAddressRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil || strings.TrimSpace(body.Code) == "" {
			httpapi.Problem(w, r, httpapi.ValidationFailed, "The body is not {\"code\": \"...\"}")
			return
		}
		if err := h.addresses.Verify(r.Context(), principal, addressID, body.Code); err != nil {
			writeAddressError(w, r, err)
			return
		}
	case "remove":
		if !h.stepUp(w, r) {
			return
		}
		if err := h.addresses.Remove(r.Context(), principal, addressID); err != nil {
			writeAddressError(w, r, err)
			return
		}
	default:
		httpapi.Problem(w, r, httpapi.NotFound, "No such action on a notification address")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
