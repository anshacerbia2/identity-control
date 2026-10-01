package registration

import (
	"context"
	"errors"
	"testing"

	"github.com/anshacerbia2/foundation-platform/id"
)

// An ownership change is refused before any database is read when it names nobody or gives no reason.
func TestAnOwnershipChangeNamesItsPartiesAndAReason(t *testing.T) {
	someone, _ := id.NewV7()
	service := &Service{}
	for name, change := range map[string]OwnershipChange{
		"nothing":         {},
		"no registration": {Principal: someone, ChangedBy: someone, Reason: "r"},
		"no principal":    {RegistrationID: someone, ChangedBy: someone, Reason: "r"},
		"no caller":       {RegistrationID: someone, Principal: someone, Reason: "r"},
		"no reason":       {RegistrationID: someone, Principal: someone, ChangedBy: someone, Reason: "  "},
	} {
		if _, err := service.GrantOwner(context.Background(), change); !errors.Is(err, ErrInvalid) {
			t.Errorf("a grant naming %s answered %v, want ErrInvalid", name, err)
		}
		if _, err := service.RevokeOwner(context.Background(), change); !errors.Is(err, ErrInvalid) {
			t.Errorf("a revocation naming %s answered %v, want ErrInvalid", name, err)
		}
	}
}
