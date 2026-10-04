package tenantcontext

import "testing"

// A type is priority exactly when its class is security, as Organization Control routes its lanes.
func TestPriorityFollowsTheClass(t *testing.T) {
	for _, eventType := range EventTypes {
		want := eventType == MembershipSuspended || eventType == MembershipRevoked || eventType == TenantSuspended ||
			eventType == TenantRestored
		if Priority(eventType) != want {
			t.Errorf("%s: priority %v, want %v", eventType, Priority(eventType), want)
		}
	}
}
