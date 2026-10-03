package securityref

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"
)

func key(id string, fill byte) Key { return Key{ID: id, Secret: bytes.Repeat([]byte{fill}, 32)} }

func principal(t *testing.T) id.UUID {
	t.Helper()
	p, err := id.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func codec(t *testing.T, keys ...Key) (*Codec, *time.Time) {
	t.Helper()
	c, err := New(keys, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	return c, &now
}

func TestAHandleOpensOnlyForWhatItWasSealedFor(t *testing.T) {
	c, _ := codec(t, key("k1", 1))
	alice, bob := principal(t), principal(t)
	handle, err := c.Seal(KindCredential, alice, "revoke", "scnehaux", "kc-credential-1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(handle, "kc-credential-1") {
		t.Fatal("the kernel identifier is visible in the handle")
	}
	ref, err := c.Open(handle, KindCredential, alice, "revoke")
	if err != nil || ref.KernelID != "kc-credential-1" || ref.Realm != "scnehaux" {
		t.Fatalf("Open: %+v, %v", ref, err)
	}
	for name, open := range map[string]func() error{
		"another Principal": func() error { _, err := c.Open(handle, KindCredential, bob, "revoke"); return err },
		"another kind":      func() error { _, err := c.Open(handle, KindSession, alice, "revoke"); return err },
		"another purpose":   func() error { _, err := c.Open(handle, KindCredential, alice, "terminate"); return err },
		"a flipped byte": func() error {
			tampered := handle[:len(handle)-2] + string("AB"[len(handle)%2])
			_, err := c.Open(tampered, KindCredential, alice, "revoke")
			return err
		},
		"no kid":       func() error { _, err := c.Open("nokid", KindCredential, alice, "revoke"); return err },
		"unknown kid":  func() error { _, err := c.Open("k9."+handle[3:], KindCredential, alice, "revoke"); return err },
		"not base64":   func() error { _, err := c.Open("k1.!!!", KindCredential, alice, "revoke"); return err },
		"empty sealed": func() error { _, err := c.Open("k1.", KindCredential, alice, "revoke"); return err },
	} {
		if err := open(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestAHandleExpires(t *testing.T) {
	c, now := codec(t, key("k1", 1))
	alice := principal(t)
	handle, _ := c.Seal(KindSession, alice, "terminate", "scnehaux", "s1")
	*now = now.Add(9 * time.Minute)
	if _, err := c.Open(handle, KindSession, alice, "terminate"); err != nil {
		t.Errorf("within the TTL: %v", err)
	}
	*now = now.Add(time.Minute)
	if _, err := c.Open(handle, KindSession, alice, "terminate"); !errors.Is(err, ErrInvalid) {
		t.Errorf("at the TTL: %v, want ErrInvalid", err)
	}
}

// A rotation seals with the new key and still opens what the previous one sealed.
func TestARotationKeepsThePreviousKeyForOpening(t *testing.T) {
	old, _ := codec(t, key("k1", 1))
	alice := principal(t)
	handle, _ := old.Seal(KindSession, alice, "terminate", "scnehaux", "s1")

	rotated, _ := codec(t, key("k2", 2), key("k1", 1))
	if _, err := rotated.Open(handle, KindSession, alice, "terminate"); err != nil {
		t.Errorf("a handle from before the rotation: %v", err)
	}
	fresh, _ := rotated.Seal(KindSession, alice, "terminate", "scnehaux", "s1")
	if !strings.HasPrefix(fresh, "k2.") {
		t.Errorf("sealed with %q, want the first key k2", fresh[:3])
	}

	dropped, _ := codec(t, key("k2", 2))
	if _, err := dropped.Open(handle, KindSession, alice, "terminate"); !errors.Is(err, ErrInvalid) {
		t.Errorf("a handle under a dropped key: %v", err)
	}
}

func TestNewRefusesAWeakOrMalformedRing(t *testing.T) {
	for name, keys := range map[string][]Key{
		"none":         nil,
		"three keys":   {key("a", 1), key("b", 2), key("c", 3)},
		"short key":    {{ID: "k1", Secret: []byte("short")}},
		"repeated kid": {key("k1", 1), key("k1", 2)},
		"bad kid":      {{ID: "has space", Secret: bytes.Repeat([]byte{1}, 32)}},
	} {
		if _, err := New(keys, time.Minute); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := New([]Key{key("k1", 1)}, 0); err == nil {
		t.Error("a zero TTL was accepted")
	}
}

func TestLoadKeyRing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring.json")
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if err := os.WriteFile(path, []byte(`{"keys":[{"kid":"k1","key":"`+secret+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadKeyRing(path)
	if err != nil || len(keys) != 1 || keys[0].ID != "k1" || len(keys[0].Secret) != 32 {
		t.Fatalf("LoadKeyRing: %+v, %v", keys, err)
	}
	if err := os.WriteFile(path, []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyRing(path); err == nil || strings.Contains(err.Error(), "not json") {
		t.Errorf("a malformed ring: %v", err)
	}
	if _, err := LoadKeyRing(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("an absent ring loaded")
	}
}

func TestSealRefusesAnIncompleteReference(t *testing.T) {
	c, _ := codec(t, key("k1", 1))
	if _, err := c.Seal(KindSession, id.UUID{}, "terminate", "scnehaux", "s1"); err == nil {
		t.Error("a reference with no Principal was sealed")
	}
	if _, err := c.Seal(KindSession, principal(t), "terminate", "scnehaux", ""); err == nil {
		t.Error("a reference with no object was sealed")
	}
}

// An accepted command's handle opens after its TTL, and only for what it was sealed for.
func TestAnAcceptedHandleOpensWithoutItsExpiry(t *testing.T) {
	c, now := codec(t, key("k1", 1))
	alice, bob := principal(t), principal(t)
	handle, _ := c.Seal(KindCredential, alice, PurposeAdminRevoke, "scnehaux", "kc-credential-1")
	*now = now.Add(time.Hour)
	if _, err := c.Open(handle, KindCredential, alice, PurposeAdminRevoke); !errors.Is(err, ErrInvalid) {
		t.Errorf("Open after the TTL: %v, want ErrInvalid", err)
	}
	ref, err := c.OpenAccepted(handle, KindCredential, alice, PurposeAdminRevoke)
	if err != nil || ref.KernelID != "kc-credential-1" {
		t.Errorf("OpenAccepted: %+v, %v", ref, err)
	}
	if _, err := c.OpenAccepted(handle, KindCredential, bob, PurposeAdminRevoke); !errors.Is(err, ErrInvalid) {
		t.Errorf("OpenAccepted for another Principal: %v, want ErrInvalid", err)
	}
}
