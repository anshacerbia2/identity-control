// Package securityref seals and opens the opaque handles this service hands a browser for one
// session, authenticator, consent or federation link (TDD-identity-control-005 §Technical
// Context).
//
// A handle carries the kernel identifier, which never leaves this service in the clear. It is sealed
// with AEAD_AES_256_GCM (RFC 5116): the plaintext is confidential and authenticated, and so is the
// associated data, which here binds the handle to its kind, the subject Principal and its purpose. A
// handle issued for one of those fails authentication when opened for another, rather than decrypting
// to an identifier that could be replayed against a different route or Principal.
package securityref

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/anshacerbia2/foundation-platform/id"
)

// Kind is what a handle names.
type Kind string

// The kinds a handle names.
const (
	KindSession       Kind = "session"
	KindCredential    Kind = "credential"
	KindConsent       Kind = "consent"
	KindFederatedLink Kind = "federation-link"
)

// ErrInvalid is any handle that does not open: tampered, expired, sealed for another kind, subject
// or purpose, or under a key no longer held. One error for all of them, so a caller probing handles
// learns nothing about which check failed.
var ErrInvalid = errors.New("securityref: the reference is not valid here")

// Key is one key of the ring: an identifier and 32 bytes, the AES-256 key size.
type Key struct {
	ID     string
	Secret []byte
}

var kidPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// Codec seals with the ring's first key and opens with any key still in it, so a rotation keeps the
// previous key for one TTL and handles sealed before it still open.
type Codec struct {
	keys []Key
	aead map[string]cipher.AEAD
	ttl  time.Duration
	now  func() time.Time
}

// New builds a codec over a key ring, the first key sealing.
func New(keys []Key, ttl time.Duration) (*Codec, error) {
	switch {
	case len(keys) == 0:
		return nil, errors.New("securityref: a key ring needs at least one key")
	case len(keys) > 2:
		return nil, errors.New("securityref: a key ring holds the sealing key and at most one previous key")
	case ttl <= 0:
		return nil, errors.New("securityref: the reference lifetime must be positive")
	}
	codec := &Codec{keys: keys, aead: map[string]cipher.AEAD{}, ttl: ttl, now: time.Now}
	for _, key := range keys {
		if !kidPattern.MatchString(key.ID) {
			return nil, fmt.Errorf("securityref: key id %q is not a short token", key.ID)
		}
		if _, seen := codec.aead[key.ID]; seen {
			return nil, fmt.Errorf("securityref: key id %q appears twice", key.ID)
		}
		if len(key.Secret) != 32 {
			return nil, fmt.Errorf("securityref: key %q is %d bytes; AES-256 needs 32", key.ID, len(key.Secret))
		}
		block, err := aes.NewCipher(key.Secret)
		if err != nil {
			return nil, fmt.Errorf("securityref: key %q: %w", key.ID, err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("securityref: key %q: %w", key.ID, err)
		}
		codec.aead[key.ID] = gcm
	}
	return codec, nil
}

// LoadKeyRing reads a key ring file: {"keys":[{"kid":"k1","key":"<base64 of 32 bytes>"}]}, the first
// key sealing. The file is a secret and its value never appears in an error.
func LoadKeyRing(path string) ([]Key, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("securityref: read the key ring: %w", err)
	}
	var file struct {
		Keys []struct {
			KID string `json:"kid"`
			Key string `json:"key"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, errors.New("securityref: the key ring is not the expected JSON")
	}
	keys := make([]Key, 0, len(file.Keys))
	for _, k := range file.Keys {
		secret, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil {
			return nil, fmt.Errorf("securityref: key %q is not base64", k.KID)
		}
		keys = append(keys, Key{ID: k.KID, Secret: secret})
	}
	return keys, nil
}

// Ref is what a handle stands for once opened.
type Ref struct {
	Kind      Kind
	Principal id.UUID
	Purpose   string
	Realm     string
	KernelID  string
	Expires   time.Time
}

type payload struct {
	KernelID string `json:"k"`
	Realm    string `json:"r"`
	Expires  int64  `json:"e"`
}

func associated(kind Kind, principal id.UUID, purpose, kid string) []byte {
	return []byte(strings.Join([]string{"scnehaux.securityref.v1", string(kind), principal.String(), purpose, kid}, "|"))
}

var encoding = base64.RawURLEncoding

// Seal makes a handle for one kernel object of the Principal, for one purpose.
func (c *Codec) Seal(kind Kind, principal id.UUID, purpose, realm, kernelID string) (string, error) {
	if kind == "" || principal.IsNil() || purpose == "" || kernelID == "" {
		return "", errors.New("securityref: a reference names its kind, Principal, purpose and object")
	}
	key := c.keys[0]
	plain, err := json.Marshal(payload{KernelID: kernelID, Realm: realm, Expires: c.now().Add(c.ttl).Unix()})
	if err != nil {
		return "", fmt.Errorf("securityref: encode: %w", err)
	}
	gcm := c.aead[key.ID]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("securityref: nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plain, associated(kind, principal, purpose, key.ID))
	return key.ID + "." + encoding.EncodeToString(sealed), nil
}

// Open returns what a handle stands for, when it was sealed for this kind, Principal and purpose
// and has not expired.
func (c *Codec) Open(handle string, kind Kind, principal id.UUID, purpose string) (Ref, error) {
	kid, body, found := strings.Cut(handle, ".")
	gcm, known := c.aead[kid]
	if !found || !known {
		return Ref{}, ErrInvalid
	}
	sealed, err := encoding.DecodeString(body)
	if err != nil || len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return Ref{}, ErrInvalid
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, associated(kind, principal, purpose, kid))
	if err != nil {
		return Ref{}, ErrInvalid
	}
	var p payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return Ref{}, ErrInvalid
	}
	expires := time.Unix(p.Expires, 0).UTC()
	if !c.now().Before(expires) {
		return Ref{}, ErrInvalid
	}
	return Ref{Kind: kind, Principal: principal, Purpose: purpose, Realm: p.Realm, KernelID: p.KernelID, Expires: expires}, nil
}
