package signingkey

import "testing"

// RFC 7638 §3.1's own example: the thumbprint of its RSA key is
// NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs.
func TestTheThumbprintIsRFC7638s(t *testing.T) {
	n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	if got := rsaThumbprint("AQAB", n); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Errorf("the thumbprint is %s", got)
	}
}

func TestThePublicKeyAloneIsKept(t *testing.T) {
	if _, err := Thumbprint([]byte(`{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}`)); err == nil {
		t.Error("a JWK with a private exponent was accepted")
	}
	public, err := publicJWK([]byte(`{"kty":"RSA","n":"x","e":"AQAB","kid":"k","x5c":["c"]}`))
	if err != nil || string(public) != `{"alg":"PS256","e":"AQAB","kty":"RSA","n":"x","use":"sig"}` {
		t.Errorf("kept %s, %v", public, err)
	}
}

func TestPeopleAreComparedFolded(t *testing.T) {
	if person(" Alice  Smith ") != person("alice smith") || person("Alice") == person("Bob") {
		t.Error("names are not compared trimmed, case-folded and with whitespace collapsed")
	}
}
