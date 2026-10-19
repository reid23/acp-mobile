package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func signTestJWT(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(header) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestCFAccessVerify(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	c := newCFAccess("team.cloudflareaccess.com", "aud-1")
	c.keys = map[string]*rsa.PublicKey{"k1": &key.PublicKey}
	c.fetched = time.Now() // no network fetches in tests

	now := time.Now().Unix()
	header := map[string]any{"alg": "RS256", "kid": "k1"}
	claims := func(mod func(map[string]any)) map[string]any {
		m := map[string]any{
			"aud": []string{"aud-1"},
			"iss": "https://team.cloudflareaccess.com",
			"exp": now + 3600,
			"nbf": now - 10,
		}
		if mod != nil {
			mod(m)
		}
		return m
	}

	cases := []struct {
		name  string
		token string
		ok    bool
	}{
		{"valid", signTestJWT(t, key, header, claims(nil)), true},
		{"string aud", signTestJWT(t, key, header, claims(func(m map[string]any) { m["aud"] = "aud-1" })), true},
		{"other app", signTestJWT(t, key, header, claims(func(m map[string]any) { m["aud"] = []string{"aud-2"} })), false},
		{"other team", signTestJWT(t, key, header, claims(func(m map[string]any) { m["iss"] = "https://evil.cloudflareaccess.com" })), false},
		{"expired", signTestJWT(t, key, header, claims(func(m map[string]any) { m["exp"] = now - 3600 })), false},
		{"forged", signTestJWT(t, other, header, claims(nil)), false},
		{"unknown kid", signTestJWT(t, key, map[string]any{"alg": "RS256", "kid": "k9"}, claims(nil)), false},
		{"alg none", signTestJWT(t, key, map[string]any{"alg": "none", "kid": "k1"}, claims(nil)), false},
		{"garbage", "not.a.jwt", false},
	}
	for _, tc := range cases {
		if err := c.verify(tc.token); (err == nil) != tc.ok {
			t.Errorf("%s: verify err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}

	valid := signTestJWT(t, key, header, claims(nil))
	r := httptest.NewRequest("GET", "/", nil)
	if c.authorized(r) {
		t.Error("request without token authorized")
	}
	r.Header.Set("Cf-Access-Jwt-Assertion", valid)
	if !c.authorized(r) {
		t.Error("request with header token rejected")
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "CF_Authorization="+valid)
	if !c.authorized(r) {
		t.Error("request with cookie token rejected")
	}
}
