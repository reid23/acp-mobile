package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// cfAccess verifies Cloudflare Access JWTs (the Cf-Access-Jwt-Assertion
// header Access adds to every request it lets through), so a request that
// passed Access needs no authkey.
type cfAccess struct {
	issuer   string // https://<team>.cloudflareaccess.com
	audience string // the Access application's AUD tag

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

func newCFAccess(teamDomain, audience string) *cfAccess {
	teamDomain = strings.TrimSuffix(strings.TrimPrefix(teamDomain, "https://"), "/")
	return &cfAccess{issuer: "https://" + teamDomain, audience: audience}
}

func (c *cfAccess) key(kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	// Keys rotate; refetch on an unknown kid, but at most once a minute.
	if time.Since(c.fetched) < time.Minute {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	c.fetched = time.Now()

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(c.issuer + "/cdn-cgi/access/certs")
	if err != nil {
		return nil, fmt.Errorf("fetch certs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch certs: %s", resp.Status)
	}
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode certs: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	c.keys = keys
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

func (c *cfAccess) verify(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("malformed token")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeJWTPart(parts[0], &header); err != nil {
		return fmt.Errorf("header: %w", err)
	}
	if header.Alg != "RS256" {
		return fmt.Errorf("unexpected alg %q", header.Alg)
	}
	key, err := c.key(header.Kid)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return fmt.Errorf("bad signature")
	}

	var claims struct {
		Aud json.RawMessage `json:"aud"`
		Iss string          `json:"iss"`
		Exp int64           `json:"exp"`
		Nbf int64           `json:"nbf"`
	}
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		return fmt.Errorf("claims: %w", err)
	}
	if claims.Iss != c.issuer {
		return fmt.Errorf("unexpected issuer %q", claims.Iss)
	}
	var auds []string
	if err := json.Unmarshal(claims.Aud, &auds); err != nil {
		var aud string
		if err := json.Unmarshal(claims.Aud, &aud); err != nil {
			return fmt.Errorf("bad aud")
		}
		auds = []string{aud}
	}
	found := false
	for _, a := range auds {
		if a == c.audience {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("token is for another application")
	}
	now := time.Now().Unix()
	const skew = 60
	if claims.Exp == 0 || now > claims.Exp+skew {
		return fmt.Errorf("token expired")
	}
	if claims.Nbf != 0 && now+skew < claims.Nbf {
		return fmt.Errorf("token not yet valid")
	}
	return nil
}

// authorized reports whether r carries a valid Access token, in the header
// Access adds or in the CF_Authorization cookie it sets.
func (c *cfAccess) authorized(r *http.Request) bool {
	token := r.Header.Get("Cf-Access-Jwt-Assertion")
	if token == "" {
		if cookie, err := r.Cookie("CF_Authorization"); err == nil {
			token = cookie.Value
		}
	}
	if token == "" {
		return false
	}
	if err := c.verify(token); err != nil {
		log.Printf("cloudflare access token rejected: %v", err)
		return false
	}
	return true
}

func decodeJWTPart(part string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}
