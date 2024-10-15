package jwt

import (
	"encoding/json"

	"github.com/lkyzhu/xwt/internal"
)

// RegisteredClaims are a structured version of the JWT Claims Set,
// restricted to Registered Claim Names, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
//
// This type can be used on its own, but then additional private and
// public claims embedded in the JWT will not be parsed. The typical use-case
// therefore is to embedded this in a user-defined claim type.
//
// See examples for how to use this with your own claim types.
type RegisteredClaims struct {
	// the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`

	// the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience internal.ClaimStrings `json:"aud,omitempty"`

	// the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	ExpiresAt *internal.NumericDate `json:"exp,omitempty"`

	// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore *internal.NumericDate `json:"nbf,omitempty"`

	// the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt *internal.NumericDate `json:"iat,omitempty"`

	// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	ID string `json:"jti,omitempty"`
}

// GetExpirationTime implements the Claims interface.
func (c *RegisteredClaims) GetExpirationTime() (*internal.NumericDate, error) {
	return c.ExpiresAt, nil
}

// GetNotBefore implements the Claims interface.
func (c *RegisteredClaims) GetNotBefore() (*internal.NumericDate, error) {
	return c.NotBefore, nil
}

// GetIssuedAt implements the Claims interface.
func (c *RegisteredClaims) GetIssuedAt() (*internal.NumericDate, error) {
	return c.IssuedAt, nil
}

// GetAudience implements the Claims interface.
func (c *RegisteredClaims) GetAudience() (internal.ClaimStrings, error) {
	return c.Audience, nil
}

// GetIssuer implements the Claims interface.
func (c *RegisteredClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject implements the Claims interface.
func (c *RegisteredClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

// Type implements the Claims interface.
func (c *RegisteredClaims) Type() string {
	return Type
}

// Marshal implements the Claims interface.
func (m *RegisteredClaims) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

// Unmarshal implements the Claims interface.
func (m *RegisteredClaims) Unmarshal(data []byte) error {
	return json.Unmarshal(data, m)
}
