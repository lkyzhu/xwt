package custom

import (
	"encoding/json"

	"github.com/lkyzhu/xwt/internal"
	"github.com/lkyzhu/xwt/jwt"
	"google.golang.org/protobuf/proto"
)

// PwtCustomClaims are a structured version of the pwt Claims Set,
// restricted to Registered Claim Names, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
//
// This type can be used on its own, but then additional private and
// public claims embedded in the pwt will not be parsed. The typical use-case
// therefore is to embedded this in a user-defined claim type.
//
// See examples for how to use this with your own claim types.
type PwtCustomClaims struct {
	CustomClaims
}

// GetExpirationTime implements the Claims interface.
func (c *PwtCustomClaims) GetExpirationTime() (*internal.NumericDate, error) {
	return internal.NewNumericDateFromSeconds(float64(c.Claims.ExpiresAt)), nil
}

// GetNotBefore implements the Claims interface.
func (c *PwtCustomClaims) GetNotBefore() (*internal.NumericDate, error) {
	return internal.NewNumericDateFromSeconds(float64(c.Claims.NotBefore)), nil
}

// GetIssuedAt implements the Claims interface.
func (c *PwtCustomClaims) GetIssuedAt() (*internal.NumericDate, error) {
	return internal.NewNumericDateFromSeconds(float64(c.Claims.IssuedAt)), nil
}

// GetAudience implements the Claims interface.
func (c *PwtCustomClaims) GetAudience() (internal.ClaimStrings, error) {
	return c.Claims.Audience, nil
}

// GetIssuer implements the Claims interface.
func (c *PwtCustomClaims) GetIssuer() (string, error) {
	return c.Claims.Issuer, nil
}

// GetSubject implements the Claims interface.
func (c *PwtCustomClaims) GetSubject() (string, error) {
	return c.Claims.Subject, nil
}

// Type implements the Claims interface.
func (c *PwtCustomClaims) Type() string {
	return "PWT"
}

// Marshal implements the Claims interface.
func (c *PwtCustomClaims) Marshal() ([]byte, error) {
	return proto.Marshal(c)
}

// Unmarshal implements the Claims interface.
func (c *PwtCustomClaims) Unmarshal(data []byte) error {
	return proto.Unmarshal(data, c)
}

type JwtCustomClaims struct {
	jwt.RegisteredClaims
	Name string
	Age  int64
}

// GetExpirationTime implements the Claims interface.
func (c *JwtCustomClaims) GetExpirationTime() (*internal.NumericDate, error) {
	return c.ExpiresAt, nil
}

// GetNotBefore implements the Claims interface.
func (c *JwtCustomClaims) GetNotBefore() (*internal.NumericDate, error) {
	return c.NotBefore, nil
}

// GetIssuedAt implements the Claims interface.
func (c *JwtCustomClaims) GetIssuedAt() (*internal.NumericDate, error) {
	return c.IssuedAt, nil
}

// GetAudience implements the Claims interface.
func (c *JwtCustomClaims) GetAudience() (internal.ClaimStrings, error) {
	return c.Audience, nil
}

// GetIssuer implements the Claims interface.
func (c *JwtCustomClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject implements the Claims interface.
func (c *JwtCustomClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

// Type implements the Claims interface.
func (c *JwtCustomClaims) Type() string {
	return "PWT"
}

// Marshal implements the Claims interface.
func (c *JwtCustomClaims) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

// Unmarshal implements the Claims interface.
func (c *JwtCustomClaims) Unmarshal(data []byte) error {
	return json.Unmarshal(data, c)
}
