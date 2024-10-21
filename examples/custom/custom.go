package custom

import (
	"encoding/json"

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

/*
// GetExpirationTime implements the Claims interface.
func (c *CustomClaims) GetExpirationTime() int64 {
	return c.Claims.ExpiresAt
}

// GetNotBefore implements the Claims interface.
func (c *CustomClaims) GetNotBefore() int64 {
	return c.Claims.NotBefore
}

// GetIssuedAt implements the Claims interface.
func (c *CustomClaims) GetIssuedAt() int64 {
	return c.Claims.IssuedAt
}

// GetAudience implements the Claims interface.
func (c *CustomClaims) GetAudience() []string {
	return c.Claims.Audience
}

// GetIssuer implements the Claims interface.
func (c *CustomClaims) GetIssuer() string {
	return c.Claims.Issuer
}

// GetSubject implements the Claims interface.
func (c *CustomClaims) GetSubject() string {
	return c.Claims.Subject
}
*/

// Type implements the Claims interface.
func (c *CustomClaims) Type() string {
	return "PWT"
}

// Marshal implements the Claims interface.
func (c *CustomClaims) Marshal() ([]byte, error) {
	return proto.Marshal(c)
}

// Unmarshal implements the Claims interface.
func (c *CustomClaims) Unmarshal(data []byte) error {
	return proto.Unmarshal(data, c)
}

type JwtCustomClaims struct {
	jwt.RegisteredClaims
	Name string
	Age  int64
}

// GetExpirationTime implements the Claims interface.
func (c *JwtCustomClaims) GetExpirationTime() int64 {
	return c.ExpiresAt
}

// GetNotBefore implements the Claims interface.
func (c *JwtCustomClaims) GetNotBefore() int64 {
	return c.NotBefore
}

// GetIssuedAt implements the Claims interface.
func (c *JwtCustomClaims) GetIssuedAt() int64 {
	return c.IssuedAt
}

// GetAudience implements the Claims interface.
func (c *JwtCustomClaims) GetAudience() []string {
	return c.Audience
}

// GetIssuer implements the Claims interface.
func (c *JwtCustomClaims) GetIssuer() string {
	return c.Issuer
}

// GetSubject implements the Claims interface.
func (c *JwtCustomClaims) GetSubject() string {
	return c.Subject
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
