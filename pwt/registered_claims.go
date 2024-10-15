package pwt

import (
	"github.com/lkyzhu/xwt/internal"
	"github.com/lkyzhu/xwt/pwt/pb"
	"google.golang.org/protobuf/proto"
)

// RegisteredClaims are a structured version of the pwt Claims Set,
// restricted to Registered Claim Names, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
//
// This type can be used on its own, but then additional private and
// public claims embedded in the pwt will not be parsed. The typical use-case
// therefore is to embedded this in a user-defined claim type.
//
// See examples for how to use this with your own claim types.
type RegisteredClaims struct {
	pb.StandardClaims
}

// GetExpirationTime implements the Claims interface.
func (c *RegisteredClaims) GetExpirationTime() (*internal.NumericDate, error) {
	return internal.NewNumericDateFromSeconds(float64(c.ExpiresAt)), nil
}

// GetNotBefore implements the Claims interface.
func (c *RegisteredClaims) GetNotBefore() (*internal.NumericDate, error) {
	return internal.NewNumericDateFromSeconds(float64(c.NotBefore)), nil
}

// GetIssuedAt implements the Claims interface.
func (c *RegisteredClaims) GetIssuedAt() (*internal.NumericDate, error) {
	return internal.NewNumericDateFromSeconds(float64(c.IssuedAt)), nil
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
func (c *RegisteredClaims) Marshal() ([]byte, error) {
	return proto.Marshal(c)
}

// Unmarshal implements the Claims interface.
func (c *RegisteredClaims) Unmarshal(data []byte) error {
	return proto.Unmarshal(data, c)
}
