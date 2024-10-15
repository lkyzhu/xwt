package xwt

import "github.com/lkyzhu/xwt/internal"

// Claims represent any form of a *WT(JWT/PWT) Claims
type Claims interface {
	GetExpirationTime() (*internal.NumericDate, error)
	GetIssuedAt() (*internal.NumericDate, error)
	GetNotBefore() (*internal.NumericDate, error)
	GetIssuer() (string, error)
	GetSubject() (string, error)
	GetAudience() (internal.ClaimStrings, error)
	Type() string
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
}
