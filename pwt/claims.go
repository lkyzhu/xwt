package pwt

import (
	"github.com/lkyzhu/xwt/internal"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	Type = "PWT"
)

// Claims represent any form of a PWT Claims
type Claims interface {
	GetExpirationTime() (*internal.NumericDate, error)
	GetIssuedAt() (*internal.NumericDate, error)
	GetNotBefore() (*internal.NumericDate, error)
	GetIssuer() (string, error)
	GetSubject() (string, error)
	GetAudience() (internal.ClaimStrings, error)
	protoreflect.ProtoMessage
}
