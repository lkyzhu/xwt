package pwt

import (
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	Type = "PWT"
)

// Claims represent any form of a PWT Claims
type Claims interface {
	GetExpirationTime() int64
	GetIssuedAt() int64
	GetNotBefore() int64
	GetIssuer() string
	GetSubject() string
	GetAudience() []string
	protoreflect.ProtoMessage
}
