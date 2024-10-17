package xwt

// Claims represent any form of a *WT(JWT/PWT) Claims
type Claims interface {
	GetExpirationTime() int64
	GetIssuedAt() int64
	GetNotBefore() int64
	GetIssuer() string
	GetSubject() string
	GetAudience() []string
	Type() string
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
}
