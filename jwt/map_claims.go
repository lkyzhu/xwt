package jwt

import (
	"encoding/json"
	"fmt"

	"github.com/lkyzhu/xwt/internal"
)

// MapClaims is a claims type that uses the map[string]interface{} for JSON
// decoding. This is the default claims type if you don't supply one
type MapClaims map[string]interface{}

// GetExpirationTime implements the Claims interface.
func (m *MapClaims) GetExpirationTime() int64 {
	return m.parseInt64("exp")
}

// GetNotBefore implements the Claims interface.
func (m *MapClaims) GetNotBefore() int64 {
	return m.parseInt64("nbf")
}

// GetIssuedAt implements the Claims interface.
func (m *MapClaims) GetIssuedAt() int64 {
	return m.parseInt64("iat")
}

// GetAudience implements the Claims interface.
func (m *MapClaims) GetAudience() []string {
	return m.parseClaimsString("aud")
}

// GetIssuer implements the Claims interface.
func (m *MapClaims) GetIssuer() string {
	return m.parseString("iss")
}

// GetSubject implements the Claims interface.
func (m *MapClaims) GetSubject() string {
	return m.parseString("sub")
}

// Type implements the Claims interface.
func (m *MapClaims) Type() string {
	return Type
}

// Marshal implements the Claims interface.
func (m *MapClaims) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

// Unmarshal implements the Claims interface.
func (m *MapClaims) Unmarshal(data []byte) error {
	return json.Unmarshal(data, m)
}

// parseInt64 tries to parse a key in the map claims type as a int64
// Tis will succeed, if the underlying type is either a float64 or a json.Number.
// Otherwise, 0 will be returned.
func (m *MapClaims) parseInt64(key string) int64 {
	v, ok := (*m)[key]
	if !ok {
		return 0
	}

	switch exp := v.(type) {
	case float64:
		return int64(exp)
	case int64:
		return exp
	case json.Number:
		v, _ := exp.Int64()
		return v
	}

	return 0
}

// parseNumericDate tries to parse a key in the map claims type as a number
// date. This will succeed, if the underlying type is either a [float64] or a
// [json.Number]. Otherwise, nil will be returned.
func (m *MapClaims) parseNumericDate(key string) (*internal.NumericDate, error) {
	v, ok := (*m)[key]
	if !ok {
		return nil, nil
	}

	switch exp := v.(type) {
	case float64:
		if exp == 0 {
			return nil, nil
		}

		return internal.NewNumericDateFromSeconds(exp), nil
	case json.Number:
		v, _ := exp.Float64()

		return internal.NewNumericDateFromSeconds(v), nil
	}

	return nil, internal.NewError(fmt.Sprintf("%s is invalid", key), internal.ErrInvalidType)
}

// parseClaimsString tries to parse a key in the map claims type as a
// [ClaimsStrings] type, which can either be a string or an array of string.
func (m *MapClaims) parseClaimsString(key string) []string {
	var cs []string
	switch v := (*m)[key].(type) {
	case string:
		cs = append(cs, v)
	case []string:
		cs = v
	case []interface{}:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				return nil
			}
			cs = append(cs, vs)
		}
	}

	return cs
}

// parseString tries to parse a key in the map claims type as a [string] type.
// If the key does not exist, an empty string is returned. If the key has the
// wrong type, an error is returned.
func (m *MapClaims) parseString(key string) string {
	var (
		ok  bool
		raw interface{}
		iss string
	)
	raw, ok = (*m)[key]
	if !ok {
		return ""
	}

	iss, ok = raw.(string)
	if !ok {
		return ""
	}

	return iss
}
