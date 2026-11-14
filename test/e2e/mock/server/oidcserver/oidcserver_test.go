package oidcserver

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func parseClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Equal(t, 3, len(parts), "JWT must have 3 parts")

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	err = json.Unmarshal(claimsBytes, &claims)
	require.NoError(t, err)
	return claims
}

func TestOIDCServerJWTExpirationConfigurable(t *testing.T) {
	// 1. With configured ExpiresIn = 120 seconds
	s := New(WithExpiresIn(120))
	require.NoError(t, s.Run())
	defer s.Close()

	token, err := s.signJWT()
	require.NoError(t, err)

	claims := parseClaims(t, token)
	iat := int64(claims["iat"].(float64))
	exp := int64(claims["exp"].(float64))
	require.Equal(t, int64(120), exp-iat, "JWT exp should be exactly 120 seconds after iat")

	// 2. Default with ExpiresIn = 0 (defaults to 1 hour = 3600 seconds)
	sDefault := New(WithExpiresIn(0))
	require.NoError(t, sDefault.Run())
	defer sDefault.Close()

	tokenDefault, err := sDefault.signJWT()
	require.NoError(t, err)

	claimsDefault := parseClaims(t, tokenDefault)
	iatDef := int64(claimsDefault["iat"].(float64))
	expDef := int64(claimsDefault["exp"].(float64))
	require.Equal(t, int64(3600), expDef-iatDef, "JWT exp default should be 1 hour (3600s)")
}

func TestOIDCServerEndpoints(t *testing.T) {
	s := New(WithBindPort(0), WithExpiresIn(300))
	require.NoError(t, s.Run())
	defer s.Close()

	require.NotEmpty(t, s.Issuer())
	require.NotEmpty(t, s.TokenEndpoint())
	require.Equal(t, int64(0), s.TokenRequestCount())
}
