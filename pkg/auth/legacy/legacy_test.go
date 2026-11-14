// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package legacy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetDefaultClientConfContract(t *testing.T) {
	require := require.New(t)

	cfg1 := GetDefaultClientConf()
	require.Equal("token", cfg1.AuthenticationMethod)
	require.False(cfg1.AuthenticateHeartBeats)
	require.False(cfg1.AuthenticateNewWorkConns)
	require.Empty(cfg1.Token)
	require.Empty(cfg1.OidcClientID)
	require.Empty(cfg1.OidcClientSecret)
	require.Empty(cfg1.OidcAudience)
	require.Empty(cfg1.OidcScope)
	require.Empty(cfg1.OidcTokenEndpointURL)
	require.NotNil(cfg1.OidcAdditionalEndpointParams)
	require.Empty(cfg1.OidcAdditionalEndpointParams)

	// Mutating the map on one instance must not affect another default instance.
	cfg1.OidcAdditionalEndpointParams["custom"] = "val"
	cfg2 := GetDefaultClientConf()
	require.Empty(cfg2.OidcAdditionalEndpointParams)
}

func TestGetDefaultServerConfContract(t *testing.T) {
	require := require.New(t)

	cfg := GetDefaultServerConf()
	require.Equal("token", cfg.AuthenticationMethod)
	require.False(cfg.AuthenticateHeartBeats)
	require.False(cfg.AuthenticateNewWorkConns)
	require.Empty(cfg.Token)
	require.Empty(cfg.OidcIssuer)
	require.Empty(cfg.OidcAudience)
	require.False(cfg.OidcSkipExpiryCheck)
	require.False(cfg.OidcSkipIssuerCheck)
}
