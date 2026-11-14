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

package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/util"
)

func TestTokenAuthReplayWindow(t *testing.T) {
	fixedNow := time.Unix(1700000000, 0)
	newVerifier := func() *TokenAuthSetterVerifier {
		v := NewTokenAuth([]v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}, "secret-token")
		v.now = func() time.Time { return fixedNow }
		return v
	}

	maxSkew := int64(defaultAuthTimeout.Seconds())

	t.Run("login within window", func(t *testing.T) {
		verifier := newVerifier()
		for _, ts := range []int64{fixedNow.Unix(), fixedNow.Unix() - maxSkew, fixedNow.Unix() + maxSkew} {
			m := &msg.Login{Timestamp: ts}
			require.NoError(t, verifier.SetLogin(m))
			require.NoError(t, verifier.VerifyLogin(m))
		}
	})

	t.Run("login outside window or zero", func(t *testing.T) {
		verifier := newVerifier()
		for _, ts := range []int64{0, -100, fixedNow.Unix() - maxSkew - 1, fixedNow.Unix() + maxSkew + 1} {
			m := &msg.Login{
				Timestamp:    ts,
				PrivilegeKey: util.GetAuthKey("secret-token", ts),
			}
			err := verifier.VerifyLogin(m)
			require.ErrorContains(t, err, "timestamp expired")
		}
	})

	t.Run("login wrong token", func(t *testing.T) {
		verifier := newVerifier()
		m := &msg.Login{
			Timestamp:    fixedNow.Unix(),
			PrivilegeKey: util.GetAuthKey("wrong-token", fixedNow.Unix()),
		}
		err := verifier.VerifyLogin(m)
		require.ErrorContains(t, err, "doesn't match")
	})

	t.Run("SetLogin populates zero timestamp", func(t *testing.T) {
		verifier := newVerifier()
		m := &msg.Login{}
		require.NoError(t, verifier.SetLogin(m))
		require.Equal(t, fixedNow.Unix(), m.Timestamp)
		require.NoError(t, verifier.VerifyLogin(m))
	})

	t.Run("ping replay window", func(t *testing.T) {
		verifier := newVerifier()
		m := &msg.Ping{}
		require.NoError(t, verifier.SetPing(m))
		require.NoError(t, verifier.VerifyPing(m))

		expired := &msg.Ping{
			Timestamp:    fixedNow.Unix() - maxSkew - 1,
			PrivilegeKey: util.GetAuthKey("secret-token", fixedNow.Unix()-maxSkew-1),
		}
		require.ErrorContains(t, verifier.VerifyPing(expired), "timestamp expired")
	})

	t.Run("newWorkConn replay window", func(t *testing.T) {
		verifier := newVerifier()
		m := &msg.NewWorkConn{}
		require.NoError(t, verifier.SetNewWorkConn(m))
		require.NoError(t, verifier.VerifyNewWorkConn(m))

		future := &msg.NewWorkConn{
			Timestamp:    fixedNow.Unix() + maxSkew + 1,
			PrivilegeKey: util.GetAuthKey("secret-token", fixedNow.Unix()+maxSkew+1),
		}
		require.ErrorContains(t, verifier.VerifyNewWorkConn(future), "timestamp expired")
	})

	t.Run("nil messages", func(t *testing.T) {
		verifier := newVerifier()
		require.Error(t, verifier.SetLogin(nil))
		require.Error(t, verifier.SetPing(nil))
		require.Error(t, verifier.SetNewWorkConn(nil))
		require.Error(t, verifier.VerifyLogin(nil))
		require.Error(t, verifier.VerifyPing(nil))
		require.Error(t, verifier.VerifyNewWorkConn(nil))
	})
}

func TestTokenAuthReplayAttackPrevention(t *testing.T) {
	fixedNow := time.Unix(1700000000, 0)
	verifier := NewTokenAuth([]v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}, "secret-token")
	verifier.now = func() time.Time { return fixedNow }

	// 1. Login within the same second is allowed for legitimate concurrency,
	// but replay when time advances must be rejected.
	loginMsg := &msg.Login{Timestamp: fixedNow.Unix()}
	require.NoError(t, verifier.SetLogin(loginMsg))
	require.NoError(t, verifier.VerifyLogin(loginMsg))
	// Concurrent in same second
	require.NoError(t, verifier.VerifyLogin(loginMsg))

	// Replay 10 seconds later
	verifier.now = func() time.Time { return fixedNow.Add(10 * time.Second) }
	err := verifier.VerifyLogin(loginMsg)
	require.Error(t, err)
	require.ErrorContains(t, err, "token replay detected")
	verifier.now = func() time.Time { return fixedNow }

	// 2. Ping within the same second is allowed for legitimate concurrency,
	// but replay when time advances must be rejected.
	pingMsg := &msg.Ping{Timestamp: fixedNow.Unix()}
	require.NoError(t, verifier.SetPing(pingMsg))
	require.NoError(t, verifier.VerifyPing(pingMsg))
	// Concurrent in same second
	require.NoError(t, verifier.VerifyPing(pingMsg))

	// Replay 10 seconds later
	verifier.now = func() time.Time { return fixedNow.Add(10 * time.Second) }
	err = verifier.VerifyPing(pingMsg)
	require.Error(t, err)
	require.ErrorContains(t, err, "token replay detected")
	verifier.now = func() time.Time { return fixedNow }

	// 3. NewWorkConn within the same second is allowed for legitimate concurrency,
	// but past work connection replay when time advances must be rejected.
	workMsg := &msg.NewWorkConn{Timestamp: fixedNow.Unix()}
	require.NoError(t, verifier.SetNewWorkConn(workMsg))
	require.NoError(t, verifier.VerifyNewWorkConn(workMsg))
	// Concurrent in same second
	require.NoError(t, verifier.VerifyNewWorkConn(workMsg))

	// Replay 10 seconds later
	verifier.now = func() time.Time { return fixedNow.Add(10 * time.Second) }
	err = verifier.VerifyNewWorkConn(workMsg)
	require.Error(t, err)
	require.ErrorContains(t, err, "token replay detected")
}

func TestBuildClientServerAuthAndAlwaysPass(t *testing.T) {
	require := require.New(t)

	// 1. AlwaysPassVerifier
	require.NoError(AlwaysPassVerifier.VerifyLogin(&msg.Login{}))
	require.NoError(AlwaysPassVerifier.VerifyPing(&msg.Ping{}))
	require.NoError(AlwaysPassVerifier.VerifyNewWorkConn(&msg.NewWorkConn{}))

	// 2. BuildClientAuth & BuildServerAuth nil and unsupported method errors
	_, err := BuildClientAuth(nil)
	require.ErrorContains(err, "auth config is nil")
	_, err = BuildServerAuth(nil)
	require.ErrorContains(err, "auth config is nil")

	_, err = BuildClientAuth(&v1.AuthClientConfig{Method: "unknown"})
	require.ErrorContains(err, "unsupported auth method")
	_, err = BuildServerAuth(&v1.AuthServerConfig{Method: "unknown"})
	require.ErrorContains(err, "unsupported auth method")

	// 3. BuildClientAuth & BuildServerAuth with token method
	clientAuth, err := BuildClientAuth(&v1.AuthClientConfig{
		Method:           v1.AuthMethodToken,
		Token:            "shared-key",
		AdditionalScopes: []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns},
	})
	require.NoError(err)
	require.Equal([]byte("shared-key"), clientAuth.EncryptionKey())

	serverAuth, err := BuildServerAuth(&v1.AuthServerConfig{
		Method:           v1.AuthMethodToken,
		Token:            "shared-key",
		AdditionalScopes: []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns},
	})
	require.NoError(err)
	require.Equal([]byte("shared-key"), serverAuth.EncryptionKey())

	loginMsg := &msg.Login{}
	require.NoError(clientAuth.Setter.SetLogin(loginMsg))
	require.NoError(serverAuth.Verifier.VerifyLogin(loginMsg))

	pingMsg := &msg.Ping{}
	require.NoError(clientAuth.Setter.SetPing(pingMsg))
	require.NoError(serverAuth.Verifier.VerifyPing(pingMsg))

	workMsg := &msg.NewWorkConn{}
	require.NoError(clientAuth.Setter.SetNewWorkConn(workMsg))
	require.NoError(serverAuth.Verifier.VerifyNewWorkConn(workMsg))
}
