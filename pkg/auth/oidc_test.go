package auth_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

type mockTokenVerifier struct{}

func (m *mockTokenVerifier) Verify(ctx context.Context, subject string) (*oidc.IDToken, error) {
	return &oidc.IDToken{
		Subject: subject,
	}, nil
}

func TestPingWithEmptySubjectFromLoginFails(t *testing.T) {
	r := require.New(t)
	consumer := auth.NewOidcAuthVerifier([]v1.AuthScope{v1.AuthScopeHeartBeats}, &mockTokenVerifier{})
	err := consumer.VerifyPing(&msg.Ping{
		PrivilegeKey: "ping-without-login",
		Timestamp:    time.Now().UnixMilli(),
	})
	r.Error(err)
	r.Contains(err.Error(), "received different OIDC subject in login and ping")
}

func TestPingAfterLoginWithNewSubjectSucceeds(t *testing.T) {
	r := require.New(t)
	consumer := auth.NewOidcAuthVerifier([]v1.AuthScope{v1.AuthScopeHeartBeats}, &mockTokenVerifier{})
	err := consumer.VerifyLogin(&msg.Login{
		PrivilegeKey: "ping-after-login",
	})
	r.NoError(err)

	err = consumer.VerifyPing(&msg.Ping{
		PrivilegeKey: "ping-after-login",
		Timestamp:    time.Now().UnixMilli(),
	})
	r.NoError(err)
}

func TestPingAfterLoginWithDifferentSubjectFails(t *testing.T) {
	r := require.New(t)
	consumer := auth.NewOidcAuthVerifier([]v1.AuthScope{v1.AuthScopeHeartBeats}, &mockTokenVerifier{})
	err := consumer.VerifyLogin(&msg.Login{
		PrivilegeKey: "login-with-first-subject",
	})
	r.NoError(err)

	err = consumer.VerifyPing(&msg.Ping{
		PrivilegeKey: "ping-with-different-subject",
		Timestamp:    time.Now().UnixMilli(),
	})
	r.Error(err)
	r.Contains(err.Error(), "received different OIDC subject in login and ping")
}

func TestOidcAuthProviderFallsBackWhenNoExpiry(t *testing.T) {
	r := require.New(t)

	var requestCount atomic.Int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // test-only dummy token response
			"access_token": "fresh-test-token",
			"token_type":   "Bearer",
		})
	}))
	defer tokenServer.Close()

	provider, err := auth.NewOidcAuthSetter(
		[]v1.AuthScope{v1.AuthScopeHeartBeats},
		v1.AuthOIDCClientConfig{
			ClientID:         "test-client",
			ClientSecret:     "test-secret",
			TokenEndpointURL: tokenServer.URL,
		},
	)
	r.NoError(err)

	// Constructor no longer fetches a token eagerly.
	// The first SetLogin triggers the adaptive probe.
	r.Equal(int32(0), requestCount.Load())

	loginMsg := &msg.Login{}
	err = provider.SetLogin(loginMsg)
	r.NoError(err)
	r.Equal("fresh-test-token", loginMsg.PrivilegeKey)

	for range 3 {
		pingMsg := &msg.Ping{}
		err = provider.SetPing(pingMsg)
		r.NoError(err)
		r.Equal("fresh-test-token", pingMsg.PrivilegeKey)
	}

	// 1 probe (login) + 3 pings = 4 requests (probe doubles as the login token fetch)
	r.Equal(int32(4), requestCount.Load(), "each call should fetch a fresh token when expires_in is missing")
}

func TestOidcAuthProviderCachesToken(t *testing.T) {
	r := require.New(t)

	var requestCount atomic.Int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // test-only dummy token response
			"access_token": "cached-test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	provider, err := auth.NewOidcAuthSetter(
		[]v1.AuthScope{v1.AuthScopeHeartBeats},
		v1.AuthOIDCClientConfig{
			ClientID:         "test-client",
			ClientSecret:     "test-secret",
			TokenEndpointURL: tokenServer.URL,
		},
	)
	r.NoError(err)

	// Constructor no longer fetches eagerly; first SetLogin triggers the probe.
	r.Equal(int32(0), requestCount.Load())

	// SetLogin triggers the adaptive probe and caches the token.
	loginMsg := &msg.Login{}
	err = provider.SetLogin(loginMsg)
	r.NoError(err)
	r.Equal("cached-test-token", loginMsg.PrivilegeKey)
	r.Equal(int32(1), requestCount.Load())

	// Subsequent calls should also reuse the cached token
	for range 5 {
		pingMsg := &msg.Ping{}
		err = provider.SetPing(pingMsg)
		r.NoError(err)
		r.Equal("cached-test-token", pingMsg.PrivilegeKey)
	}
	r.Equal(int32(1), requestCount.Load(), "token endpoint should only be called once; cached token should be reused")
}

func TestOidcAuthProviderRetriesOnInitialFailure(t *testing.T) {
	r := require.New(t)

	var requestCount atomic.Int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := requestCount.Add(1)
		// The oauth2 library retries once internally, so we need two
		// consecutive failures to surface an error to the caller.
		if n <= 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":             "temporarily_unavailable",
				"error_description": "service is starting up",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // test-only dummy token response
			"access_token": "retry-test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	// Constructor succeeds even though the IdP is "down".
	provider, err := auth.NewOidcAuthSetter(
		[]v1.AuthScope{v1.AuthScopeHeartBeats},
		v1.AuthOIDCClientConfig{
			ClientID:         "test-client",
			ClientSecret:     "test-secret",
			TokenEndpointURL: tokenServer.URL,
		},
	)
	r.NoError(err)
	r.Equal(int32(0), requestCount.Load())

	// First SetLogin hits the IdP, which returns an error (after internal retry).
	loginMsg := &msg.Login{}
	err = provider.SetLogin(loginMsg)
	r.Error(err)
	r.Equal(int32(2), requestCount.Load())

	// Second SetLogin retries and succeeds.
	err = provider.SetLogin(loginMsg)
	r.NoError(err)
	r.Equal("retry-test-token", loginMsg.PrivilegeKey)
	r.Equal(int32(3), requestCount.Load())

	// Subsequent calls use cached token.
	pingMsg := &msg.Ping{}
	err = provider.SetPing(pingMsg)
	r.NoError(err)
	r.Equal("retry-test-token", pingMsg.PrivilegeKey)
	r.Equal(int32(3), requestCount.Load())
}

func TestNewOidcAuthSetterRejectsInvalidStaticConfig(t *testing.T) {
	r := require.New(t)
	tokenServer := httptest.NewServer(http.NotFoundHandler())
	defer tokenServer.Close()

	_, err := auth.NewOidcAuthSetter(nil, v1.AuthOIDCClientConfig{
		ClientID:         "test-client",
		TokenEndpointURL: "://bad",
	})
	r.Error(err)
	r.Contains(err.Error(), "auth.oidc.tokenEndpointURL")

	_, err = auth.NewOidcAuthSetter(nil, v1.AuthOIDCClientConfig{
		TokenEndpointURL: tokenServer.URL,
	})
	r.Error(err)
	r.Contains(err.Error(), "auth.oidc.clientID is required")

	_, err = auth.NewOidcAuthSetter(nil, v1.AuthOIDCClientConfig{
		ClientID:         "test-client",
		TokenEndpointURL: tokenServer.URL,
		AdditionalEndpointParams: map[string]string{
			"scope": "profile",
		},
	})
	r.Error(err)
	r.Contains(err.Error(), "auth.oidc.additionalEndpointParams.scope is not allowed; use auth.oidc.scope instead")

	_, err = auth.NewOidcAuthSetter(nil, v1.AuthOIDCClientConfig{
		ClientID:                 "test-client",
		TokenEndpointURL:         tokenServer.URL,
		Audience:                 "api",
		AdditionalEndpointParams: map[string]string{"audience": "override"},
	})
	r.Error(err)
	r.Contains(err.Error(), "cannot specify both auth.oidc.audience and auth.oidc.additionalEndpointParams.audience")
}

// subjectTokenVerifier maps a token to the subject it belongs to, so that
// two different tokens can carry the same subject.
type subjectTokenVerifier struct {
	subjects map[string]string
}

func (m *subjectTokenVerifier) Verify(_ context.Context, token string) (*oidc.IDToken, error) {
	subject, ok := m.subjects[token]
	if !ok {
		return nil, errors.New("unknown token")
	}
	return &oidc.IDToken{Subject: subject}, nil
}

// The oidc verifier is built once per server and shared by every control
// session, so the set of subjects that logged in is global. A ping that
// carries the token of a subject that logged in on another session is
// accepted.
//
// This is not an authorization or identity-isolation problem: the identity
// and the privileges of a session are fixed by its login message and are
// never derived from the subject set again. The subject set only decides
// whether a message that carries a token is accepted, and a token that
// verifies against the issuer and has a subject that logged in on this
// server is a credential of that subject, whoever presents it.
func TestPingWithTheSubjectOfAnotherSessionIsAccepted(t *testing.T) {
	r := require.New(t)

	verifier := &subjectTokenVerifier{subjects: map[string]string{
		"token-alice": "alice",
		"token-bob":   "bob",
	}}
	consumer := auth.NewOidcAuthVerifier(
		[]v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}, verifier)

	// Another session of this server logs in as bob.
	r.NoError(consumer.VerifyLogin(&msg.Login{PrivilegeKey: "token-bob"}))

	// The session that logged in as alice accepts a ping that carries bob's
	// token, because the check is against the set of all subjects that
	// logged in on this server.
	r.NoError(consumer.VerifyPing(&msg.Ping{
		PrivilegeKey: "token-bob",
		Timestamp:    time.Now().UnixMilli(),
	}))
	r.NoError(consumer.VerifyNewWorkConn(&msg.NewWorkConn{PrivilegeKey: "token-bob"}))

	// A subject that never logged in on this server is still rejected.
	r.Error(consumer.VerifyPing(&msg.Ping{
		PrivilegeKey: "token-mallory",
		Timestamp:    time.Now().UnixMilli(),
	}))
	r.Error(consumer.VerifyNewWorkConn(&msg.NewWorkConn{PrivilegeKey: "token-mallory"}))
}

func TestOidcAuthProviderScopesAndCustomHTTPClient(t *testing.T) {
	r := require.New(t)

	var receivedAudience, receivedCustomParam string
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		receivedAudience = req.FormValue("audience")
		receivedCustomParam = req.FormValue("resource")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec
			"access_token": "tls-oidc-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tlsServer.Close()

	// Write server's self-signed cert to a CA PEM file
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})
	r.NoError(os.WriteFile(caFile, certPEM, 0o600))

	// 1. With TrustedCaFile + Audience + AdditionalEndpointParams + NewWorkConns scope only
	provider, err := auth.NewOidcAuthSetter(
		[]v1.AuthScope{v1.AuthScopeNewWorkConns},
		v1.AuthOIDCClientConfig{
			ClientID:                 "client-1",
			ClientSecret:             "secret-1",
			Audience:                 "frps-aud",
			Scope:                    "openid",
			TokenEndpointURL:         tlsServer.URL,
			TrustedCaFile:            caFile,
			AdditionalEndpointParams: map[string]string{"resource": "urn:frp"},
		},
	)
	r.NoError(err)

	// SetPing should be a no-op since AuthScopeHeartBeats is not enabled
	pingMsg := &msg.Ping{}
	r.NoError(provider.SetPing(pingMsg))
	r.Empty(pingMsg.PrivilegeKey)

	// SetNewWorkConn should fetch token since AuthScopeNewWorkConns is enabled
	workMsg := &msg.NewWorkConn{}
	r.NoError(provider.SetNewWorkConn(workMsg))
	r.Equal("tls-oidc-token", workMsg.PrivilegeKey)
	r.Equal("frps-aud", receivedAudience)
	r.Equal("urn:frp", receivedCustomParam)

	// 2. With InsecureSkipVerify and ProxyURL
	providerInsecure, err := auth.NewOidcAuthSetter(
		nil,
		v1.AuthOIDCClientConfig{
			ClientID:           "client-1",
			ClientSecret:       "secret-1",
			TokenEndpointURL:   tlsServer.URL,
			InsecureSkipVerify: true,
		},
	)
	r.NoError(err)
	loginMsg := &msg.Login{}
	r.NoError(providerInsecure.SetLogin(loginMsg))
	r.Equal("tls-oidc-token", loginMsg.PrivilegeKey)

	// SetNewWorkConn should be a no-op when AuthScopeNewWorkConns is not enabled
	workMsgNoScope := &msg.NewWorkConn{}
	r.NoError(providerInsecure.SetNewWorkConn(workMsgNoScope))
	r.Empty(workMsgNoScope.PrivilegeKey)

	// 3. Error cases for TrustedCaFile and ProxyURL
	_, err = auth.NewOidcAuthSetter(nil, v1.AuthOIDCClientConfig{
		ClientID:         "client-1",
		TokenEndpointURL: tlsServer.URL,
		TrustedCaFile:    filepath.Join(t.TempDir(), "nonexistent.pem"),
	})
	r.ErrorContains(err, "failed to read OIDC CA certificate file")

	badCAFile := filepath.Join(t.TempDir(), "bad-ca.pem")
	r.NoError(os.WriteFile(badCAFile, []byte("not-a-valid-pem"), 0o600))
	_, err = auth.NewOidcAuthSetter(nil, v1.AuthOIDCClientConfig{
		ClientID:         "client-1",
		TokenEndpointURL: tlsServer.URL,
		TrustedCaFile:    badCAFile,
	})
	r.ErrorContains(err, "failed to parse OIDC CA certificate")

	_, err = auth.NewOidcAuthSetter(nil, v1.AuthOIDCClientConfig{
		ClientID:         "client-1",
		TokenEndpointURL: tlsServer.URL,
		ProxyURL:         "://invalid-proxy-url",
	})
	r.ErrorContains(err, "failed to parse OIDC proxy URL")

	// Valid ProxyURL constructs HTTP client without error
	_, err = auth.NewOidcAuthSetter(nil, v1.AuthOIDCClientConfig{
		ClientID:         "client-1",
		TokenEndpointURL: tlsServer.URL,
		ProxyURL:         "http://127.0.0.1:8080",
	})
	r.NoError(err)
}

func TestOidcTokenSourceAuthProviderAndConsumerScopes(t *testing.T) {
	r := require.New(t)
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "oidc_token")
	r.NoError(os.WriteFile(tokenFile, []byte("  dynamic-oidc-jwt-token \n"), 0o600))

	// 1. BuildClientAuth with OIDC TokenSource
	clientAuth, err := auth.BuildClientAuth(&v1.AuthClientConfig{
		Method:           v1.AuthMethodOIDC,
		AdditionalScopes: []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns},
		OIDC: v1.AuthOIDCClientConfig{
			TokenSource: &v1.ValueSource{
				Type: "file",
				File: &v1.FileSource{Path: tokenFile},
			},
		},
	})
	r.NoError(err)

	loginMsg := &msg.Login{}
	r.NoError(clientAuth.Setter.SetLogin(loginMsg))
	r.Equal("dynamic-oidc-jwt-token", loginMsg.PrivilegeKey)

	pingMsg := &msg.Ping{}
	r.NoError(clientAuth.Setter.SetPing(pingMsg))
	r.Equal("dynamic-oidc-jwt-token", pingMsg.PrivilegeKey)

	workMsg := &msg.NewWorkConn{}
	r.NoError(clientAuth.Setter.SetNewWorkConn(workMsg))
	r.Equal("dynamic-oidc-jwt-token", workMsg.PrivilegeKey)

	// 2. OidcTokenSourceAuthProvider without additional scopes does not populate Ping or NewWorkConn
	noScopeSetter := auth.NewOidcTokenSourceAuthSetter(nil, &v1.ValueSource{
		Type: "file",
		File: &v1.FileSource{Path: tokenFile},
	})
	emptyPing := &msg.Ping{}
	r.NoError(noScopeSetter.SetPing(emptyPing))
	r.Empty(emptyPing.PrivilegeKey)

	emptyWork := &msg.NewWorkConn{}
	r.NoError(noScopeSetter.SetNewWorkConn(emptyWork))
	r.Empty(emptyWork.PrivilegeKey)

	// 3. Error when ValueSource fails to resolve
	brokenSetter := auth.NewOidcTokenSourceAuthSetter(
		[]v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns},
		&v1.ValueSource{
			Type: "file",
			File: &v1.FileSource{Path: filepath.Join(tmpDir, "missing")},
		},
	)
	r.ErrorContains(brokenSetter.SetLogin(&msg.Login{}), "couldn't acquire OIDC token")
	r.ErrorContains(brokenSetter.SetPing(&msg.Ping{}), "couldn't acquire OIDC token")
	r.ErrorContains(brokenSetter.SetNewWorkConn(&msg.NewWorkConn{}), "couldn't acquire OIDC token")

	// 4. OidcAuthConsumer without additional scopes skips verification on Ping and NewWorkConn
	verifier := &subjectTokenVerifier{subjects: map[string]string{"good": "sub1"}}
	noScopeConsumer := auth.NewOidcAuthVerifier(nil, verifier)
	r.ErrorContains(noScopeConsumer.VerifyLogin(&msg.Login{PrivilegeKey: "bad"}), "invalid OIDC token in login")
	r.NoError(noScopeConsumer.VerifyPing(&msg.Ping{PrivilegeKey: "bad"}))
	r.NoError(noScopeConsumer.VerifyNewWorkConn(&msg.NewWorkConn{PrivilegeKey: "bad"}))

	// 5. BuildClientAuth and BuildServerAuth with token method + TokenSource
	sharedTokenFile := filepath.Join(tmpDir, "shared_token")
	r.NoError(os.WriteFile(sharedTokenFile, []byte("file-resolved-secret\n"), 0o600))

	ca, err := auth.BuildClientAuth(&v1.AuthClientConfig{
		Method: v1.AuthMethodToken,
		TokenSource: &v1.ValueSource{
			Type: "file",
			File: &v1.FileSource{Path: sharedTokenFile},
		},
	})
	r.NoError(err)
	r.Equal([]byte("file-resolved-secret"), ca.EncryptionKey())

	sa, err := auth.BuildServerAuth(&v1.AuthServerConfig{
		Method: v1.AuthMethodToken,
		TokenSource: &v1.ValueSource{
			Type: "file",
			File: &v1.FileSource{Path: sharedTokenFile},
		},
	})
	r.NoError(err)
	r.Equal([]byte("file-resolved-secret"), sa.EncryptionKey())

	// Missing token source file returns error in BuildClientAuth / BuildServerAuth
	_, err = auth.BuildClientAuth(&v1.AuthClientConfig{
		Method: v1.AuthMethodToken,
		TokenSource: &v1.ValueSource{
			Type: "file",
			File: &v1.FileSource{Path: filepath.Join(tmpDir, "missing")},
		},
	})
	r.ErrorContains(err, "failed to resolve auth.tokenSource")

	_, err = auth.BuildServerAuth(&v1.AuthServerConfig{
		Method: v1.AuthMethodToken,
		TokenSource: &v1.ValueSource{
			Type: "file",
			File: &v1.FileSource{Path: filepath.Join(tmpDir, "missing")},
		},
	})
	r.ErrorContains(err, "failed to resolve auth.tokenSource")

	// NewTokenVerifier / BuildServerAuth OIDC with discovery server and invalid issuer
	var discoveryServer *httptest.Server
	discoveryServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   discoveryServer.URL,
				"jwks_uri": discoveryServer.URL + "/jwks",
			})
			return
		}
		http.NotFound(w, req)
	}))
	defer discoveryServer.Close()

	oidcServerAuth, err := auth.BuildServerAuth(&v1.AuthServerConfig{
		Method: v1.AuthMethodOIDC,
		OIDC: v1.AuthOIDCServerConfig{
			Issuer:          discoveryServer.URL,
			Audience:        "my-aud",
			SkipExpiryCheck: true,
			SkipIssuerCheck: true,
		},
	})
	r.NoError(err)
	r.NotNil(oidcServerAuth.Verifier)

	_, err = auth.BuildServerAuth(&v1.AuthServerConfig{
		Method: v1.AuthMethodOIDC,
		OIDC: v1.AuthOIDCServerConfig{
			Issuer: "http://127.0.0.1:1",
		},
	})
	r.Error(err)

	// 6. Nil messages and nil dependencies return errors instead of panicking
	r.ErrorContains(clientAuth.Setter.SetLogin(nil), "login message is nil")
	r.ErrorContains(clientAuth.Setter.SetPing(nil), "ping message is nil")
	r.ErrorContains(clientAuth.Setter.SetNewWorkConn(nil), "newWorkConn message is nil")

	nilValueSourceSetter := auth.NewOidcTokenSourceAuthSetter(nil, nil)
	r.ErrorContains(nilValueSourceSetter.SetLogin(&msg.Login{}), "token source is nil")

	scopedConsumer := auth.NewOidcAuthVerifier(
		[]v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns},
		verifier,
	)
	r.ErrorContains(scopedConsumer.VerifyLogin(nil), "login message is nil")
	r.ErrorContains(scopedConsumer.VerifyPing(nil), "ping message is nil")
	r.ErrorContains(scopedConsumer.VerifyNewWorkConn(nil), "newWorkConn message is nil")

	nilVerifierConsumer := auth.NewOidcAuthVerifier(
		[]v1.AuthScope{v1.AuthScopeHeartBeats},
		nil,
	)
	r.ErrorContains(nilVerifierConsumer.VerifyLogin(&msg.Login{PrivilegeKey: "tok"}), "verifier is nil")
	r.ErrorContains(nilVerifierConsumer.VerifyPing(&msg.Ping{PrivilegeKey: "tok"}), "verifier is nil")
}
