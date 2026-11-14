package client

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// TestCSRFAndOriginProtection_CANON065 verifies that state-changing requests
// with cross-site / cross-origin headers are rejected with HTTP 403 Forbidden.
func TestCSRFAndOriginProtection_CANON065(t *testing.T) {
	require := require.New(t)

	svr := &Service{
		common: &v1.ClientCommonConfig{
			WebServer: v1.WebServerConfig{
				Addr: "127.0.0.1",
				Port: 7400,
			},
		},
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := svr.csrfMiddleware(nextHandler)

	tests := []struct {
		name           string
		method         string
		url            string
		host           string
		headers        map[string]string
		expectedStatus int
	}{
		{
			name:           "GET is safe with external Origin",
			method:         http.MethodGet,
			url:            "/api/status",
			host:           "127.0.0.1:7400",
			headers:        map[string]string{"Origin": "http://evil.com"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST rejected when Sec-Fetch-Site is cross-site",
			method:         http.MethodPost,
			url:            "/api/reload",
			host:           "127.0.0.1:7400",
			headers:        map[string]string{"Sec-Fetch-Site": "cross-site"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "POST rejected when Origin is evil.com",
			method:         http.MethodPost,
			url:            "/api/stop",
			host:           "127.0.0.1:7400",
			headers:        map[string]string{"Origin": "http://evil.com"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "PUT rejected when Origin is attacker.com",
			method:         http.MethodPut,
			url:            "/api/config",
			host:           "127.0.0.1:7400",
			headers:        map[string]string{"Origin": "http://attacker.com"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "DELETE rejected when Origin is evil.com",
			method:         http.MethodDelete,
			url:            "/api/store/proxies/p1",
			host:           "127.0.0.1:7400",
			headers:        map[string]string{"Origin": "http://evil.com"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "POST rejected when Referer is evil.com",
			method:         http.MethodPost,
			url:            "/api/reload",
			host:           "127.0.0.1:7400",
			headers:        map[string]string{"Referer": "http://evil.com/csrf.html"},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "POST accepted when Origin matches Host",
			method:         http.MethodPost,
			url:            "/api/reload",
			host:           "127.0.0.1:7400",
			headers:        map[string]string{"Origin": "http://127.0.0.1:7400"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST accepted when Origin matches WebServer port loopback localhost",
			method:         http.MethodPost,
			url:            "/api/reload",
			host:           "127.0.0.1:7400",
			headers:        map[string]string{"Origin": "http://localhost:7400"},
			expectedStatus: http.StatusOK,
		},
		{
			name:   "POST accepted with same-origin Sec-Fetch-Site and matching Origin",
			method: http.MethodPost,
			url:    "/api/stop",
			host:   "127.0.0.1:7400",
			headers: map[string]string{
				"Sec-Fetch-Site": "same-origin",
				"Origin":         "http://127.0.0.1:7400",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "CLI / curl request without browser headers is accepted",
			method:         http.MethodPost,
			url:            "/api/reload",
			host:           "127.0.0.1:7400",
			headers:        map[string]string{},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, nil)
			req.Host = tc.host
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			require.Equal(tc.expectedStatus, rec.Code)
		})
	}
}
