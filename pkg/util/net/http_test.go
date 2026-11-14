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

package net

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHTTPAuthMiddleware(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("authorized"))
	})

	t.Run("anonymous mode allows unauthenticated requests", func(t *testing.T) {
		mw := NewHTTPAuthMiddleware("", "").Middleware(okHandler)
		req := httptest.NewRequest(http.MethodGet, "/status", nil)
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "authorized", rec.Body.String())
	})

	t.Run("enforces basic auth credentials and fail delay", func(t *testing.T) {
		authMid := NewHTTPAuthMiddleware("admin", "s3cr3t").SetAuthFailDelay(15 * time.Millisecond)
		mw := authMid.Middleware(okHandler)

		// Valid credentials succeed immediately.
		reqValid := httptest.NewRequest(http.MethodGet, "/status", nil)
		reqValid.SetBasicAuth("admin", "s3cr3t")
		recValid := httptest.NewRecorder()
		mw.ServeHTTP(recValid, reqValid)
		require.Equal(t, http.StatusOK, recValid.Code)
		require.Equal(t, "authorized", recValid.Body.String())

		// Missing credentials return 401 with WWW-Authenticate header after delay.
		reqMissing := httptest.NewRequest(http.MethodGet, "/status", nil)
		recMissing := httptest.NewRecorder()
		start := time.Now()
		mw.ServeHTTP(recMissing, reqMissing)
		elapsed := time.Since(start)
		require.Equal(t, http.StatusUnauthorized, recMissing.Code)
		require.Equal(t, `Basic realm="Restricted"`, recMissing.Header().Get("WWW-Authenticate"))
		require.GreaterOrEqual(t, elapsed, 10*time.Millisecond)

		// Wrong password returns 401.
		authMid.SetAuthFailDelay(0)
		reqWrong := httptest.NewRequest(http.MethodGet, "/status", nil)
		reqWrong.SetBasicAuth("admin", "wrong")
		recWrong := httptest.NewRecorder()
		mw.ServeHTTP(recWrong, reqWrong)
		require.Equal(t, http.StatusUnauthorized, recWrong.Code)
	})
}

func TestMakeHTTPGzipHandler(t *testing.T) {
	payload := "compressible response payload for gzip handler testing"
	handler := MakeHTTPGzipHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(payload))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))

	t.Run("plain response when Accept-Encoding does not include gzip", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/data", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.Empty(t, rec.Header().Get("Content-Encoding"))
		require.Equal(t, payload, rec.Body.String())
	})

	t.Run("gzipped response when Accept-Encoding includes gzip", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/data", nil)
		req.Header.Set("Accept-Encoding", "deflate, gzip, br")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, "gzip", rec.Header().Get("Content-Encoding"))
		require.True(t, rec.Flushed)

		zr, err := gzip.NewReader(rec.Body)
		require.NoError(t, err)
		defer zr.Close()
		decompressed, err := io.ReadAll(zr)
		require.NoError(t, err)
		require.Equal(t, payload, string(decompressed))
	})
}
