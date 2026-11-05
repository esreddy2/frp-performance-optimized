// Copyright 2017 fatedier, fatedier@gmail.com
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
	"strings"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/util/util"
)

type HTTPAuthMiddleware struct {
	user          string
	passwd        string
	authFailDelay time.Duration
	mu            sync.Mutex
}

func NewHTTPAuthMiddleware(user, passwd string) *HTTPAuthMiddleware {
	return &HTTPAuthMiddleware{
		user:   user,
		passwd: passwd,
	}
}

func (authMid *HTTPAuthMiddleware) SetAuthFailDelay(delay time.Duration) *HTTPAuthMiddleware {
	authMid.mu.Lock()
	defer authMid.mu.Unlock()
	authMid.authFailDelay = delay
	return authMid
}

func (authMid *HTTPAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authMid.mu.Lock()
		delay := authMid.authFailDelay
		authMid.mu.Unlock()
		reqUser, reqPasswd, hasAuth := r.BasicAuth()
		// Anonymous mode: when no credentials are configured, all requests are
		// allowed without authentication. This is intentional for deployments
		// that rely on network-level protection; set user/passwd to enforce
		// basic auth. (AUD-016)
		if (authMid.user == "" && authMid.passwd == "") ||
			(hasAuth && util.ConstantTimeEqString(reqUser, authMid.user) &&
				util.ConstantTimeEqString(reqPasswd, authMid.passwd)) {
			next.ServeHTTP(w, r)
		} else {
			if delay > 0 {
				time.Sleep(delay)
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}
	})
}

type HTTPGzipWrapper struct {
	h http.Handler
}

func (gw *HTTPGzipWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		gw.h.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Encoding", "gzip")
	gz := gzip.NewWriter(w)
	defer gz.Close()
	gzr := gzipResponseWriter{Writer: gz, ResponseWriter: w}
	gw.h.ServeHTTP(gzr, r)
}

func MakeHTTPGzipHandler(h http.Handler) http.Handler {
	return &HTTPGzipWrapper{
		h: h,
	}
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func (w gzipResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
	if gz, ok := w.Writer.(*gzip.Writer); ok {
		_ = gz.Flush()
	}
}
