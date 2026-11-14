package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func TestHTTPHelpersAndCanonicalHost(t *testing.T) {
	require := require.New(t)

	// 1. OkResponse & ProxyUnauthorizedResponse
	okResp := OkResponse()
	require.Equal(http.StatusOK, okResp.StatusCode)
	require.Equal("OK", okResp.Status)

	unauthResp := ProxyUnauthorizedResponse()
	require.Equal(http.StatusProxyAuthRequired, unauthResp.StatusCode)
	require.Contains(unauthResp.Header.Get("Proxy-Authenticate"), "Basic")

	// 2. CanonicalHost (domain, trailing dot, IPv4:port, IPv6, [IPv6]:port, invalid port)
	h, err := CanonicalHost("Example.COM:8080")
	require.NoError(err)
	require.Equal("example.com", h)

	h, err = CanonicalHost("Sub.Example.COM.")
	require.NoError(err)
	require.Equal("sub.example.com", h)

	h, err = CanonicalHost("::1")
	require.NoError(err)
	require.Equal("::1", h)

	h, err = CanonicalHost("[::1]:8443")
	require.NoError(err)
	require.Equal("::1", h)

	_, err = CanonicalHost("bad:host:port")
	// 2 colons without brackets -> hasPort is false, returned as-is
	require.NoError(err)

	_, err = CanonicalHost("[::1]:80:90")
	require.Error(err)

	// 3. BasicAuth & ParseBasicAuth
	hdr := BasicAuth("alice", "s3cr:t")
	u, p, ok := ParseBasicAuth(hdr)
	require.True(ok)
	require.Equal("alice", u)
	require.Equal("s3cr:t", p)

	// Case-insensitive "basic " prefix
	u, p, ok = ParseBasicAuth("basic " + strings.TrimPrefix(hdr, "Basic "))
	require.True(ok)
	require.Equal("alice", u)
	require.Equal("s3cr:t", p)

	// Invalid BasicAuth cases
	_, _, ok = ParseBasicAuth("Bearer token")
	require.False(ok)
	_, _, ok = ParseBasicAuth("Basic $$$not-base64$$$")
	require.False(ok)
	_, _, ok = ParseBasicAuth("Basic YWx5Y2U=") // "alyce" without colon
	require.False(ok)
}

func TestContextErrorMiddlewareAndHandlers(t *testing.T) {
	require := require.New(t)

	// 1. Error nil-safety & Unwrap
	var nilErr *Error
	require.Equal("", nilErr.Error())
	require.Nil(nilErr.Unwrap())
	emptyErr := &Error{Code: http.StatusBadRequest}
	require.Equal("", emptyErr.Error())

	apiErr := NewError(http.StatusBadRequest, "bad input")
	require.Equal("bad input", apiErr.Error())
	require.ErrorIs(fmt.Errorf("wrapped: %w", apiErr), apiErr.Unwrap())

	// 2. Context Param, Query, BindJSON, Body, MakeHTTPHandlerFunc, MakeHTTPHandlerFuncV2, NewRequestLogger
	router := mux.NewRouter()
	router.Use(NewRequestLogger)

	router.HandleFunc("/v1/echo/{id}", MakeHTTPHandlerFunc(func(ctx *Context) (any, error) {
		var payload map[string]string
		if err := ctx.BindJSON(&payload); err != nil {
			return nil, NewError(http.StatusBadRequest, "invalid json")
		}
		return map[string]string{
			"id":  ctx.Param("id"),
			"q":   ctx.Query("q"),
			"msg": payload["msg"],
		}, nil
	})).Methods("POST")

	router.HandleFunc("/v1/raw", MakeHTTPHandlerFunc(func(ctx *Context) (any, error) {
		b, err := ctx.Body()
		if err != nil {
			return nil, err
		}
		if string(b) == "string" {
			return "str-resp", nil
		}
		if string(b) == "nil" {
			return nil, nil
		}
		if string(b) == "err" {
			return nil, errors.New("internalboom")
		}
		return b, nil
	})).Methods("POST")

	router.HandleFunc("/v2/item", MakeHTTPHandlerFuncV2(func(ctx *Context) (any, error) {
		if ctx.Query("fail") == "1" {
			return nil, fmt.Errorf("wrapped: %w", NewError(http.StatusUnprocessableEntity, "bad v2"))
		}
		return map[string]int{"count": 42}, nil
	})).Methods("GET")

	// Test JSON response
	req := httptest.NewRequest("POST", "/v1/echo/99?q=search", strings.NewReader(`{"msg":"hi"}`))
	rw := httptest.NewRecorder()
	router.ServeHTTP(rw, req)
	require.Equal(http.StatusOK, rw.Code)
	var out map[string]string
	require.NoError(json.Unmarshal(rw.Body.Bytes(), &out))
	require.Equal("99", out["id"])
	require.Equal("search", out["q"])
	require.Equal("hi", out["msg"])

	// Test BindJSON error
	reqBad := httptest.NewRequest("POST", "/v1/echo/99", strings.NewReader(`{bad`))
	rwBad := httptest.NewRecorder()
	router.ServeHTTP(rwBad, reqBad)
	require.Equal(http.StatusBadRequest, rwBad.Code)

	// Test []byte, string, nil, and 500 error in MakeHTTPHandlerFunc
	for _, tc := range []struct {
		in       string
		wantCode int
		wantBody string
	}{
		{in: "bytes", wantCode: http.StatusOK, wantBody: "bytes"},
		{in: "string", wantCode: http.StatusOK, wantBody: "str-resp"},
		{in: "nil", wantCode: http.StatusOK, wantBody: ""},
		{in: "err", wantCode: http.StatusInternalServerError, wantBody: "internalboom"},
	} {
		r := httptest.NewRequest("POST", "/v1/raw", bytes.NewBufferString(tc.in))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		require.Equal(tc.wantCode, w.Code)
		if tc.wantBody != "" {
			require.Contains(w.Body.String(), tc.wantBody)
		}
	}

	// Test MakeHTTPHandlerFuncV2 success and wrapped *Error
	rV2 := httptest.NewRequest("GET", "/v2/item", nil)
	wV2 := httptest.NewRecorder()
	router.ServeHTTP(wV2, rV2)
	require.Equal(http.StatusOK, wV2.Code)
	var v2Resp V2Response
	require.NoError(json.Unmarshal(wV2.Body.Bytes(), &v2Resp))
	require.Equal(http.StatusOK, v2Resp.Code)
	require.Equal("success", v2Resp.Msg)

	rV2Fail := httptest.NewRequest("GET", "/v2/item?fail=1", nil)
	wV2Fail := httptest.NewRecorder()
	router.ServeHTTP(wV2Fail, rV2Fail)
	require.Equal(http.StatusUnprocessableEntity, wV2Fail.Code)

	// 3. Server with PprofEnable and RouteRegister
	srv, err := NewServer(v1.WebServerConfig{
		Addr:        "127.0.0.1",
		Port:        0,
		User:        "admin",
		Password:    "pass",
		PprofEnable: true,
	})
	require.NoError(err)
	defer srv.Close()
	require.NotEmpty(srv.Address())

	srv.RouteRegister(func(helper *RouterRegisterHelper) {
		helper.Router.HandleFunc("/ping", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "pong")
		})
	})

	reqPprof := httptest.NewRequest("GET", "/debug/pprof/cmdline", nil)
	reqPprof.SetBasicAuth("admin", "pass")
	wPprof := httptest.NewRecorder()
	srv.router.ServeHTTP(wPprof, reqPprof)
	require.Equal(http.StatusOK, wPprof.Code)
}
