package http

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type limitedZeroReader struct {
	remaining int64
}

func (r *limitedZeroReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	for i := 0; i < n; i++ {
		p[i] = ' '
	}
	r.remaining -= int64(n)
	return n, nil
}

func (r *limitedZeroReader) Close() error {
	return nil
}

func TestContextBindJSONAndBodyLimits(t *testing.T) {
	// 1. Normal JSON binding
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"key":"value"}`))
	ctx := NewContext(rec, req)
	var data map[string]string
	err := ctx.BindJSON(&data)
	require.NoError(t, err)
	require.Equal(t, "value", data["key"])

	// 2. Normal Body read
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("hello world"))
	ctx = NewContext(rec, req)
	body, err := ctx.Body()
	require.NoError(t, err)
	require.Equal(t, "hello world", string(body))

	// 3. Oversized JSON binding (> 10MB)
	rec = httptest.NewRecorder()
	// Create a reader exceeding 10MB
	oversized := io.MultiReader(
		strings.NewReader(`{"key":"`),
		&limitedZeroReader{remaining: 11 << 20},
		strings.NewReader(`"}`),
	)
	req = httptest.NewRequest(http.MethodPost, "/", io.NopCloser(oversized))
	ctx = NewContext(rec, req)
	var largeData map[string]string
	err = ctx.BindJSON(&largeData)
	require.Error(t, err)
	require.Contains(t, err.Error(), "request body too large")

	// 4. Oversized Body read (> 10MB)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/", io.NopCloser(&limitedZeroReader{remaining: 11 << 20}))
	ctx = NewContext(rec, req)
	_, err = ctx.Body()
	require.Error(t, err)
	require.Contains(t, err.Error(), "request body too large")

	// 5. Query and Param
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/?name=alice", nil)
	ctx = NewContext(rec, req)
	require.Equal(t, "alice", ctx.Query("name"))
	require.Empty(t, ctx.Param("id"))
}

func TestContextBindJSONWithInvalidJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{not-json}`))
	ctx := NewContext(rec, req)
	var data map[string]string
	err := ctx.BindJSON(&data)
	require.Error(t, err)
}
