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

package xlog

import (
	"bytes"
	"context"
	"testing"

	goliblog "github.com/fatedier/golib/log"
	"github.com/stretchr/testify/require"

	frplog "github.com/fatedier/frp/pkg/util/log"
)

func TestPrefixIsNotPartOfFormatString(t *testing.T) {
	tests := []struct {
		name string
		log  func(*Logger)
	}{
		{name: "error", log: func(xl *Logger) { xl.Errorf("value [%s]", "ok") }},
		{name: "warn", log: func(xl *Logger) { xl.Warnf("value [%s]", "ok") }},
		{name: "info", log: func(xl *Logger) { xl.Infof("value [%s]", "ok") }},
		{name: "debug", log: func(xl *Logger) { xl.Debugf("value [%s]", "ok") }},
		{name: "trace", log: func(xl *Logger) { xl.Tracef("value [%s]", "ok") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureLogs(t)

			tt.log(New().AppendPrefix("%1000000s"))

			require.Contains(t, output.String(), "[%1000000s] value [ok]")
			require.Less(t, output.Len(), 1024)
		})
	}
}

func TestFormattingSemanticsArePreserved(t *testing.T) {
	output := captureLogs(t)
	xl := New().AppendPrefix("run")

	xl.Infof("%[2]s %[1]s", "first", "second")
	xl.Infof("100% complete")

	require.Contains(t, output.String(), "[run] second first")
	require.Contains(t, output.String(), "[run] 100% complete")
}

func TestLoggerPrefixesSpawnAndReset(t *testing.T) {
	output := captureLogs(t)
	xl := New()
	// Logging without prefixes works cleanly
	xl.Infof("no-prefix")
	require.Contains(t, output.String(), "no-prefix")

	// Add prefixes with different priorities and update existing by Name
	xl.AddPrefix(LogPrefix{Name: "high", Value: "high-val", Priority: 100})
	xl.AddPrefix(LogPrefix{Name: "default", Value: "def-v1", Priority: 0})
	xl.AddPrefix(LogPrefix{Name: "low", Value: "low-val", Priority: 1})
	xl.AddPrefix(LogPrefix{Name: "default", Value: "def-v2", Priority: 10})

	output.Reset()
	xl.Infof("ordered")
	require.Contains(t, output.String(), "[high-val] [def-v2] [low-val] ordered")

	// Spawn creates an independent logger with copied prefixes
	child := xl.Spawn()
	child.AppendPrefix("child-only")
	old := xl.ResetPrefixes()
	require.Len(t, old, 3)

	output.Reset()
	xl.Infof("parent-after-reset")
	require.NotContains(t, output.String(), "[high-val]")
	require.Contains(t, output.String(), "parent-after-reset")

	output.Reset()
	child.Infof("child-msg")
	require.Contains(t, output.String(), "[high-val] [def-v2] [child-only] [low-val] child-msg")
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	got, ok := FromContext(ctx)
	require.False(t, ok)
	require.Nil(t, got)

	safe := FromContextSafe(ctx)
	require.NotNil(t, safe)

	xl := New().AppendPrefix("ctx-logger")
	ctxWithLogger := NewContext(ctx, xl)
	got, ok = FromContext(ctxWithLogger)
	require.True(t, ok)
	require.Same(t, xl, got)
	require.Same(t, xl, FromContextSafe(ctxWithLogger))
}

func TestLogWriters(t *testing.T) {
	output := captureLogs(t)
	xl := New().AppendPrefix("writer")

	writers := []struct {
		name   string
		writer LogWriter
		msg    string
	}{
		{name: "trace", writer: NewTraceWriter(xl), msg: "  trace line \n"},
		{name: "debug", writer: NewDebugWriter(xl), msg: "  debug line \n"},
		{name: "info", writer: NewInfoWriter(xl), msg: "  info line \n"},
		{name: "warn", writer: NewWarnWriter(xl), msg: "  warn line \n"},
		{name: "error", writer: NewErrorWriter(xl), msg: "  error line \n"},
	}

	for _, tc := range writers {
		t.Run(tc.name, func(t *testing.T) {
			output.Reset()
			n, err := tc.writer.Write([]byte(tc.msg))
			require.NoError(t, err)
			require.Equal(t, len(tc.msg), n)
			require.Contains(t, output.String(), "[writer] "+tc.name+" line")
		})
	}
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	output := bytes.NewBuffer(nil)
	oldLogger := frplog.Logger
	frplog.Logger = goliblog.New(
		goliblog.WithOutput(output),
		goliblog.WithLevel(goliblog.TraceLevel),
		goliblog.WithCaller(false),
	)
	t.Cleanup(func() {
		frplog.Logger = oldLogger
	})
	return output
}
