package log

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitLoggerAndLogFunctions(t *testing.T) {
	require := require.New(t)

	// 1. InitLogger to file with valid and invalid level strings
	logFile := filepath.Join(t.TempDir(), "frp.log")
	InitLogger(logFile, "trace", 3, true)

	Errorf("error message %d", 1)
	Warnf("warn message %d", 2)
	Infof("info message %d", 3)
	Debugf("debug message %d", 4)
	Tracef("trace message %d", 5)
	Logf(InfoLevel, 1, "logf message %s", "ok")

	wl := NewWriteLogger(WarnLevel, 1)
	n, err := wl.Write([]byte("write logger line\n"))
	require.NoError(err)
	require.Equal(len("write logger line\n"), n)

	content, err := os.ReadFile(logFile)
	require.NoError(err)
	text := string(content)
	require.Contains(text, "error message 1")
	require.Contains(text, "warn message 2")
	require.Contains(text, "info message 3")
	require.Contains(text, "debug message 4")
	require.Contains(text, "trace message 5")
	require.Contains(text, "logf message ok")
	require.Contains(text, "write logger line")

	// 2. InitLogger with invalid level defaults to InfoLevel and console mode
	InitLogger("console", "invalid-level", 1, false)
	InitLogger("console", "info", 1, true)

	// 3. Concurrent InitLogger and logging calls should be race-free
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			InitLogger("console", "info", 1, true)
			Infof("concurrent info %d", idx)
			Warnf("concurrent warn %d", idx)
			Errorf("concurrent err %d", idx)
			Debugf("concurrent debug %d", idx)
			Tracef("concurrent trace %d", idx)
			_, _ = wl.Write([]byte("concurrent write\n"))
		}(i)
	}
	wg.Wait()
}
