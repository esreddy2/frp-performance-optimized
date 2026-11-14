package process

import (
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProcessGroupTermination(t *testing.T) {
	// Launch a shell process that spawns background child sleep processes
	p := NewWithEnvs("sh", []string{"-c", "sleep 60 & sleep 60 & wait"}, nil)
	err := p.Start()
	require.NoError(t, err)

	pid := p.cmd.Process.Pid
	require.Greater(t, pid, 0)

	// Verify that the process group was created and equals pid
	pgid, err := syscall.Getpgid(pid)
	require.NoError(t, err)
	require.Equal(t, pid, pgid, "Process must be group leader")

	// Stop the process
	time.Sleep(50 * time.Millisecond)
	_ = p.Stop()

	// Verify the root process has exited
	select {
	case <-p.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("process did not exit in time")
	}

	// Verify the process group is terminated
	time.Sleep(100 * time.Millisecond)
	err = syscall.Kill(-pgid, 0)
	require.Error(t, err, "Process group should no longer exist after Stop")
}

func TestProcessWaitForOutput(t *testing.T) {
	p := NewWithEnvs("sh", []string{"-c", "echo hello; sleep 0.1; echo world"}, nil)
	require.NoError(t, p.Start())
	defer func() { _ = p.Stop() }()

	err := p.WaitForOutput("world", 1, 2*time.Second)
	require.NoError(t, err)
	require.True(t, strings.Contains(p.Output(), "hello"))
	require.True(t, strings.Contains(p.Output(), "world"))
}
