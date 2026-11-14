package framework

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEventuallySuccess(t *testing.T) {
	var counter atomic.Int32
	go func() {
		time.Sleep(50 * time.Millisecond)
		counter.Store(1)
	}()

	start := time.Now()
	Eventually(func() bool {
		return counter.Load() == 1
	}, 1*time.Second, 10*time.Millisecond)

	elapsed := time.Since(start)
	require.Less(t, elapsed, 500*time.Millisecond, "Eventually should return as soon as condition is met")
}
