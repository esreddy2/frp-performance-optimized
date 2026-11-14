package wait

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestFastBackoffManagerUsesClock(t *testing.T) {
	require := require.New(t)

	start := time.Date(2026, time.May, 8, 12, 30, 0, 0, time.UTC)
	clk := clocktesting.NewFakeClock(start)
	backoff := newFastBackoffManagerWithClock(FastBackoffOptions{
		Duration: time.Second,
	}, clk).(*fastBackoffImpl)

	require.Equal(time.Second, backoff.Backoff(0, false))
	require.Equal(start, backoff.lastCalledTime)

	next := start.Add(time.Minute)
	clk.SetTime(next)
	require.Equal(time.Second, backoff.Backoff(time.Second, false))
	require.Equal(next, backoff.lastCalledTime)
}

func TestFastBackoffExponentialFastRetryAndCap(t *testing.T) {
	require := require.New(t)

	start := time.Date(2026, time.May, 8, 12, 30, 0, 0, time.UTC)
	clk := clocktesting.NewFakeClock(start)
	bm := newFastBackoffManagerWithClock(FastBackoffOptions{
		Duration:           100 * time.Millisecond,
		InitDurationIfFail: 200 * time.Millisecond,
		Factor:             2.0,
		Jitter:             0.05,
		MaxDuration:        1 * time.Second,
	}, clk)

	// Initial call returns base Duration
	d := bm.Backoff(0, false)
	require.Equal(100*time.Millisecond, d)

	// First error uses InitDurationIfFail * Factor (200ms * 2 = 400ms + jitter)
	clk.Step(10 * time.Millisecond)
	d = bm.Backoff(d, true)
	require.GreaterOrEqual(d, 400*time.Millisecond)
	require.LessOrEqual(d, 420*time.Millisecond)

	// Second error doubles previousDuration (~800ms + jitter)
	clk.Step(10 * time.Millisecond)
	d = bm.Backoff(d, true)
	require.GreaterOrEqual(d, 800*time.Millisecond)
	require.LessOrEqual(d, 882*time.Millisecond)

	// Subsequent errors cap at MaxDuration (1s)
	clk.Step(10 * time.Millisecond)
	d = bm.Backoff(d, true)
	require.Equal(1*time.Second, d)

	// Recovery resets consecutiveErrCount and returns base Duration
	clk.Step(100 * time.Millisecond)
	d = bm.Backoff(d, false)
	require.Equal(100*time.Millisecond, d)

	// FastRetryCount returns FastRetryDelay for the first FastRetryCount (2) calls within FastRetryWindow
	fastBM := newFastBackoffManagerWithClock(FastBackoffOptions{
		Duration:        100 * time.Millisecond,
		Factor:          2.0,
		FastRetryCount:  2,
		FastRetryDelay:  10 * time.Millisecond,
		FastRetryJitter: 0.1,
		FastRetryWindow: 5 * time.Second,
	}, clk)
	_ = fastBM.Backoff(0, false)

	// 1st error in window -> fast retry
	clk.Step(100 * time.Millisecond)
	fastDelay1 := fastBM.Backoff(100*time.Millisecond, true)
	require.GreaterOrEqual(fastDelay1, 10*time.Millisecond)
	require.LessOrEqual(fastDelay1, 11*time.Millisecond)

	// 2nd error in window -> fast retry
	clk.Step(100 * time.Millisecond)
	fastDelay2 := fastBM.Backoff(100*time.Millisecond, true)
	require.GreaterOrEqual(fastDelay2, 10*time.Millisecond)
	require.LessOrEqual(fastDelay2, 11*time.Millisecond)

	// 3rd error in same window exceeds FastRetryCount -> falls back to exponential backoff (100ms * 2 = 200ms)
	clk.Step(100 * time.Millisecond)
	slowDelay := fastBM.Backoff(100*time.Millisecond, true)
	require.Equal(200*time.Millisecond, slowDelay)

	// Advance past FastRetryWindow (5s) -> window resets and next error gets FastRetryDelay again
	clk.Step(6 * time.Second)
	resetFastDelay := fastBM.Backoff(200*time.Millisecond, true)
	require.GreaterOrEqual(resetFastDelay, 10*time.Millisecond)
	require.LessOrEqual(resetFastDelay, 11*time.Millisecond)

	// Also verify NewFastBackoffManager and nil-clock fallback
	realBM := NewFastBackoffManager(FastBackoffOptions{Duration: 5 * time.Millisecond})
	require.Equal(5*time.Millisecond, realBM.Backoff(0, false))
	nilClockBM := newFastBackoffManagerWithClock(FastBackoffOptions{Duration: 5 * time.Millisecond}, nil)
	require.Equal(5*time.Millisecond, nilClockBM.Backoff(0, false))
}

func TestBackoffUntilUntilAndJitter(t *testing.T) {
	require := require.New(t)

	// Jitter with <= 0 factor defaults to 1.0
	for range 20 {
		j := Jitter(100*time.Millisecond, 0)
		require.GreaterOrEqual(j, 100*time.Millisecond)
		require.LessOrEqual(j, 200*time.Millisecond)
	}

	// BackoffUntil (non-sliding) stops when f returns done=true after transient error
	attempts := 0
	stopCh := make(chan struct{})
	BackoffUntil(func() (bool, error) {
		attempts++
		if attempts == 1 {
			return false, errors.New("transient error")
		}
		if attempts == 2 {
			return false, nil
		}
		return true, nil
	}, BackoffFunc(func(prev time.Duration, prevErr bool) time.Duration {
		return time.Millisecond
	}), false, stopCh)
	require.Equal(3, attempts)

	// Until runs periodically until stopCh is closed
	var count atomic.Int32
	untilStop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		Until(func() {
			if count.Add(1) >= 3 {
				select {
				case <-untilStop:
				default:
					close(untilStop)
				}
			}
		}, time.Millisecond, untilStop)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Until did not stop after stopCh was closed")
	}
	require.GreaterOrEqual(count.Load(), int32(3))
}

type zeroBackoffManager struct{}

func (z *zeroBackoffManager) Backoff(_ time.Duration, _ bool) time.Duration {
	return 0
}

func TestBackoffUntilZeroOrNegativeDurationNoPanic(t *testing.T) {
	require := require.New(t)

	stopCh := make(chan struct{})
	var calls atomic.Int32

	require.NotPanics(func() {
		BackoffUntil(func() (bool, error) {
			if calls.Add(1) >= 2 {
				close(stopCh)
				return true, nil
			}
			return false, nil
		}, &zeroBackoffManager{}, true, stopCh)
	})
	require.GreaterOrEqual(calls.Load(), int32(2))
}
