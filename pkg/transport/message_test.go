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

package transport

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/msg"
)

type noopSender struct{}

func (noopSender) Send(msg.Message) error { return nil }

func TestMessageTransporterDispatchNonBlockingAndCancelRace(t *testing.T) {
	tr := NewMessageTransporter(noopSender{})

	// Concurrent Do cancellations and Dispatch calls must not panic or race.
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
			defer cancel()
			lane := "lane"
			if i%2 == 0 {
				lane = "lane-even"
			}
			_, _ = tr.Do(ctx, &msg.Ping{}, lane, "Pong")
		})
		wg.Go(func() {
			tr.Dispatch(&msg.Pong{}, "lane")
			tr.Dispatch(&msg.Pong{}, "lane-even")
		})
	}
	wg.Wait()

	// Duplicate Dispatch to an unread lane must not block and must return false.
	ctx := t.Context()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = tr.Do(ctx, &msg.Ping{}, "dup-lane", "Pong")
	}()

	require.Eventually(t, func() bool {
		return tr.Dispatch(&msg.Pong{}, "dup-lane")
	}, time.Second, time.Millisecond)
	// Second dispatch before Do drains (or after Do exits) must not block.
	_ = tr.Dispatch(&msg.Pong{}, "dup-lane")
	<-done
}
