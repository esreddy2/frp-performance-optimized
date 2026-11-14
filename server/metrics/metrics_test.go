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

package metrics

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type recordingServerMetrics struct {
	mu          sync.Mutex
	newClients  atomic.Int32
	closedConns atomic.Int32
	openConns   atomic.Int32
	closedClis  atomic.Int32
	proxies     []string
	closedPxys  []string
	trafficIn   int64
	trafficOut  int64
}

func (r *recordingServerMetrics) NewClient() {
	r.newClients.Add(1)
}

func (r *recordingServerMetrics) CloseClient() {
	r.closedClis.Add(1)
}

func (r *recordingServerMetrics) NewProxy(name, proxyType, user, clientID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.proxies = append(r.proxies, name+":"+proxyType+":"+user+":"+clientID)
}

func (r *recordingServerMetrics) CloseProxy(name, proxyType string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closedPxys = append(r.closedPxys, name+":"+proxyType)
}

func (r *recordingServerMetrics) OpenConnection(name, proxyType string) {
	r.openConns.Add(1)
}

func (r *recordingServerMetrics) CloseConnection(name, proxyType string) {
	r.closedConns.Add(1)
}

func (r *recordingServerMetrics) AddTrafficIn(_ string, _ string, trafficBytes int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.trafficIn += trafficBytes
}

func (r *recordingServerMetrics) AddTrafficOut(_ string, _ string, trafficBytes int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.trafficOut += trafficBytes
}

func TestNoopServerMetricsSafeByDefault(t *testing.T) {
	var noop ServerMetrics = noopServerMetrics{}
	require.NotPanics(t, func() {
		noop.NewClient()
		noop.CloseClient()
		noop.NewProxy("ssh", "tcp", "alice", "cid-1")
		noop.CloseProxy("ssh", "tcp")
		noop.OpenConnection("ssh", "tcp")
		noop.CloseConnection("ssh", "tcp")
		noop.AddTrafficIn("ssh", "tcp", 1024)
		noop.AddTrafficOut("ssh", "tcp", 2048)
		noop.AddTrafficIn("", "", 0)
		noop.AddTrafficOut("", "", -1)
	})
}

func TestRegisterOnceAndDelegateAllOperations(t *testing.T) {
	origServer := Server
	t.Cleanup(func() {
		Server = origServer
		registerMetrics = sync.Once{}
	})
	registerMetrics = sync.Once{}

	primary := &recordingServerMetrics{}
	secondary := &recordingServerMetrics{}

	Register(primary)
	Register(secondary)

	require.Same(t, primary, Server)

	Server.NewClient()
	Server.CloseClient()
	Server.NewProxy("web", "http", "bob", "client-1")
	Server.CloseProxy("web", "http")
	Server.OpenConnection("web", "http")
	Server.CloseConnection("web", "http")
	Server.AddTrafficIn("web", "http", 512)
	Server.AddTrafficOut("web", "http", 1024)

	require.Equal(t, int32(1), primary.newClients.Load())
	require.Equal(t, int32(1), primary.closedClis.Load())
	require.Equal(t, int32(1), primary.openConns.Load())
	require.Equal(t, int32(1), primary.closedConns.Load())
	require.Equal(t, []string{"web:http:bob:client-1"}, primary.proxies)
	require.Equal(t, []string{"web:http"}, primary.closedPxys)
	require.Equal(t, int64(512), primary.trafficIn)
	require.Equal(t, int64(1024), primary.trafficOut)

	require.Equal(t, int32(0), secondary.newClients.Load())
}
