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

package source

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/util/jsonx"
)

func TestStoreSource_AddProxyAndVisitor_DoesNotApplyRuntimeDefaults(t *testing.T) {
	require := require.New(t)

	path := filepath.Join(t.TempDir(), "store.json")
	storeSource, err := NewStoreSource(StoreSourceConfig{Path: path})
	require.NoError(err)

	proxyCfg := &v1.TCPProxyConfig{}
	proxyCfg.Name = "proxy1"
	proxyCfg.Type = "tcp"
	proxyCfg.LocalPort = 10080

	visitorCfg := &v1.XTCPVisitorConfig{}
	visitorCfg.Name = "visitor1"
	visitorCfg.Type = "xtcp"
	visitorCfg.ServerName = "server1"
	visitorCfg.SecretKey = "secret"
	visitorCfg.BindPort = 10081

	err = storeSource.AddProxy(proxyCfg)
	require.NoError(err)
	err = storeSource.AddVisitor(visitorCfg)
	require.NoError(err)

	gotProxy := storeSource.GetProxy("proxy1")
	require.NotNil(gotProxy)
	require.Empty(gotProxy.GetBaseConfig().LocalIP)

	gotVisitor := storeSource.GetVisitor("visitor1")
	require.NotNil(gotVisitor)
	require.Empty(gotVisitor.GetBaseConfig().BindAddr)
	require.Empty(gotVisitor.(*v1.XTCPVisitorConfig).Protocol)
}

func TestStoreSource_UpdateAndRemoveProxyAndVisitor(t *testing.T) {
	require := require.New(t)

	storeSource := newTestStoreSource(t)

	proxyCfg := mockProxy("proxy1")
	visitorCfg := mockVisitor("visitor1")

	require.NoError(storeSource.AddProxy(proxyCfg))
	require.NoError(storeSource.AddVisitor(visitorCfg))
	require.ErrorIs(storeSource.AddProxy(proxyCfg), ErrAlreadyExists)
	require.ErrorIs(storeSource.AddVisitor(visitorCfg), ErrAlreadyExists)
	require.ErrorContains(storeSource.RemoveProxy(""), "proxy name cannot be empty")
	require.ErrorContains(storeSource.RemoveVisitor(""), "visitor name cannot be empty")

	updatedProxy := mockProxy("proxy1").(*v1.TCPProxyConfig)
	updatedProxy.RemotePort = 19090
	require.NoError(storeSource.UpdateProxy(updatedProxy))
	require.Equal(19090, storeSource.GetProxy("proxy1").(*v1.TCPProxyConfig).RemotePort)

	updatedVisitor := mockVisitor("visitor1").(*v1.STCPVisitorConfig)
	updatedVisitor.ServerName = "updated-server"
	require.NoError(storeSource.UpdateVisitor(updatedVisitor))
	require.Equal("updated-server", storeSource.GetVisitor("visitor1").(*v1.STCPVisitorConfig).ServerName)

	require.NoError(storeSource.RemoveProxy("proxy1"))
	require.Nil(storeSource.GetProxy("proxy1"))
	require.ErrorIs(storeSource.RemoveProxy("proxy1"), ErrNotFound)

	require.NoError(storeSource.RemoveVisitor("visitor1"))
	require.Nil(storeSource.GetVisitor("visitor1"))
	require.ErrorIs(storeSource.RemoveVisitor("visitor1"), ErrNotFound)

	require.ErrorIs(storeSource.UpdateProxy(updatedProxy), ErrNotFound)
	require.ErrorIs(storeSource.UpdateVisitor(updatedVisitor), ErrNotFound)
}

func TestStoreSource_MutationRollsBackOnPersistFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod does not make directories unwritable on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("chmod does not block writes for uid 0")
	}

	require := require.New(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	storeSource, err := NewStoreSource(StoreSourceConfig{Path: path})
	require.NoError(err)

	proxyCfg := mockProxy("proxy1")
	visitorCfg := mockVisitor("visitor1")
	originalRemotePort := proxyCfg.(*v1.TCPProxyConfig).RemotePort
	originalServerName := visitorCfg.(*v1.STCPVisitorConfig).ServerName
	require.NoError(storeSource.AddProxy(proxyCfg))
	require.NoError(storeSource.AddVisitor(visitorCfg))

	require.NoError(os.Chmod(dir, 0o500))
	t.Cleanup(func() {
		_ = os.Chmod(dir, 0o700)
	})

	requirePersistError := func(err error) {
		t.Helper()
		require.Error(err)
		require.ErrorContains(err, "failed to persist")
		require.NotErrorIs(err, ErrAlreadyExists)
		require.NotErrorIs(err, ErrNotFound)
	}

	requirePersistError(storeSource.AddProxy(mockProxy("proxy2")))
	require.Nil(storeSource.GetProxy("proxy2"))

	updatedProxy := mockProxy("proxy1").(*v1.TCPProxyConfig)
	updatedProxy.RemotePort = 19090
	requirePersistError(storeSource.UpdateProxy(updatedProxy))
	require.Equal(originalRemotePort, storeSource.GetProxy("proxy1").(*v1.TCPProxyConfig).RemotePort)

	requirePersistError(storeSource.RemoveProxy("proxy1"))
	require.NotNil(storeSource.GetProxy("proxy1"))

	requirePersistError(storeSource.AddVisitor(mockVisitor("visitor2")))
	require.Nil(storeSource.GetVisitor("visitor2"))

	updatedVisitor := mockVisitor("visitor1").(*v1.STCPVisitorConfig)
	updatedVisitor.ServerName = "updated-server"
	requirePersistError(storeSource.UpdateVisitor(updatedVisitor))
	require.Equal(originalServerName, storeSource.GetVisitor("visitor1").(*v1.STCPVisitorConfig).ServerName)

	requirePersistError(storeSource.RemoveVisitor("visitor1"))
	require.NotNil(storeSource.GetVisitor("visitor1"))
}

func TestStoreSource_LoadFromFile_DoesNotApplyRuntimeDefaults(t *testing.T) {
	require := require.New(t)

	path := filepath.Join(t.TempDir(), "store.json")

	proxyCfg := &v1.TCPProxyConfig{}
	proxyCfg.Name = "proxy1"
	proxyCfg.Type = "tcp"
	proxyCfg.LocalPort = 10080

	visitorCfg := &v1.XTCPVisitorConfig{}
	visitorCfg.Name = "visitor1"
	visitorCfg.Type = "xtcp"
	visitorCfg.ServerName = "server1"
	visitorCfg.SecretKey = "secret"
	visitorCfg.BindPort = 10081

	stored := storeData{
		Proxies:  []v1.TypedProxyConfig{{ProxyConfigurer: proxyCfg}},
		Visitors: []v1.TypedVisitorConfig{{VisitorConfigurer: visitorCfg}},
	}
	data, err := jsonx.Marshal(stored)
	require.NoError(err)
	err = os.WriteFile(path, data, 0o600)
	require.NoError(err)

	storeSource, err := NewStoreSource(StoreSourceConfig{Path: path})
	require.NoError(err)

	gotProxy := storeSource.GetProxy("proxy1")
	require.NotNil(gotProxy)
	require.Empty(gotProxy.GetBaseConfig().LocalIP)

	gotVisitor := storeSource.GetVisitor("visitor1")
	require.NotNil(gotVisitor)
	require.Empty(gotVisitor.GetBaseConfig().BindAddr)
	require.Empty(gotVisitor.(*v1.XTCPVisitorConfig).Protocol)
}

func TestStoreSource_LoadFromFile_UnknownFieldsAreIgnored(t *testing.T) {
	require := require.New(t)

	path := filepath.Join(t.TempDir(), "store.json")
	raw := []byte(`{
		"proxies": [
			{"name":"proxy1","type":"tcp","localPort":10080,"unexpected":"value"}
		],
		"visitors": [
			{"name":"visitor1","type":"xtcp","serverName":"server1","secretKey":"secret","bindPort":10081,"unexpected":"value"}
		]
	}`)
	err := os.WriteFile(path, raw, 0o600)
	require.NoError(err)

	storeSource, err := NewStoreSource(StoreSourceConfig{Path: path})
	require.NoError(err)

	require.NotNil(storeSource.GetProxy("proxy1"))
	require.NotNil(storeSource.GetVisitor("visitor1"))
}

func TestStoreSource_DirectoryPermissions(t *testing.T) {
	require := require.New(t)

	dir := filepath.Join(t.TempDir(), "nested-store-dir")
	path := filepath.Join(dir, "store.json")

	storeSource, err := NewStoreSource(StoreSourceConfig{Path: path})
	require.NoError(err)

	err = storeSource.AddProxy(&v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name:         "p1",
			Type:         "tcp",
			ProxyBackend: v1.ProxyBackend{LocalPort: 8080},
		},
	})
	require.NoError(err)

	info, err := os.Stat(dir)
	require.NoError(err)
	require.Equal(os.FileMode(0o700), info.Mode().Perm())
}

func TestStoreSource_ReturnsDeepClones(t *testing.T) {
	require := require.New(t)

	storeSource := newTestStoreSource(t)
	proxyCfg := mockProxy("proxy-clone")
	visitorCfg := mockVisitor("visitor-clone")

	require.NoError(storeSource.AddProxy(proxyCfg))
	require.NoError(storeSource.AddVisitor(visitorCfg))

	// 1. Mutating GetProxy does not mutate stored proxy
	p1 := storeSource.GetProxy("proxy-clone")
	require.NotNil(p1)
	p1.GetBaseConfig().LocalIP = "mutated-ip"
	p2 := storeSource.GetProxy("proxy-clone")
	require.NotEqual("mutated-ip", p2.GetBaseConfig().LocalIP)

	// 2. Mutating GetAllProxies does not mutate stored proxy
	allP, err := storeSource.GetAllProxies()
	require.NoError(err)
	require.Len(allP, 1)
	allP[0].GetBaseConfig().LocalIP = "mutated-in-all"
	p3 := storeSource.GetProxy("proxy-clone")
	require.NotEqual("mutated-in-all", p3.GetBaseConfig().LocalIP)

	// 3. Mutating GetVisitor does not mutate stored visitor
	v1 := storeSource.GetVisitor("visitor-clone")
	require.NotNil(v1)
	v1.GetBaseConfig().BindAddr = "mutated-addr"
	v2 := storeSource.GetVisitor("visitor-clone")
	require.NotEqual("mutated-addr", v2.GetBaseConfig().BindAddr)

	// 4. Mutating GetAllVisitors does not mutate stored visitor
	allV, err := storeSource.GetAllVisitors()
	require.NoError(err)
	require.Len(allV, 1)
	allV[0].GetBaseConfig().BindAddr = "mutated-in-all"
	v3 := storeSource.GetVisitor("visitor-clone")
	require.NotEqual("mutated-in-all", v3.GetBaseConfig().BindAddr)
}
