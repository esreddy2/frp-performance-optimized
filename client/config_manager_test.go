package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"github.com/fatedier/frp/client/configmgmt"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/policy/security"
	httppkg "github.com/fatedier/frp/pkg/util/http"
	"github.com/fatedier/frp/pkg/vnet"
)

func newTestRawTCPProxyConfig(name string) *v1.TCPProxyConfig {
	return &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: name,
			Type: "tcp",
			ProxyBackend: v1.ProxyBackend{
				LocalPort: 10080,
			},
		},
	}
}

func newTestVirtualNetProxyConfig(name string) *v1.STCPProxyConfig {
	return &v1.STCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: name,
			Type: "stcp",
			ProxyBackend: v1.ProxyBackend{
				Plugin: v1.TypedClientPluginOptions{
					Type:                v1.PluginVirtualNet,
					ClientPluginOptions: &v1.VirtualNetPluginOptions{Type: v1.PluginVirtualNet},
				},
			},
		},
	}
}

func newTestVirtualNetVisitorConfig(name string) *v1.STCPVisitorConfig {
	return &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name:       name,
			Type:       "stcp",
			ServerName: "vnet-server",
			SecretKey:  "secret",
			BindPort:   -1,
			Plugin: v1.TypedVisitorPluginOptions{
				Type: v1.VisitorPluginVirtualNet,
				VisitorPluginOptions: &v1.VirtualNetVisitorPluginOptions{
					Type:          v1.VisitorPluginVirtualNet,
					DestinationIP: "100.86.0.1",
				},
			},
		},
	}
}

func TestServiceConfigManagerReloadVirtualNetRuntimeDependency(t *testing.T) {
	const runtimeErr = "VirtualNet-dependent configuration requires a VirtualNet runtime enabled at startup"

	tests := []struct {
		name                  string
		startupVirtualNetAddr string
		nextConfig            string
		wantRuntimeDependency bool
	}{
		{
			name:       "unrelated common config",
			nextConfig: `serverAddr = "0.0.0.0"`,
		},
		{
			name: "VirtualNet address without startup runtime",
			nextConfig: `featureGates = { VirtualNet = true }
virtualNet.address = "100.86.0.4/24"
`,
			wantRuntimeDependency: true,
		},
		{
			name: "VirtualNet proxy without startup runtime",
			nextConfig: `[[proxies]]
name = "vnet-proxy"
type = "stcp"
secretKey = "secret"
[proxies.plugin]
type = "virtual_net"
`,
			wantRuntimeDependency: true,
		},
		{
			name: "VirtualNet visitor without startup runtime",
			nextConfig: `[[visitors]]
name = "vnet-visitor"
type = "stcp"
serverName = "vnet-server"
secretKey = "secret"
bindPort = -1
[visitors.plugin]
type = "virtual_net"
destinationIP = "100.86.0.1"
`,
			wantRuntimeDependency: true,
		},
		{
			name:                  "existing VirtualNet startup runtime",
			startupVirtualNetAddr: "100.86.0.4/24",
			nextConfig: `featureGates = { VirtualNet = true }
virtualNet.address = "100.86.0.5/24"
`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			current := &v1.ClientCommonConfig{}
			if tc.startupVirtualNetAddr != "" {
				current.FeatureGates = map[string]bool{"VirtualNet": true}
				current.VirtualNet.Address = tc.startupVirtualNetAddr
			}
			if err := current.Complete(); err != nil {
				t.Fatalf("complete current config: %v", err)
			}

			configFile := filepath.Join(t.TempDir(), "frpc.toml")
			if err := os.WriteFile(configFile, []byte(tc.nextConfig), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			configSource := source.NewConfigSource()
			aggregator := source.NewAggregator(configSource)
			svr := &Service{
				common:         current,
				reloadCommon:   current,
				configFilePath: configFile,
				unsafeFeatures: security.NewUnsafeFeatures(nil),
				aggregator:     aggregator,
				configSource:   configSource,
			}
			if tc.startupVirtualNetAddr != "" {
				svr.vnetController = vnet.NewController(current.VirtualNet)
			}

			err := (&serviceConfigManager{svr: svr}).ReloadFromFile(true)
			if tc.wantRuntimeDependency {
				if !errors.Is(err, configmgmt.ErrApplyConfig) || !strings.Contains(err.Error(), runtimeErr) {
					t.Fatalf("expected VirtualNet runtime dependency error, got: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("reload config: %v", err)
			}
			if svr.common != current {
				t.Fatal("reload should not replace startup common config")
			}
			if tc.startupVirtualNetAddr == "" && svr.vnetController != nil {
				t.Fatal("reload should not enable startup-only VirtualNet runtime state")
			}
		})
	}
}

func TestServiceConfigManagerReloadVirtualNetRuntimeDependencyUsesMergedSources(t *testing.T) {
	const runtimeErr = "VirtualNet-dependent configuration requires a VirtualNet runtime enabled at startup"

	tests := []struct {
		name                  string
		nextConfig            string
		storeProxy            v1.ProxyConfigurer
		storeVisitor          v1.VisitorConfigurer
		wantRuntimeDependency bool
		wantProxyPlugin       string
	}{
		{
			name:                  "Store VirtualNet proxy is rejected",
			nextConfig:            `serverAddr = "0.0.0.0"`,
			storeProxy:            newTestVirtualNetProxyConfig("store-vnet"),
			wantRuntimeDependency: true,
		},
		{
			name:                  "Store VirtualNet visitor is rejected",
			nextConfig:            `serverAddr = "0.0.0.0"`,
			storeVisitor:          newTestVirtualNetVisitorConfig("store-vnet"),
			wantRuntimeDependency: true,
		},
		{
			name: "Store VirtualNet proxy overrides file proxy",
			nextConfig: `[[proxies]]
name = "shared"
type = "tcp"
localPort = 10080
remotePort = 10081
`,
			storeProxy:            newTestVirtualNetProxyConfig("shared"),
			wantRuntimeDependency: true,
		},
		{
			name: "Store non-VirtualNet proxy overrides file VirtualNet proxy",
			nextConfig: `[[proxies]]
name = "shared"
type = "stcp"
secretKey = "secret"
[proxies.plugin]
type = "virtual_net"
`,
			storeProxy:      newTestRawTCPProxyConfig("shared"),
			wantProxyPlugin: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			current := &v1.ClientCommonConfig{}
			if err := current.Complete(); err != nil {
				t.Fatalf("complete current config: %v", err)
			}

			configFile := filepath.Join(t.TempDir(), "frpc.toml")
			if err := os.WriteFile(configFile, []byte(tc.nextConfig), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			storeSource, err := source.NewStoreSource(source.StoreSourceConfig{
				Path: filepath.Join(t.TempDir(), "store.json"),
			})
			if err != nil {
				t.Fatalf("new store source: %v", err)
			}
			if tc.storeProxy != nil {
				if err := storeSource.AddProxy(tc.storeProxy); err != nil {
					t.Fatalf("add store proxy: %v", err)
				}
			}
			if tc.storeVisitor != nil {
				if err := storeSource.AddVisitor(tc.storeVisitor); err != nil {
					t.Fatalf("add store visitor: %v", err)
				}
			}

			configSource := source.NewConfigSource()
			aggregator := source.NewAggregator(configSource)
			aggregator.SetStoreSource(storeSource)
			svr := &Service{
				common:         current,
				reloadCommon:   current,
				configFilePath: configFile,
				unsafeFeatures: security.NewUnsafeFeatures(nil),
				aggregator:     aggregator,
				configSource:   configSource,
				storeSource:    storeSource,
			}

			err = (&serviceConfigManager{svr: svr}).ReloadFromFile(true)
			if tc.wantRuntimeDependency {
				if !errors.Is(err, configmgmt.ErrApplyConfig) || !strings.Contains(err.Error(), runtimeErr) {
					t.Fatalf("expected VirtualNet runtime dependency error, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("reload config: %v", err)
			}

			if len(svr.proxyCfgs) != 1 {
				t.Fatalf("expected one applied proxy, got %d", len(svr.proxyCfgs))
			}
			if got := svr.proxyCfgs[0].GetBaseConfig().Plugin.Type; got != tc.wantProxyPlugin {
				t.Fatalf("unexpected applied proxy plugin: %q", got)
			}
		})
	}
}

func TestServiceConfigManagerCreateStoreProxyConflict(t *testing.T) {
	storeSource, err := source.NewStoreSource(source.StoreSourceConfig{
		Path: filepath.Join(t.TempDir(), "store.json"),
	})
	if err != nil {
		t.Fatalf("new store source: %v", err)
	}
	if err := storeSource.AddProxy(newTestRawTCPProxyConfig("p1")); err != nil {
		t.Fatalf("seed proxy: %v", err)
	}

	agg := source.NewAggregator(source.NewConfigSource())
	agg.SetStoreSource(storeSource)

	mgr := &serviceConfigManager{
		svr: &Service{
			aggregator:   agg,
			configSource: agg.ConfigSource(),
			storeSource:  storeSource,
			common:       &v1.ClientCommonConfig{},
			reloadCommon: &v1.ClientCommonConfig{},
		},
	}

	_, err = mgr.CreateStoreProxy(newTestRawTCPProxyConfig("p1"))
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if !errors.Is(err, configmgmt.ErrConflict) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServiceConfigManagerCreateStoreProxyKeepsStoreOnReloadFailure(t *testing.T) {
	storeSource, err := source.NewStoreSource(source.StoreSourceConfig{
		Path: filepath.Join(t.TempDir(), "store.json"),
	})
	if err != nil {
		t.Fatalf("new store source: %v", err)
	}

	mgr := &serviceConfigManager{
		svr: &Service{
			storeSource:  storeSource,
			common:       &v1.ClientCommonConfig{},
			reloadCommon: &v1.ClientCommonConfig{},
		},
	}

	_, err = mgr.CreateStoreProxy(newTestRawTCPProxyConfig("p1"))
	if err == nil {
		t.Fatal("expected apply config error")
	}
	if !errors.Is(err, configmgmt.ErrApplyConfig) {
		t.Fatalf("unexpected error: %v", err)
	}
	if storeSource.GetProxy("p1") == nil {
		t.Fatal("proxy should remain in store after reload failure")
	}
}

func TestServiceConfigManagerCreateStoreProxyStoreDisabled(t *testing.T) {
	mgr := &serviceConfigManager{
		svr: &Service{
			common:       &v1.ClientCommonConfig{},
			reloadCommon: &v1.ClientCommonConfig{},
		},
	}

	_, err := mgr.CreateStoreProxy(newTestRawTCPProxyConfig("p1"))
	if err == nil {
		t.Fatal("expected store disabled error")
	}
	if !errors.Is(err, configmgmt.ErrStoreDisabled) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServiceConfigManagerCreateStoreProxyDoesNotPersistRuntimeDefaults(t *testing.T) {
	storeSource, err := source.NewStoreSource(source.StoreSourceConfig{
		Path: filepath.Join(t.TempDir(), "store.json"),
	})
	if err != nil {
		t.Fatalf("new store source: %v", err)
	}
	agg := source.NewAggregator(source.NewConfigSource())
	agg.SetStoreSource(storeSource)

	mgr := &serviceConfigManager{
		svr: &Service{
			aggregator:   agg,
			configSource: agg.ConfigSource(),
			storeSource:  storeSource,
			common:       &v1.ClientCommonConfig{},
			reloadCommon: &v1.ClientCommonConfig{},
		},
	}

	persisted, err := mgr.CreateStoreProxy(newTestRawTCPProxyConfig("raw-proxy"))
	if err != nil {
		t.Fatalf("create store proxy: %v", err)
	}
	if persisted == nil {
		t.Fatal("expected persisted proxy to be returned")
	}

	got := storeSource.GetProxy("raw-proxy")
	if got == nil {
		t.Fatal("proxy not found in store")
	}
	if got.GetBaseConfig().LocalIP != "" {
		t.Fatalf("localIP was persisted with runtime default: %q", got.GetBaseConfig().LocalIP)
	}
	if got.GetBaseConfig().Transport.BandwidthLimitMode != "" {
		t.Fatalf("bandwidthLimitMode was persisted with runtime default: %q", got.GetBaseConfig().Transport.BandwidthLimitMode)
	}
}

func TestServiceConfigManagerCRUDAndFileOps(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "frpc.toml")

	storeSource, err := source.NewStoreSource(source.StoreSourceConfig{
		Path: filepath.Join(tmpDir, "store.json"),
	})
	if err != nil {
		t.Fatalf("new store source: %v", err)
	}
	agg := source.NewAggregator(source.NewConfigSource())
	agg.SetStoreSource(storeSource)

	common := &v1.ClientCommonConfig{User: "alice"}
	_ = common.Complete()

	svr := &Service{
		aggregator:   agg,
		configSource: agg.ConfigSource(),
		storeSource:  storeSource,
		common:       common,
		reloadCommon: common,
	}
	mgr := newServiceConfigManager(svr)

	// 1. ReadConfigFile / WriteConfigFile / ReloadFromFile without configFilePath
	if _, err := mgr.ReadConfigFile(); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument when configFilePath is empty, got %v", err)
	}
	if err := mgr.ReloadFromFile(true); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on ReloadFromFile without path, got %v", err)
	}
	if err := mgr.WriteConfigFile(nil); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on empty WriteConfigFile, got %v", err)
	}

	svr.configFilePath = cfgPath
	if _, err := mgr.ReadConfigFile(); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on missing config file, got %v", err)
	}
	if err := mgr.WriteConfigFile([]byte("serverAddr = \"127.0.0.1\"\n")); err != nil {
		t.Fatalf("WriteConfigFile: %v", err)
	}
	gotContent, err := mgr.ReadConfigFile()
	if err != nil || gotContent != "serverAddr = \"127.0.0.1\"\n" {
		t.Fatalf("unexpected ReadConfigFile result: %q, err=%v", gotContent, err)
	}

	// 2. StoreEnabled and Proxy CRUD
	if !mgr.StoreEnabled() {
		t.Fatal("expected StoreEnabled to be true")
	}
	if mgr.IsStoreProxyEnabled("") || mgr.IsStoreProxyEnabled("nonexistent") {
		t.Fatal("expected IsStoreProxyEnabled to be false for empty or nonexistent proxy")
	}

	if _, err := mgr.CreateStoreProxy(nil); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for nil proxy, got %v", err)
	}

	p1 := newTestRawTCPProxyConfig("p1")
	if _, err := mgr.CreateStoreProxy(p1); err != nil {
		t.Fatalf("CreateStoreProxy: %v", err)
	}
	if !mgr.IsStoreProxyEnabled("p1") {
		t.Fatal("expected p1 to be enabled in store by default")
	}

	proxies, err := mgr.ListStoreProxies()
	if err != nil || len(proxies) != 1 {
		t.Fatalf("ListStoreProxies: len=%d, err=%v", len(proxies), err)
	}

	if _, err := mgr.GetStoreProxy(""); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for empty name, got %v", err)
	}
	if _, err := mgr.GetStoreProxy("missing"); !errors.Is(err, configmgmt.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing proxy, got %v", err)
	}
	if got, err := mgr.GetStoreProxy("p1"); err != nil || got.GetBaseConfig().Name != "p1" {
		t.Fatalf("GetStoreProxy(p1): %v, %v", got, err)
	}
	if got, ok := mgr.GetProxyConfig("p1"); !ok || got.GetBaseConfig().Name != "p1" {
		t.Fatalf("GetProxyConfig(p1): ok=%v", ok)
	}
	if _, ok := mgr.GetProxyConfig("missing"); ok {
		t.Fatal("expected GetProxyConfig(missing) to return false")
	}

	// UpdateStoreProxy error cases and success
	if _, err := mgr.UpdateStoreProxy("", p1); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on empty name: %v", err)
	}
	if _, err := mgr.UpdateStoreProxy("p1", nil); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on nil cfg: %v", err)
	}
	if _, err := mgr.UpdateStoreProxy("other", p1); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on name mismatch: %v", err)
	}
	missingPxy := newTestRawTCPProxyConfig("missing")
	if _, err := mgr.UpdateStoreProxy("missing", missingPxy); !errors.Is(err, configmgmt.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on updating missing proxy: %v", err)
	}

	disabled := false
	p1.Enabled = &disabled
	p1.LocalPort = 10081
	if _, err := mgr.UpdateStoreProxy("p1", p1); err != nil {
		t.Fatalf("UpdateStoreProxy(p1): %v", err)
	}
	if mgr.IsStoreProxyEnabled("p1") {
		t.Fatal("expected IsStoreProxyEnabled(p1) to be false after disabling")
	}

	// DeleteStoreProxy error cases and success
	if err := mgr.DeleteStoreProxy(""); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on empty delete name: %v", err)
	}
	if err := mgr.DeleteStoreProxy("missing"); !errors.Is(err, configmgmt.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on deleting missing proxy: %v", err)
	}
	if err := mgr.DeleteStoreProxy("p1"); err != nil {
		t.Fatalf("DeleteStoreProxy(p1): %v", err)
	}

	// 3. Visitor CRUD
	if _, err := mgr.CreateStoreVisitor(nil); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for nil visitor: %v", err)
	}
	vcfg := &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name:       "v1",
			Type:       "stcp",
			ServerName: "srv1",
			SecretKey:  "sec",
			BindPort:   9001,
		},
	}
	if _, err := mgr.CreateStoreVisitor(vcfg); err != nil {
		t.Fatalf("CreateStoreVisitor: %v", err)
	}
	if _, err := mgr.CreateStoreVisitor(vcfg); !errors.Is(err, configmgmt.ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate visitor: %v", err)
	}

	visitors, err := mgr.ListStoreVisitors()
	if err != nil || len(visitors) != 1 {
		t.Fatalf("ListStoreVisitors: len=%d, err=%v", len(visitors), err)
	}
	if _, err := mgr.GetStoreVisitor(""); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for empty visitor name: %v", err)
	}
	if _, err := mgr.GetStoreVisitor("missing"); !errors.Is(err, configmgmt.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing visitor: %v", err)
	}
	if got, err := mgr.GetStoreVisitor("v1"); err != nil || got.GetBaseConfig().Name != "v1" {
		t.Fatalf("GetStoreVisitor(v1): %v, %v", got, err)
	}
	if got, ok := mgr.GetVisitorConfig("v1"); !ok || got.GetBaseConfig().Name != "v1" {
		t.Fatalf("GetVisitorConfig(v1): ok=%v", ok)
	}
	if _, ok := mgr.GetVisitorConfig("missing"); ok {
		t.Fatal("expected GetVisitorConfig(missing) to return false")
	}

	// UpdateStoreVisitor error cases and success
	if _, err := mgr.UpdateStoreVisitor("", vcfg); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on empty visitor name: %v", err)
	}
	if _, err := mgr.UpdateStoreVisitor("v1", nil); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on nil visitor cfg: %v", err)
	}
	if _, err := mgr.UpdateStoreVisitor("other", vcfg); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on visitor name mismatch: %v", err)
	}
	missingVisitor := &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name:       "missing",
			Type:       "stcp",
			ServerName: "srv1",
			BindPort:   9002,
		},
	}
	if _, err := mgr.UpdateStoreVisitor("missing", missingVisitor); !errors.Is(err, configmgmt.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on updating missing visitor: %v", err)
	}
	vcfg.BindPort = 9003
	if _, err := mgr.UpdateStoreVisitor("v1", vcfg); err != nil {
		t.Fatalf("UpdateStoreVisitor(v1): %v", err)
	}

	// DeleteStoreVisitor error cases and success
	if err := mgr.DeleteStoreVisitor(""); !errors.Is(err, configmgmt.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on empty delete visitor name: %v", err)
	}
	if err := mgr.DeleteStoreVisitor("missing"); !errors.Is(err, configmgmt.ErrNotFound) {
		t.Fatalf("expected ErrNotFound on deleting missing visitor: %v", err)
	}
	if err := mgr.DeleteStoreVisitor("v1"); err != nil {
		t.Fatalf("DeleteStoreVisitor(v1): %v", err)
	}
}

func TestAPIRouterRegistration(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "frpc.toml")
	if err := os.WriteFile(cfgPath, []byte("serverAddr = \"127.0.0.1\"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	storeSource, err := source.NewStoreSource(source.StoreSourceConfig{
		Path: filepath.Join(tmpDir, "store.json"),
	})
	if err != nil {
		t.Fatalf("new store source: %v", err)
	}
	agg := source.NewAggregator(source.NewConfigSource())
	agg.SetStoreSource(storeSource)

	common := &v1.ClientCommonConfig{ServerAddr: "127.0.0.1"}
	_ = common.Complete()

	svr := &Service{
		aggregator:     agg,
		configSource:   agg.ConfigSource(),
		storeSource:    storeSource,
		common:         common,
		reloadCommon:   common,
		configFilePath: cfgPath,
	}

	router := mux.NewRouter()
	helper := &httppkg.RouterRegisterHelper{
		Router:         router,
		AssetsFS:       http.Dir(tmpDir),
		AuthMiddleware: func(next http.Handler) http.Handler { return next },
	}
	svr.registerRouteHandlers(helper)

	// /healthz
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /healthz, got %d", rec.Code)
	}

	// / redirects to /static/
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("expected 301 on /, got %d", rec.Code)
	}

	// /api/status and /api/config
	for _, path := range []string{"/api/status", "/api/config", "/api/store/proxies", "/api/store/visitors"} {
		rec = httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 on %s, got %d (%s)", path, rec.Code, rec.Body.String())
		}
	}
}
