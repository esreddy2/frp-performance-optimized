// Copyright 2017 fatedier, fatedier@gmail.com
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

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatedier/golib/crypto"
	"github.com/samber/lo"

	"github.com/fatedier/frp/client/proxy"
	"github.com/fatedier/frp/pkg/auth"
	"github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/metrics/text"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/policy/security"
	httppkg "github.com/fatedier/frp/pkg/util/http"
	"github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/wait"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/pkg/vnet"
)

func init() {
	crypto.DefaultSalt = "frp"
	// Disable quic-go's receive buffer warning.
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	// Disable quic-go's ECN support by default. It may cause issues on certain operating systems.
	if os.Getenv("QUIC_GO_DISABLE_ECN") == "" {
		os.Setenv("QUIC_GO_DISABLE_ECN", "true")
	}
}

type cancelErr struct {
	Err error
}

func (e cancelErr) Error() string {
	return e.Err.Error()
}

// ServiceOptions contains options for creating a new client service.
type ServiceOptions struct {
	Common *v1.ClientCommonConfig

	// InitialRunID is sent in the first login request. When empty, frps
	// assigns a RunID as usual. After a successful login, the RunID returned
	// by frps is used for subsequent reconnects.
	InitialRunID string

	// OnFirstLoginSuccess is called synchronously with the RunID returned after
	// frps has accepted and authenticated a Login, before the corresponding
	// control is created or starts proxy and visitor registration. It runs at
	// most once in this Service lifetime; a later internal reconnect cannot act
	// on state created after the first accepted Login. Returning an error rejects
	// the authenticated session, closes it, and terminates the Service without
	// installing a control. The RunID is passed through verbatim, so a caller
	// that correlates it with external state must validate it before applying
	// side effects. Cancellation observed immediately after Login acceptance
	// skips the hook; cancellation concurrent with hook dispatch may still allow
	// that one synchronous call. The caller owns callback execution: it must
	// return promptly, and a panic propagates like other ServiceOptions callbacks.
	// The returned Service error wraps the callback error for errors.Is/errors.As,
	// but uses a fixed message so callback details cannot create unbounded log
	// output.
	OnFirstLoginSuccess func(runID string) error

	// ConfigSourceAggregator manages internal config and optional store sources.
	// It is required for creating a Service.
	ConfigSourceAggregator *source.Aggregator

	UnsafeFeatures *security.UnsafeFeatures

	// ConfigFilePath is the path to the configuration file used to initialize.
	// If it is empty, it means that the configuration file is not used for initialization.
	// It may be initialized using command line parameters or called directly.
	ConfigFilePath string

	// ClientSpec is the client specification that control the client behavior.
	ClientSpec *msg.ClientSpec

	// ConnectorCreator is a function that creates a new connector to make connections to the server.
	// The Connector shields the underlying connection details, whether it is through TCP or QUIC connection,
	// and regardless of whether multiplexing is used.
	//
	// If it is not set, the default frpc connector will be used.
	// By using a custom Connector, it can be used to implement a VirtualClient, which connects to frps
	// through a pipe instead of a real physical connection.
	ConnectorCreator func(context.Context, *v1.ClientCommonConfig) Connector

	// HandleWorkConnCb is a callback function that is called when a new work connection is created.
	//
	// If it is not set, the default frpc implementation will be used.
	HandleWorkConnCb func(*v1.ProxyBaseConfig, net.Conn, *msg.StartWorkConn) bool
}

// setServiceOptionsDefault sets the default values for ServiceOptions.
func setServiceOptionsDefault(options *ServiceOptions) error {
	if options.Common != nil {
		if err := options.Common.Complete(); err != nil {
			return err
		}
	}
	if options.ConnectorCreator == nil {
		options.ConnectorCreator = NewConnector
	}
	return nil
}

// Service is the client service that connects to frps and provides proxy services.
type Service struct {
	ctlMu sync.RWMutex
	// Stores gracefulShutdownDuration independently from ctlMu, because the
	// graceful shutdown wait may hold ctlMu for an arbitrary duration.
	gracefulShutdownDuration atomic.Int64
	// manager control connection with server
	ctl *Control
	// Uniq id got from frps, it will be attached to loginMsg.
	runIDMu sync.Mutex
	runID   string

	// Auth runtime and encryption materials
	auth *auth.ClientAuth

	// web server for admin UI and apis
	webServer     *httppkg.Server
	metricsServer *httppkg.Server

	// WaitGroups join the Run goroutines of the HTTP servers and the vnet
	// controller so shutdown can wait for them to exit.
	webServerWg     sync.WaitGroup
	metricsServerWg sync.WaitGroup
	vnetWg          sync.WaitGroup

	vnetController *vnet.Controller

	cfgMu sync.RWMutex
	// reloadMu serializes config updates with control startup and publication,
	// keeping reloadCommon and applied config in sync across reloads and reconnects.
	reloadMu sync.Mutex
	common   *v1.ClientCommonConfig
	// reloadCommon is used for filtering/defaulting during config-source reloads.
	// It can be updated by /api/reload without mutating startup-only common behavior.
	reloadCommon *v1.ClientCommonConfig
	proxyCfgs    []v1.ProxyConfigurer
	visitorCfgs  []v1.VisitorConfigurer
	clientSpec   *msg.ClientSpec

	// aggregator manages multiple configuration sources.
	// When set, the service watches for config changes and reloads automatically.
	aggregator   *source.Aggregator
	configSource *source.ConfigSource
	storeSource  *source.StoreSource

	unsafeFeatures *security.UnsafeFeatures

	// The configuration file used to initialize this client, or an empty
	// string if no configuration file was used.
	configFilePath string

	// service context
	ctx context.Context
	// call cancel to stop service
	cancel context.CancelCauseFunc
	// Protect cancel publication and shutdown before the first Run.
	lifecycleMu sync.Mutex
	closed      bool

	connectorCreator func(context.Context, *v1.ClientCommonConfig) Connector
	handleWorkConnCb func(*v1.ProxyBaseConfig, net.Conn, *msg.StartWorkConn) bool

	onFirstLoginSuccess func(string) error
	// firstLoginSuccessOnce guards the hook so it runs at most once per Service
	// lifetime, no matter how often the client reconnects.
	firstLoginSuccessOnce sync.Once
	// firstLoginSuccessError is written only by the synchronous first-login
	// path before the reconnect goroutine starts; later reconnects read it
	// after sync.Once.Do returns.
	firstLoginSuccessError error
}

func NewService(options ServiceOptions) (*Service, error) {
	if err := setServiceOptionsDefault(&options); err != nil {
		return nil, err
	}

	authRuntime, err := auth.BuildClientAuth(&options.Common.Auth)
	if err != nil {
		return nil, err
	}

	if options.ConfigSourceAggregator == nil {
		return nil, fmt.Errorf("config source aggregator is required")
	}

	configSource := options.ConfigSourceAggregator.ConfigSource()
	storeSource := options.ConfigSourceAggregator.StoreSource()

	proxyCfgs, visitorCfgs, loadErr := options.ConfigSourceAggregator.Load()
	if loadErr != nil {
		return nil, fmt.Errorf("failed to load config from aggregator: %w", loadErr)
	}
	proxyCfgs, visitorCfgs = config.FilterClientConfigurers(options.Common, proxyCfgs, visitorCfgs)
	proxyCfgs = config.CompleteProxyConfigurers(proxyCfgs)
	visitorCfgs = config.CompleteVisitorConfigurers(visitorCfgs)

	// Create HTTP servers after all other fallible steps, rolling back the web
	// listener if the metrics server cannot be created.
	var webServer *httppkg.Server
	if options.Common.WebServer.Port > 0 {
		ws, err := httppkg.NewServer(options.Common.WebServer)
		if err != nil {
			return nil, err
		}
		webServer = ws
	}
	// frpc exposes Go runtime metrics only. They are written by pkg/metrics/text
	// so that client_golang and protobuf stay out of the frpc binary.
	var metricsHandler http.Handler
	if options.Common.MetricsServer.Port > 0 {
		registry := text.NewRegistry()
		registry.RegisterRuntime()
		metricsHandler = registry.Handler()
	}
	metricsServer, err := httppkg.NewMetricsServer(options.Common.MetricsServer, metricsHandler)
	if err != nil {
		if webServer != nil {
			_ = webServer.Close()
		}
		return nil, err
	}

	s := &Service{
		ctx:              context.Background(),
		auth:             authRuntime,
		webServer:        webServer,
		metricsServer:    metricsServer,
		common:           options.Common,
		reloadCommon:     options.Common,
		configFilePath:   options.ConfigFilePath,
		unsafeFeatures:   options.UnsafeFeatures,
		proxyCfgs:        proxyCfgs,
		visitorCfgs:      visitorCfgs,
		clientSpec:       options.ClientSpec,
		aggregator:       options.ConfigSourceAggregator,
		configSource:     configSource,
		storeSource:      storeSource,
		runID:            options.InitialRunID,
		connectorCreator: options.ConnectorCreator,
		handleWorkConnCb: options.HandleWorkConnCb,

		onFirstLoginSuccess: options.OnFirstLoginSuccess,
	}

	if webServer != nil {
		webServer.RouteRegister(s.registerRouteHandlers)
	}
	if options.Common.VirtualNet.Address != "" {
		s.vnetController = vnet.NewController(options.Common.VirtualNet)
	}
	return s, nil
}

// Run drives the service. A Service is single-use: after Close or
// GracefulClose has been called, Run returns without attempting login.
func (svr *Service) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	svr.lifecycleMu.Lock()
	if svr.closed {
		svr.lifecycleMu.Unlock()
		cancel(nil)
		return ctx.Err()
	}
	svr.ctx = xlog.NewContext(ctx, xlog.FromContextSafe(ctx))
	svr.cancel = cancel
	svr.lifecycleMu.Unlock()
	defer cancel(nil)
	defer svr.stop()
	if err := ctx.Err(); err != nil {
		return err
	}

	// set custom DNSServer
	if svr.common.DNSServer != "" {
		netpkg.SetDefaultDNSAddress(svr.common.DNSServer)
	}

	if svr.vnetController != nil {
		vnetController := svr.vnetController
		if err := svr.vnetController.Init(); err != nil {
			log.Errorf("init virtual network controller error: %v", err)
			if stopErr := vnetController.Stop(); stopErr != nil {
				log.Warnf("stop virtual network controller error: %v", stopErr)
			}
			svr.vnetController = nil
			return err
		}
		svr.vnetWg.Go(func() {
			log.Infof("virtual network controller start...")
			if err := vnetController.Run(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Warnf("virtual network controller exit with error: %v", err)
				if svr.cancel != nil {
					svr.cancel(cancelErr{Err: err})
				}
			}
		})
	}

	if svr.webServer != nil {
		if svr.common.WebServer.PprofEnable {
			log.Warnf("webServer pprof endpoints are deprecated; use metricsServer.pprofEnable instead")
		}
		if svr.common.MetricsServer.Port == 0 {
			log.Infof("webServer /healthz is deprecated; health probes can migrate to metricsServer.port")
		}
		webServer := svr.webServer
		svr.webServerWg.Go(func() {
			log.Infof("admin server listen on %s", webServer.Address())
			if err := webServer.Run(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warnf("admin server exit with error: %v", err)
			}
		})
	}

	if svr.metricsServer != nil {
		metricsServer := svr.metricsServer
		svr.metricsServerWg.Go(func() {
			log.Infof("metrics server listen on %s", metricsServer.Address())
			if err := metricsServer.Run(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warnf("metrics server exit with error: %v", err)
			}
		})
	}

	// first login to frps
	svr.loopLoginUntilSuccess(10*time.Second, lo.FromPtr(svr.common.LoginFailExit))
	if svr.ctl == nil {
		// A rejected first-login hook is reported with its own error so the
		// caller can match it with errors.Is/errors.As.
		if svr.firstLoginSuccessError != nil {
			return svr.firstLoginSuccessError
		}
		svr.lifecycleMu.Lock()
		closed := svr.closed
		svr.lifecycleMu.Unlock()
		if closed {
			// The owner asked the service to stop, so the missing control is
			// the expected outcome and not a login failure.
			return nil
		}
		cancelCause := cancelErr{}
		if !errors.As(context.Cause(svr.ctx), &cancelCause) {
			return fmt.Errorf("login to the server failed: %w", context.Cause(svr.ctx))
		}
		return fmt.Errorf("login to the server failed: %v. With loginFailExit enabled, no additional retries will be attempted", cancelCause.Err)
	}

	svr.ctlMu.RLock()
	initialCtl := svr.ctl
	svr.ctlMu.RUnlock()
	go svr.keepControllerWorking(initialCtl)

	<-svr.ctx.Done()
	return nil
}

func (svr *Service) keepControllerWorking(initialCtl *Control) {
	// Re-read the current control under lock so a replacement that happened
	// before this goroutine started is not missed.
	ctl := initialCtl
	svr.ctlMu.RLock()
	if cur := svr.ctl; cur != nil {
		ctl = cur
	}
	svr.ctlMu.RUnlock()
	if ctl == nil {
		return
	}
	<-ctl.Done()

	// There is a situation where the login is successful but due to certain reasons,
	// the control immediately exits. It is necessary to limit the frequency of reconnection in this case.
	// The interval for the first three retries in 1 minute will be very short, and then it will increase exponentially.
	// The maximum interval is 20 seconds.
	wait.BackoffUntil(func() (bool, error) {
		// loopLoginUntilSuccess is another layer of loop that will continuously attempt to
		// login to the server until successful.
		svr.loopLoginUntilSuccess(20*time.Second, false)
		svr.ctlMu.RLock()
		ctl := svr.ctl
		svr.ctlMu.RUnlock()
		if ctl != nil {
			<-ctl.Done()
			return false, errors.New("control is closed and try another loop")
		}
		// If ctl is nil, no control was installed (login failure, rejected
		// first-login hook, or service shutdown); stop reconnecting.
		return false, nil
	}, wait.NewFastBackoffManager(
		wait.FastBackoffOptions{
			Duration:        time.Second,
			Factor:          2,
			Jitter:          0.1,
			MaxDuration:     20 * time.Second,
			FastRetryCount:  3,
			FastRetryDelay:  200 * time.Millisecond,
			FastRetryWindow: time.Minute,
			FastRetryJitter: 0.5,
		},
	), true, svr.ctx.Done())
}

func (svr *Service) loopLoginUntilSuccess(maxInterval time.Duration, firstLoginExit bool) {
	xl := xlog.FromContextSafe(svr.ctx)

	loginFunc := func() (bool, error) {
		if svr.ctx.Err() != nil {
			return false, svr.ctx.Err()
		}
		xl.Infof("try to connect to server...")
		dialer := &controlSessionDialer{
			ctx:              svr.ctx,
			common:           svr.common,
			auth:             svr.auth,
			clientSpec:       svr.clientSpec,
			vnetController:   svr.vnetController,
			connectorCreator: svr.connectorCreator,
		}
		svr.runIDMu.Lock()
		runID := svr.runID
		svr.runIDMu.Unlock()
		sessionCtx, err := dialer.Dial(runID)
		if err != nil {
			errOutput := err
			if !lo.FromPtr(svr.common.Transport.TLS.Enable) && !svr.common.Transport.UsesImplicitTLS() {
				errOutput = fmt.Errorf(
					"%w (transport.tls.enable is false; if server enforces TLS via transport.tls.force = true, set transport.tls.enable = true in frpc.toml)",
					err,
				)
			}
			xl.Warnf("connect to server error: %v", errOutput)
			if firstLoginExit {
				svr.cancel(cancelErr{Err: errOutput})
			}
			return false, errOutput
		}
		// The service may have been closed while the login was in flight. Drop
		// the accepted session instead of installing a control for a service
		// that is already shutting down.
		if svr.ctx.Err() != nil {
			closeSessionContext(sessionCtx)
			return false, context.Cause(svr.ctx)
		}

		svr.runIDMu.Lock()
		svr.runID = sessionCtx.RunID
		runID = svr.runID
		svr.runIDMu.Unlock()
		xl.AddPrefix(xlog.LogPrefix{Name: "runID", Value: runID})
		xl.Infof("login to server success, get run id [%s]", runID)
		if err := svr.runFirstLoginSuccessHook(); err != nil {
			closeSessionContext(sessionCtx)
			svr.cancel(cancelErr{Err: err})
			xl.Errorf("accepted login rejected: %v", err)
			return false, err
		}

		ctl, err := NewControl(svr.ctx, sessionCtx)
		if err != nil {
			closeSessionContext(sessionCtx)
			xl.Errorf("new control error: %v", err)
			return false, err
		}
		ctl.SetInWorkConnCallback(svr.handleWorkConnCb)

		// Capture the config snapshot under reloadMu, then publish the new
		// control before running proxy startup so reloads issued during startup
		// target the new control. Proxy startup itself runs outside the lock
		// so reloads are not blocked by it.
		svr.reloadMu.Lock()
		svr.cfgMu.RLock()
		proxyCfgs := svr.proxyCfgs
		visitorCfgs := svr.visitorCfgs
		svr.cfgMu.RUnlock()

		svr.ctlMu.Lock()
		old := svr.ctl
		svr.ctl = ctl
		svr.ctlMu.Unlock()
		svr.reloadMu.Unlock()

		ctl.Run(proxyCfgs, visitorCfgs)

		if old != nil {
			old.Close()
		}
		return true, nil
	}

	// try to reconnect to server until success
	wait.BackoffUntil(loginFunc, wait.NewFastBackoffManager(
		wait.FastBackoffOptions{
			Duration:    time.Second,
			Factor:      2,
			Jitter:      0.1,
			MaxDuration: maxInterval,
		}), true, svr.ctx.Done())
}

// firstLoginSuccessHookError reports that the first-login hook rejected an
// authenticated session. The cause is preserved for errors.Is/errors.As, but
// the message is fixed so a callback error cannot create unbounded log output.
type firstLoginSuccessHookError struct {
	cause error
}

func (e *firstLoginSuccessHookError) Error() string {
	return "first login success hook rejected authenticated session"
}

func (e *firstLoginSuccessHookError) Unwrap() error {
	return e.cause
}

// runFirstLoginSuccessHook invokes the first-login hook at most once per
// Service lifetime and returns the recorded rejection, if any.
func (svr *Service) runFirstLoginSuccessHook() error {
	if svr.onFirstLoginSuccess == nil {
		return nil
	}
	svr.firstLoginSuccessOnce.Do(func() {
		svr.runIDMu.Lock()
		runID := svr.runID
		svr.runIDMu.Unlock()
		if err := svr.onFirstLoginSuccess(runID); err != nil {
			svr.firstLoginSuccessError = &firstLoginSuccessHookError{cause: err}
		}
	})
	return svr.firstLoginSuccessError
}

// closeSessionContext releases the resources of an accepted but unused
// control session.
func closeSessionContext(sessionCtx *SessionContext) {
	_ = sessionCtx.Conn.Close()
	_ = sessionCtx.Connector.Close()
}

func (svr *Service) UpdateAllConfigurer(proxyCfgs []v1.ProxyConfigurer, visitorCfgs []v1.VisitorConfigurer) error {
	svr.reloadMu.Lock()
	defer svr.reloadMu.Unlock()
	return svr.updateAllConfigurerLocked(proxyCfgs, visitorCfgs)
}

// Caller must hold reloadMu.
func (svr *Service) updateAllConfigurerLocked(proxyCfgs []v1.ProxyConfigurer, visitorCfgs []v1.VisitorConfigurer) error {
	svr.cfgMu.Lock()
	svr.proxyCfgs = proxyCfgs
	svr.visitorCfgs = visitorCfgs
	svr.cfgMu.Unlock()

	svr.ctlMu.RLock()
	defer svr.ctlMu.RUnlock()
	ctl := svr.ctl
	if ctl != nil {
		return ctl.UpdateAllConfigurer(proxyCfgs, visitorCfgs)
	}
	return nil
}

func (svr *Service) UpdateConfigSource(
	common *v1.ClientCommonConfig,
	proxyCfgs []v1.ProxyConfigurer,
	visitorCfgs []v1.VisitorConfigurer,
) error {
	svr.reloadMu.Lock()
	defer svr.reloadMu.Unlock()

	return svr.updateConfigSourceLocked(common, proxyCfgs, visitorCfgs)
}

// Caller must hold reloadMu.
func (svr *Service) updateConfigSourceLocked(
	common *v1.ClientCommonConfig,
	proxyCfgs []v1.ProxyConfigurer,
	visitorCfgs []v1.VisitorConfigurer,
) error {
	cfgSource := svr.configSource
	if cfgSource == nil {
		return fmt.Errorf("config source is not available")
	}

	if err := cfgSource.ReplaceAll(proxyCfgs, visitorCfgs); err != nil {
		return err
	}

	// Non-atomic update semantics: source has been updated at this point.
	// Even if reload fails below, keep this common config for subsequent reloads.
	svr.cfgMu.Lock()
	svr.reloadCommon = common
	svr.cfgMu.Unlock()

	if err := svr.reloadConfigFromSourcesLocked(); err != nil {
		return err
	}
	return nil
}

func (svr *Service) Close() {
	svr.GracefulClose(time.Duration(0))
}

func (svr *Service) GracefulClose(d time.Duration) {
	svr.gracefulShutdownDuration.Store(int64(d))
	svr.lifecycleMu.Lock()
	if svr.closed {
		svr.lifecycleMu.Unlock()
		return
	}
	svr.closed = true
	cancel := svr.cancel
	svr.lifecycleMu.Unlock()
	if cancel != nil {
		// Once Run has claimed startup, it also owns cleanup.
		cancel(nil)
	} else {
		svr.stop()
	}
}

func (svr *Service) stop() {
	// Coordinate shutdown with reload/update paths that read source pointers.
	svr.reloadMu.Lock()
	if svr.aggregator != nil {
		svr.aggregator = nil
	}
	svr.configSource = nil
	svr.storeSource = nil
	svr.reloadMu.Unlock()

	svr.ctlMu.Lock()
	ctl := svr.ctl
	svr.ctl = nil
	svr.ctlMu.Unlock()

	if ctl != nil {
		d := time.Duration(svr.gracefulShutdownDuration.Load())
		ctl.GracefulClose(d)
	}
	if svr.webServer != nil {
		if err := svr.webServer.Close(); err != nil {
			log.Warnf("close web server error: %v", err)
		}
		svr.webServer = nil
	}
	svr.webServerWg.Wait()
	if svr.metricsServer != nil {
		if err := svr.metricsServer.Close(); err != nil {
			log.Warnf("close metrics server error: %v", err)
		}
		svr.metricsServer = nil
	}
	svr.metricsServerWg.Wait()
	if svr.vnetController != nil {
		if err := svr.vnetController.Stop(); err != nil {
			log.Warnf("stop virtual network controller error: %v", err)
		}
		svr.vnetController = nil
	}
	svr.vnetWg.Wait()
}

func (svr *Service) getProxyStatus(name string) (*proxy.WorkingStatus, bool) {
	svr.ctlMu.RLock()
	ctl := svr.ctl
	svr.ctlMu.RUnlock()

	if ctl == nil {
		return nil, false
	}
	return ctl.pm.GetProxyStatus(name)
}

func (svr *Service) getVisitorCfg(name string) (v1.VisitorConfigurer, bool) {
	svr.ctlMu.RLock()
	ctl := svr.ctl
	svr.ctlMu.RUnlock()

	if ctl == nil {
		return nil, false
	}
	return ctl.vm.GetVisitorCfg(name)
}

func (svr *Service) StatusExporter() StatusExporter {
	return &statusExporterImpl{
		getProxyStatusFunc: svr.getProxyStatus,
	}
}

type StatusExporter interface {
	GetProxyStatus(name string) (*proxy.WorkingStatus, bool)
}

type statusExporterImpl struct {
	getProxyStatusFunc func(name string) (*proxy.WorkingStatus, bool)
}

func (s *statusExporterImpl) GetProxyStatus(name string) (*proxy.WorkingStatus, bool) {
	return s.getProxyStatusFunc(name)
}

func (svr *Service) reloadConfigFromSources() error {
	svr.reloadMu.Lock()
	defer svr.reloadMu.Unlock()
	return svr.reloadConfigFromSourcesLocked()
}

func (svr *Service) reloadConfigFromSourcesLocked() error {
	aggregator := svr.aggregator
	if aggregator == nil {
		return errors.New("config aggregator is not initialized")
	}

	svr.cfgMu.RLock()
	reloadCommon := svr.reloadCommon
	svr.cfgMu.RUnlock()

	proxies, visitors, err := aggregator.Load()
	if err != nil {
		return fmt.Errorf("reload config from sources failed: %w", err)
	}

	proxies, visitors = config.FilterClientConfigurers(reloadCommon, proxies, visitors)
	proxies = config.CompleteProxyConfigurers(proxies)
	visitors = config.CompleteVisitorConfigurers(visitors)
	requirements := validation.GetClientConfigRequirements(reloadCommon, proxies, visitors)
	if svr.vnetController == nil && requirements.VirtualNet {
		return errors.New(
			"VirtualNet-dependent configuration requires a VirtualNet runtime enabled at startup; " +
				"restart frpc after configuring featureGates.VirtualNet and virtualNet.address",
		)
	}

	// Atomically replace the entire configuration
	if err := svr.updateAllConfigurerLocked(proxies, visitors); err != nil {
		return err
	}
	return nil
}
