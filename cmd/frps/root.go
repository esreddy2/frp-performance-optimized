// Copyright 2018 fatedier, fatedier@gmail.com
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

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/fatedier/frp/pkg/config"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/policy/security"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/version"
	"github.com/fatedier/frp/server"
)

var (
	cfgFile          string
	showVersion      bool
	strictConfigMode bool
	allowUnsafe      []string

	serverCfg v1.ServerConfig
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file of frps")
	rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "version of frps")
	rootCmd.PersistentFlags().BoolVarP(&strictConfigMode, "strict_config", "", true, "strict config parsing mode, unknown fields will cause errors")
	rootCmd.PersistentFlags().StringSliceVarP(&allowUnsafe, "allow-unsafe", "", []string{},
		fmt.Sprintf("allowed unsafe features, one or more of: %s", strings.Join(security.ServerUnsafeFeatures, ", ")))

	config.RegisterServerConfigFlags(rootCmd, &serverCfg)
}

var rootCmd = &cobra.Command{
	Use:   "frps",
	Short: "frps is the server of frp (https://github.com/fatedier/frp)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Println(version.Full())
			return nil
		}

		var (
			svrCfg         *v1.ServerConfig
			isLegacyFormat bool
			err            error
		)
		if cfgFile != "" {
			svrCfg, isLegacyFormat, err = config.LoadServerConfig(cfgFile, strictConfigMode)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			if isLegacyFormat {
				fmt.Printf("WARNING: ini format is deprecated and the support will be removed in the future, " +
					"please use yaml/json/toml format instead!\n")
			}
			mergeServerConfigFlags(cmd, svrCfg, &serverCfg)
		} else {
			if err := serverCfg.Complete(); err != nil {
				fmt.Printf("failed to complete server config: %v\n", err)
				os.Exit(1)
			}
			svrCfg = &serverCfg
		}

		unsafeFeatures := security.NewUnsafeFeatures(allowUnsafe)
		validator := validation.NewConfigValidator(unsafeFeatures)
		warning, err := validator.ValidateServerConfig(svrCfg)
		if warning != nil {
			fmt.Printf("WARNING: %v\n", warning)
		}
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if err := runServer(svrCfg); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return nil
	},
}

func Execute() {
	rootCmd.SetGlobalNormalizationFunc(config.WordSepNormalizeFunc)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func mergeServerConfigFlags(cmd *cobra.Command, dst, src *v1.ServerConfig) {
	flags := cmd.PersistentFlags()
	if flags.Changed("bind_addr") {
		dst.BindAddr = src.BindAddr
	}
	if flags.Changed("bind_port") {
		dst.BindPort = src.BindPort
	}
	if flags.Changed("kcp_bind_port") {
		dst.KCPBindPort = src.KCPBindPort
	}
	if flags.Changed("quic_bind_port") {
		dst.QUICBindPort = src.QUICBindPort
	}
	if flags.Changed("proxy_bind_addr") {
		dst.ProxyBindAddr = src.ProxyBindAddr
	}
	if flags.Changed("vhost_http_port") {
		dst.VhostHTTPPort = src.VhostHTTPPort
	}
	if flags.Changed("vhost_https_port") {
		dst.VhostHTTPSPort = src.VhostHTTPSPort
	}
	if flags.Changed("vhost_http_timeout") {
		dst.VhostHTTPTimeout = src.VhostHTTPTimeout
	}
	if flags.Changed("dashboard_addr") {
		dst.WebServer.Addr = src.WebServer.Addr
	}
	if flags.Changed("dashboard_port") {
		dst.WebServer.Port = src.WebServer.Port
	}
	if flags.Changed("dashboard_user") {
		dst.WebServer.User = src.WebServer.User
	}
	if flags.Changed("dashboard_pwd") {
		dst.WebServer.Password = src.WebServer.Password
	}
	if flags.Changed("enable_prometheus") {
		dst.EnablePrometheus = src.EnablePrometheus
	}
	if flags.Changed("log_file") {
		dst.Log.To = src.Log.To
	}
	if flags.Changed("log_level") {
		dst.Log.Level = src.Log.Level
	}
	if flags.Changed("log_max_days") {
		dst.Log.MaxDays = src.Log.MaxDays
	}
	if flags.Changed("disable_log_color") {
		dst.Log.DisablePrintColor = src.Log.DisablePrintColor
	}
	if flags.Changed("token") {
		dst.Auth.Token = src.Auth.Token
	}
	if flags.Changed("subdomain_host") {
		dst.SubDomainHost = src.SubDomainHost
	}
	if flags.Changed("allow_ports") {
		dst.AllowPorts = src.AllowPorts
	}
	if flags.Changed("max_ports_per_client") {
		dst.MaxPortsPerClient = src.MaxPortsPerClient
	}
	if flags.Changed("tls_only") {
		dst.Transport.TLS.Force = src.Transport.TLS.Force
	}
	if flags.Changed("dashboard_tls_mode") {
		dst.WebServer.TLS = src.WebServer.TLS
	}
	if flags.Changed("dashboard_tls_cert_file") && dst.WebServer.TLS != nil && src.WebServer.TLS != nil {
		dst.WebServer.TLS.CertFile = src.WebServer.TLS.CertFile
	}
	if flags.Changed("dashboard_tls_key_file") && dst.WebServer.TLS != nil && src.WebServer.TLS != nil {
		dst.WebServer.TLS.KeyFile = src.WebServer.TLS.KeyFile
	}
	_ = dst.Complete()
}

func runServer(cfg *v1.ServerConfig) (err error) {
	log.InitLogger(cfg.Log.To, cfg.Log.Level, int(cfg.Log.MaxDays), cfg.Log.DisablePrintColor)

	if cfgFile != "" {
		log.Infof("frps uses config file: %s", cfgFile)
	} else {
		log.Infof("frps uses command line arguments for config")
	}

	svr, err := server.NewService(cfg)
	if err != nil {
		return err
	}
	log.Infof("frps started successfully")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	svr.Run(ctx)
	return
}
