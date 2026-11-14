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

//go:build !frps

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

func init() {
	Register(v1.PluginStaticFile, NewStaticFilePlugin)
}

type restrictedDir struct {
	root string
}

func newRestrictedDir(root string) (*restrictedDir, error) {
	if root == "" {
		return nil, errors.New("static file plugin local_path cannot be empty")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("invalid local_path: %w", err)
	}
	evalRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve local_path: %w", err)
	}
	return &restrictedDir{root: evalRoot}, nil
}

func (d *restrictedDir) Open(name string) (http.File, error) {
	if filepath.Separator != '/' && strings.ContainsRune(name, filepath.Separator) {
		return nil, errors.New("http: invalid character in file path")
	}
	fullName := filepath.Join(d.root, filepath.FromSlash(path.Clean("/"+name)))
	evalName, err := filepath.EvalSymlinks(fullName)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(d.root, evalName)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}
	return os.Open(evalName)
}

type StaticFilePlugin struct {
	opts *v1.StaticFilePluginOptions

	l *Listener
	s *http.Server
}

func NewStaticFilePlugin(_ PluginContext, options v1.ClientPluginOptions) (Plugin, error) {
	opts := options.(*v1.StaticFilePluginOptions)

	fs, err := newRestrictedDir(opts.LocalPath)
	if err != nil {
		return nil, err
	}

	listener := NewProxyListener()

	sp := &StaticFilePlugin{
		opts: opts,

		l: listener,
	}
	var prefix string
	if opts.StripPrefix != "" {
		trimmed := strings.Trim(opts.StripPrefix, "/")
		if trimmed != "" {
			prefix = "/" + trimmed + "/"
		} else {
			prefix = "/"
		}
	} else {
		prefix = "/"
	}

	router := mux.NewRouter()
	router.Use(netpkg.NewHTTPAuthMiddleware(opts.HTTPUser, opts.HTTPPassword).SetAuthFailDelay(200 * time.Millisecond).Middleware)
	router.PathPrefix(prefix).Handler(netpkg.MakeHTTPGzipHandler(http.StripPrefix(prefix, http.FileServer(fs)))).Methods("GET", "HEAD")
	sp.s = &http.Server{
		Handler:           router,
		ReadHeaderTimeout: 60 * time.Second,
	}
	go func() {
		_ = sp.s.Serve(listener)
	}()
	return sp, nil
}

func (sp *StaticFilePlugin) Handle(_ context.Context, connInfo *ConnectionInfo) {
	wrapConn := netpkg.WrapReadWriteCloserToConn(connInfo.Conn, connInfo.UnderlyingConn)
	_ = sp.l.PutConn(wrapConn)
}

func (sp *StaticFilePlugin) Name() string {
	return v1.PluginStaticFile
}

func (sp *StaticFilePlugin) Close() error {
	sp.s.Close()
	sp.l.Close()
	return nil
}
