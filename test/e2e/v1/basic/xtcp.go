package basic

import (
	"fmt"
	"time"

	"github.com/onsi/ginkgo/v2"

	"github.com/fatedier/frp/test/e2e/framework"
	"github.com/fatedier/frp/test/e2e/framework/consts"
	"github.com/fatedier/frp/test/e2e/pkg/port"
	"github.com/fatedier/frp/test/e2e/pkg/request"
)

var _ = ginkgo.Describe("[Feature: XTCP]", func() {
	f := framework.NewDefaultFramework()

	ginkgo.It("Fallback To STCP", func() {
		serverConf := consts.DefaultServerConfig
		clientConf := consts.DefaultClientConfig

		fallbackPortName := port.GenName("FALLBACK")
		bindPortName := port.GenName("XTCP")
		clientConf += fmt.Sprintf(`
			[[proxies]]
			name = "foo"
			type = "stcp"
			secretKey = "abcdefg"
			localPort = {{ .%s }}

			[[visitors]]
			name = "foo-visitor"
			type = "stcp"
			serverName = "foo"
			secretKey = "abcdefg"
			bindPort = {{ .%s }}

			[[visitors]]
			name = "bar-visitor"
			type = "xtcp"
			serverName = "bar"
			secretKey = "abcdefg"
			bindPort = {{ .%s }}
			keepTunnelOpen = true
			fallbackTo = "foo-visitor"
			fallbackTimeoutMs = 200
			`, framework.TCPEchoServerPort, fallbackPortName, bindPortName)

		f.RunProcesses(serverConf, []string{clientConf})
		framework.NewRequestExpect(f).
			RequestModify(func(r *request.Request) {
				r.Timeout(time.Second)
			}).
			PortName(bindPortName).
			Ensure()
	})
})
