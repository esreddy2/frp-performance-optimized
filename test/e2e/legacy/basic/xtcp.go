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
		serverConf := consts.LegacyDefaultServerConfig
		clientConf := consts.LegacyDefaultClientConfig

		fallbackPortName := port.GenName("FALLBACK")
		bindPortName := port.GenName("XTCP")
		clientConf += fmt.Sprintf(`
			[foo]
			type = stcp
			sk = abcdefg
			local_port = {{ .%s }}

			[foo-visitor]
			type = stcp
			role = visitor
			server_name = foo
			sk = abcdefg
			bind_port = {{ .%s }}

			[bar-visitor]
			type = xtcp
			role = visitor
			server_name = bar
			sk = abcdefg
			bind_port = {{ .%s }}
			keep_tunnel_open = true
			fallback_to = foo-visitor
			fallback_timeout_ms = 200
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
