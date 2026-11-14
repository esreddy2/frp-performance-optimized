package features

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"

	"github.com/fatedier/frp/pkg/naming"
	"github.com/fatedier/frp/pkg/proto/udp"
	"github.com/fatedier/frp/test/e2e/framework"
	"github.com/fatedier/frp/test/e2e/framework/consts"
	"github.com/fatedier/frp/test/e2e/pkg/port"
)

var _ = ginkgo.Describe("[Feature: QUIC Datagram]", func() {
	f := framework.NewDefaultFramework()

	ginkgo.It("relays a udp proxy over quic datagrams", func() {
		serverConf := consts.DefaultServerConfig
		serverConf += fmt.Sprintf(`
		quicBindPort = {{ .%s }}
		transport.quic.enableDatagrams = true
		`, consts.PortServerName)

		remotePortName := port.GenName("QUICDatagramRemotePort")
		clientConf := consts.DefaultClientConfig
		clientConf += fmt.Sprintf(`
		transport.protocol = "quic"
		transport.quic.enableDatagrams = true

		[[proxies]]
		name = "udp-datagram"
		type = "udp"
		localPort = {{ .%s }}
		remotePort = {{ .%s }}
		quicDatagrams = true
		`, framework.UDPEchoServerPort, remotePortName)

		serverProcess, clientProcesses := f.RunProcesses(serverConf, []string{clientConf})

		// A silent fallback to the reliable work-connection stream would
		// still pass the echo check below, so require both ends to report
		// that the datagram lane is actually in use.
		framework.ExpectNoError(serverProcess.WaitForOutput("udp proxy relaying via quic datagrams", 1, 10*time.Second))
		framework.ExpectNoError(clientProcesses[0].WaitForOutput("udp proxy relaying via quic datagrams", 1, 10*time.Second))

		// QUIC datagrams are unreliable and unordered, so retry the echo
		// instead of expecting the first packet to arrive.
		req := framework.NewRequest().UDP().Port(f.PortByName(remotePortName))
		gomega.Eventually(func(g gomega.Gomega) {
			resp, err := req.Do()
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(string(resp.Content)).To(gomega.Equal(consts.TestString))
		}, 10*time.Second, 200*time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("relays a user-prefixed udp proxy at the max datagram identifier length", func() {
		serverConf := consts.DefaultServerConfig
		serverConf += fmt.Sprintf(`
		quicBindPort = {{ .%s }}
		transport.quic.enableDatagrams = true
		`, consts.PortServerName)

		user := "dg-user"
		// Wire-level name is "<user>.<proxyName>". At exactly MaxDatagramIdentifierLength,
		// the datagram lane must still be enabled.
		proxyName := strings.Repeat("n", naming.MaxDatagramIdentifierLength-len(user)-1)
		remotePortName := port.GenName("QUICDatagramMaxNameRemotePort")

		clientConf := consts.DefaultClientConfig
		clientConf += fmt.Sprintf(`
		transport.protocol = "quic"
		transport.quic.enableDatagrams = true
		user = "%s"

		[[proxies]]
		name = "%s"
		type = "udp"
		localPort = {{ .%s }}
		remotePort = {{ .%s }}
		quicDatagrams = true
		`, user, proxyName, framework.UDPEchoServerPort, remotePortName)

		serverProcess, clientProcesses := f.RunProcesses(serverConf, []string{clientConf})
		framework.ExpectNoError(serverProcess.WaitForOutput("udp proxy relaying via quic datagrams", 1, 10*time.Second))
		framework.ExpectNoError(clientProcesses[0].WaitForOutput("udp proxy relaying via quic datagrams", 1, 10*time.Second))

		req := framework.NewRequest().UDP().Port(f.PortByName(remotePortName))
		gomega.Eventually(func(g gomega.Gomega) {
			resp, err := req.Do()
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(string(resp.Content)).To(gomega.Equal(consts.TestString))
		}, 10*time.Second, 200*time.Millisecond).Should(gomega.Succeed())
	})

	ginkgo.It("handles oversized udp payloads via stream fallback or strict drop", func() {
		serverConf := consts.DefaultServerConfig
		serverConf += fmt.Sprintf(`
		quicBindPort = {{ .%s }}
		transport.quic.enableDatagrams = true
		`, consts.PortServerName)

		fallbackPortName := port.GenName("QUICDatagramFallbackRemotePort")
		strictPortName := port.GenName("QUICDatagramStrictRemotePort")

		clientConf := consts.DefaultClientConfig
		clientConf += fmt.Sprintf(`
		transport.protocol = "quic"
		transport.quic.enableDatagrams = true

		[[proxies]]
		name = "udp-datagram-fallback"
		type = "udp"
		localPort = {{ .%s }}
		remotePort = {{ .%s }}
		quicDatagrams = true

		[[proxies]]
		name = "udp-datagram-strict"
		type = "udp"
		localPort = {{ .%s }}
		remotePort = {{ .%s }}
		quicDatagrams = true
		quicDatagramStrict = true
		`, framework.UDPEchoServerPort, fallbackPortName, framework.UDPEchoServerPort, strictPortName)

		serverProcess, clientProcesses := f.RunProcesses(serverConf, []string{clientConf})
		framework.ExpectNoError(serverProcess.WaitForOutput("udp proxy relaying via quic datagrams", 2, 10*time.Second))
		framework.ExpectNoError(clientProcesses[0].WaitForOutput("udp proxy relaying via quic datagrams", 2, 10*time.Second))

		oversized := bytes.Repeat([]byte("a"), udp.DatagramFrameBudget+1)

		// Default mode: oversized payload falls back to the reliable work-connection stream.
		fallbackReq := framework.NewRequest().UDP().Port(f.PortByName(fallbackPortName)).Body(oversized)
		gomega.Eventually(func(g gomega.Gomega) {
			resp, err := fallbackReq.Do()
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(resp.Content).To(gomega.Equal(oversized))
		}, 10*time.Second, 200*time.Millisecond).Should(gomega.Succeed())

		// Strict mode: normal payload succeeds over datagrams, while oversized payload is dropped.
		strictSmallReq := framework.NewRequest().UDP().Port(f.PortByName(strictPortName))
		gomega.Eventually(func(g gomega.Gomega) {
			resp, err := strictSmallReq.Do()
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(string(resp.Content)).To(gomega.Equal(consts.TestString))
		}, 10*time.Second, 200*time.Millisecond).Should(gomega.Succeed())

		_, err := framework.NewRequest().UDP().Port(f.PortByName(strictPortName)).
			Timeout(500 * time.Millisecond).
			Body(oversized).
			Do()
		gomega.Expect(err).To(gomega.HaveOccurred(), "oversized udp payload should be dropped when quicDatagramStrict is true")
	})

	// The datagram lane identifies a proxy by its wire-level name, and the
	// identifier field of a datagram frame holds a single length byte. The
	// wire-level name is the proxy name with the user prefix, so the limit
	// applies to the effective name on the wire.
	ginkgo.It("rejects a udp proxy whose wire name does not fit the datagram identifier", func() {
		serverConf := consts.DefaultServerConfig
		serverConf += fmt.Sprintf(`
		quicBindPort = {{ .%s }}
		transport.quic.enableDatagrams = true
		`, consts.PortServerName)

		user := "dg-user"
		// The wire-level name is the user, a dot and the proxy name.
		proxyName := strings.Repeat("n", naming.MaxDatagramIdentifierLength-len(user))

		clientConf := consts.DefaultClientConfig
		clientConf += fmt.Sprintf(`
		transport.protocol = "quic"
		transport.quic.enableDatagrams = true
		user = "%s"

		[[proxies]]
		name = "%s"
		type = "udp"
		localPort = {{ .%s }}
		remotePort = {{ .%s }}
		quicDatagrams = true
		`, user, proxyName, framework.UDPEchoServerPort, port.GenName("QUICDatagramLongNameRemotePort"))

		_, clientProcesses := f.RunProcesses(serverConf, []string{clientConf})

		// The client has to report the config error instead of silently
		// relaying the proxy over the reliable work-connection stream.
		framework.ExpectNoError(clientProcesses[0].WaitForOutput(
			"the quic datagram lane needs a wire-level proxy name", 1, 10*time.Second))
	})
})
