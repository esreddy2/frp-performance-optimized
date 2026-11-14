package net

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

var ErrWebsocketListenerClosed = errors.New("websocket listener closed")

const (
	FrpWebsocketPath = "/~!frp"
)

type WebsocketListener struct {
	ln       net.Listener
	acceptCh chan net.Conn
	done     chan struct{}

	server *http.Server

	closeOnce sync.Once

	mu       sync.Mutex
	pending  map[net.Conn]func()
	serveErr error
}

// NewWebsocketListener to handle websocket connections
// ln: tcp listener for websocket connections
func NewWebsocketListener(ln net.Listener) (wl *WebsocketListener) {
	wl = &WebsocketListener{
		ln:       ln,
		acceptCh: make(chan net.Conn),
		done:     make(chan struct{}),
		pending:  make(map[net.Conn]func()),
	}

	muxer := http.NewServeMux()
	muxer.Handle(FrpWebsocketPath, websocket.Handler(func(c *websocket.Conn) {
		// The tunnel payload is a raw byte stream (yamux), not UTF-8 text.
		// Send it as binary frames; otherwise RFC 6455-compliant intermediaries
		// (e.g. API gateways/reverse proxies) UTF-8-validate the default text
		// frames and close the connection on invalid bytes.
		c.PayloadType = websocket.BinaryFrame
		notifyCh := make(chan struct{})
		var closeNotifyOnce sync.Once
		closeNotify := func() {
			closeNotifyOnce.Do(func() {
				defer func() { _ = recover() }()
				close(notifyCh)
			})
		}
		conn := WrapCloseNotifyConn(c, func(_ error) {
			defer func() { _ = recover() }()
			closeNotify()
		})
		select {
		case <-wl.done:
			conn.Close()
			return
		default:
		}
		wl.mu.Lock()
		wl.pending[conn] = closeNotify
		wl.mu.Unlock()

		select {
		case <-wl.done:
			wl.mu.Lock()
			delete(wl.pending, conn)
			wl.mu.Unlock()
			closeNotify()
			conn.Close()
			return
		case wl.acceptCh <- conn:
		}

		<-notifyCh
		wl.mu.Lock()
		delete(wl.pending, conn)
		wl.mu.Unlock()
	}))

	wl.server = &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           muxer,
		ReadHeaderTimeout: 60 * time.Second,
	}

	go func() {
		if err := wl.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			wl.mu.Lock()
			wl.serveErr = err
			wl.mu.Unlock()
		}
	}()
	return
}

func (p *WebsocketListener) Accept() (net.Conn, error) {
	select {
	case <-p.done:
		return nil, ErrWebsocketListenerClosed
	case c := <-p.acceptCh:
		p.mu.Lock()
		delete(p.pending, c)
		p.mu.Unlock()
		select {
		case <-p.done:
			c.Close()
			return nil, ErrWebsocketListenerClosed
		default:
		}
		return c, nil
	}
}

func (p *WebsocketListener) Close() error {
	p.closeOnce.Do(func() { close(p.done) })
	err := p.server.Close()

	p.mu.Lock()
	type pendingItem struct {
		conn  net.Conn
		close func()
	}
	items := make([]pendingItem, 0, len(p.pending))
	for c, closeFn := range p.pending {
		items = append(items, pendingItem{conn: c, close: closeFn})
		delete(p.pending, c)
	}
	se := p.serveErr
	p.mu.Unlock()

	for _, item := range items {
		item.close()
		item.conn.Close()
	}

drain:
	for {
		select {
		case c := <-p.acceptCh:
			c.Close()
		default:
			break drain
		}
	}

	if err == nil && se != nil && !errors.Is(se, http.ErrServerClosed) {
		err = se
	}
	return err
}

func (p *WebsocketListener) Addr() net.Addr {
	return p.ln.Addr()
}
