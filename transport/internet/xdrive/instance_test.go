package xdrive

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// hopOutbound is an outbound tagged "hop" that carries TCP straight to its destination, and counts the
// connections it carries.
type hopOutbound struct {
	carried atomic.Int32
}

func (o *hopOutbound) Start() error                         { return nil }
func (o *hopOutbound) Close() error                         { return nil }
func (o *hopOutbound) Tag() string                          { return "hop" }
func (o *hopOutbound) SenderSettings() *serial.TypedMessage { return nil }
func (o *hopOutbound) ProxySettings() *serial.TypedMessage  { return nil }

func (o *hopOutbound) Dispatch(ctx context.Context, link *transport.Link) {
	o.carried.Add(1)
	outbounds := session.OutboundsFromContext(ctx)
	conn, err := internet.DialSystem(context.Background(), outbounds[len(outbounds)-1].Target, nil)
	if err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return
	}
	go func() {
		buf.Copy(link.Reader, buf.NewWriter(conn))
		conn.Close()
	}()
	buf.Copy(buf.NewReader(conn), link.Writer)
	common.Close(link.Writer)
}

// hopOutbounds is the outbound manager of an instance whose only outbound is hop.
type hopOutbounds struct {
	hop *hopOutbound
}

func (m *hopOutbounds) Type() interface{} { return outbound.ManagerType() }
func (m *hopOutbounds) Start() error      { return nil }
func (m *hopOutbounds) Close() error      { return nil }

func (m *hopOutbounds) GetHandler(tag string) outbound.Handler {
	if tag == m.hop.Tag() {
		return m.hop
	}
	return nil
}

func (m *hopOutbounds) GetDefaultHandler() outbound.Handler { return m.hop }

func (m *hopOutbounds) AddHandler(ctx context.Context, handler outbound.Handler) error { return nil }

func (m *hopOutbounds) RemoveHandler(ctx context.Context, tag string) error { return nil }

func (m *hopOutbounds) ListHandlers(ctx context.Context) []outbound.Handler {
	return []outbound.Handler{m.hop}
}

func TestConnectionKeepsTheDialerProxyOfItsDial(t *testing.T) {
	// A connection outlives its dial and keeps reaching the storage, each time through the dialerProxy of
	// the instance that dialed it, whose outbound manager the context of the dial carries, and not through
	// the one of the instance created last (InitSystemDialer), which the listener here goes through. The
	// store closes every connection, so that each request dials again.
	resetSharedStorage()
	t.Cleanup(resetSharedStorage)
	store := newFakeStore(t)
	store.server.Config.SetKeepAlivesEnabled(false)
	settings := templateSettings(store, map[string]interface{}{"type": "none"}, nil)
	settings.SocketSettings = &internet.SocketConfig{DialerProxy: "hop"}

	own, last := &hopOutbound{}, &hopOutbound{}
	internet.InitSystemDialer(nil, &hopOutbounds{hop: last})
	t.Cleanup(func() { internet.InitSystemDialer(nil, nil) })

	accepted := make(chan stat.Connection, 1)
	listener, err := Serve(context.Background(), net.LocalHostIP, net.Port(0), settings, func(conn stat.Connection) {
		accepted <- conn
	})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	defer listener.Close()

	ctx := internet.ContextWithOutboundManager(context.Background(), &hopOutbounds{hop: own})
	client, err := Dial(ctx, net.Destination{}, settings)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
	var server stat.Connection
	select {
	case server = <-accepted:
	case <-time.After(testPatience):
		t.Fatal("listener did not accept the session")
	}
	defer server.Close()
	carriedByDial := own.carried.Load()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectRead(t, server, "ping")
	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	expectRead(t, client, "pong")

	if own.carried.Load() <= carriedByDial {
		t.Errorf("after its dial, the connection reached the storage through the hop of its own instance %d times", own.carried.Load()-carriedByDial)
	}
}
