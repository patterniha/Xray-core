package grpc_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/testing/mocks"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc"
)

func TestConnectionKeepsTheInstanceOfItsDial(t *testing.T) {
	// gRPC dials the connection itself, in a context of its own. The connection still resolves the server
	// with the DNS client and goes through the dialerProxy of the instance that dialed it, which the
	// context of the dial carries, and not with those of the instance created last (InitSystemDialer).
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	type instance struct {
		dns       *mocks.DNSClient
		outbounds *mocks.OutboundManager
		resolved  atomic.Bool
		proxied   atomic.Bool
	}
	newInstance := func() *instance {
		i := &instance{dns: mocks.NewDNSClient(mockCtl), outbounds: mocks.NewOutboundManager(mockCtl)}
		i.dns.EXPECT().LookupIP("grpc.example", gomock.Any()).DoAndReturn(func(string, dns.IPOption) ([]net.IP, uint32, error) {
			i.resolved.Store(true)
			return []net.IP{net.LocalHostIP.IP()}, 0, nil
		}).AnyTimes()
		// without a handler for it, the dial ends there
		i.outbounds.EXPECT().GetHandler("hop").DoAndReturn(func(string) outbound.Handler {
			i.proxied.Store(true)
			return nil
		}).AnyTimes()
		return i
	}
	own, last := newInstance(), newInstance()
	internet.InitSystemDialer(last.dns, last.outbounds)
	defer internet.InitSystemDialer(nil, nil)

	streamSettings, err := internet.ToMemoryStreamConfig(&internet.StreamConfig{
		ProtocolName: "grpc",
		TransportSettings: []*internet.TransportConfig{{
			ProtocolName: "grpc",
			Settings:     serial.ToTypedMessage(&grpc.Config{ServiceName: "test"}),
		}},
		SocketSettings: &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_USE_IP, DialerProxy: "hop"},
	})
	common.Must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = internet.ContextWithDNSClient(internet.ContextWithOutboundManager(ctx, own.outbounds), own.dns)
	if conn, err := internet.Dial(ctx, net.TCPDestination(net.DomainAddress("grpc.example"), 443), streamSettings); err == nil {
		conn.Close()
		t.Fatal("the connection was dialed without its dialerProxy")
	}

	if !own.resolved.Load() || !own.proxied.Load() {
		t.Error("the connection did not resolve the server and go through the dialerProxy with the instance that dialed it")
	}
	if last.resolved.Load() || last.proxied.Load() {
		t.Error("the connection resolved the server or went through the dialerProxy with the instance created last")
	}
}
