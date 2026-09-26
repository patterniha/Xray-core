package internet_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/mocks"
	"github.com/xtls/xray-core/testing/servers/tcp"
	. "github.com/xtls/xray-core/transport/internet"
)

func TestDetachedContext(t *testing.T) {
	// Work that outlives a dial keeps the outbound manager and the DNS client of its instance, and nothing
	// else of the context of the dial: neither its cancellation nor its other values.
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()
	om := mocks.NewOutboundManager(mockCtl)
	dc := mocks.NewDNSClient(mockCtl)

	type key struct{}
	dialCtx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "dial"))
	dialCtx = ContextWithDNSClient(ContextWithOutboundManager(dialCtx, om), dc)
	detached := DetachedContext(dialCtx)
	cancel()

	if detached.Err() != nil {
		t.Error("the detached context ended with the dial")
	}
	if OutboundManagerFromContext(detached) != om {
		t.Error("the detached context lost the outbound manager")
	}
	if DNSClientFromContext(detached) != dc {
		t.Error("the detached context lost the DNS client")
	}
	if detached.Value(key{}) != nil {
		t.Error("the detached context kept another value of the dial")
	}
	if bare := DetachedContext(context.Background()); OutboundManagerFromContext(bare) != nil || DNSClientFromContext(bare) != nil {
		t.Error("a context without features got some")
	}
}

func TestDialWithLocalAddr(t *testing.T) {
	server := &tcp.Server{}
	dest, err := server.Start()
	common.Must(err)
	defer server.Close()

	conn, err := DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, dest.Port), nil)
	common.Must(err)
	if r := cmp.Diff(conn.RemoteAddr().String(), "127.0.0.1:"+dest.Port.String()); r != "" {
		t.Error(r)
	}
	conn.Close()
}
