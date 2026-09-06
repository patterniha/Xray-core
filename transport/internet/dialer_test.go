package internet_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	. "github.com/xtls/xray-core/transport/internet"
)

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

func TestDialWithDialMode(t *testing.T) {
	server := &tcp.Server{}
	dest, err := server.Start()
	common.Must(err)
	defer server.Close()

	// an empty dialMode runs the default dialing code
	conn, err := DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, dest.Port), &SocketConfig{DialMode: ""})
	common.Must(err)
	if r := cmp.Diff(conn.RemoteAddr().String(), "127.0.0.1:"+dest.Port.String()); r != "" {
		t.Error(r)
	}
	conn.Close()

	// a dialMode that has no code behind it yet is rejected
	if _, err := DialSystem(context.Background(), net.TCPDestination(net.LocalHostIP, dest.Port), &SocketConfig{DialMode: "unknown"}); err == nil {
		t.Fatal("expected an error for a dialMode without code")
	}
}
