package core_test

import (
	"context"
	"crypto/rand"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/protobuf/proto"
)

func xor(b []byte) []byte {
	r := make([]byte, len(b))
	for i, v := range b {
		r[i] = v ^ 'c'
	}
	return r
}

func xor2(b []byte) []byte {
	r := make([]byte, len(b))
	for i, v := range b {
		r[i] = v ^ 'd'
	}
	return r
}

func TestXrayDial(t *testing.T) {
	tcpServer := tcp.Server{
		MsgProcessor: xor,
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	cfgBytes, err := proto.Marshal(config)
	common.Must(err)

	server, err := core.StartInstance("protobuf", cfgBytes)
	common.Must(err)
	defer server.Close()

	conn, err := core.Dial(context.Background(), server, dest)
	common.Must(err)
	defer conn.Close()

	const size = 10240 * 1024
	payload := make([]byte, size)
	common.Must2(rand.Read(payload))

	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}

	receive := make([]byte, size)
	if _, err := io.ReadFull(conn, receive); err != nil {
		t.Fatal("failed to read all response: ", err)
	}

	if r := cmp.Diff(xor(receive), payload); r != "" {
		t.Error(r)
	}
}

func TestXrayDialerProxyOfEachInstance(t *testing.T) {
	// Two instances in one process, as when a client tests several configurations at once. The
	// dialerProxy of each has to resolve in its own outbounds, not in those of the one created last.
	serverA := tcp.Server{MsgProcessor: xor}
	destA, err := serverA.Start()
	common.Must(err)
	defer serverA.Close()
	serverB := tcp.Server{MsgProcessor: xor2}
	destB, err := serverB.Start()
	common.Must(err)
	defer serverB.Close()

	// start runs an instance whose default outbound dials through its outbound "hop", which goes to hopDest
	start := func(hopDest net.Destination) *core.Instance {
		allow := []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}
		config := &core.Config{
			App: []*serial.TypedMessage{
				serial.ToTypedMessage(&dispatcher.Config{}),
				serial.ToTypedMessage(&proxyman.InboundConfig{}),
				serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			},
			Outbound: []*core.OutboundHandlerConfig{
				{
					Tag: "proxy",
					SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
						StreamSettings: &internet.StreamConfig{
							SocketSettings: &internet.SocketConfig{DialerProxy: "hop"},
						},
					}),
					ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: allow}),
				},
				{
					Tag: "hop",
					ProxySettings: serial.ToTypedMessage(&freedom.Config{
						DestinationOverride: &freedom.DestinationOverride{
							Server: &protocol.ServerEndpoint{
								Address: net.NewIPOrDomain(hopDest.Address),
								Port:    uint32(hopDest.Port),
							},
						},
						FinalRules: allow,
					}),
				},
			},
		}
		cfgBytes, err := proto.Marshal(config)
		common.Must(err)
		server, err := core.StartInstance("protobuf", cfgBytes)
		common.Must(err)
		return server
	}

	instanceA := start(destA)
	defer instanceA.Close()
	instanceB := start(destB)
	defer instanceB.Close()

	for _, c := range []struct {
		name      string
		instance  *core.Instance
		processor func([]byte) []byte
	}{
		{"A", instanceA, xor},
		{"B", instanceB, xor2},
	} {
		conn, err := core.Dial(context.Background(), c.instance, destA)
		common.Must(err)

		payload := make([]byte, 1024)
		common.Must2(rand.Read(payload))
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		receive := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, receive); err != nil {
			t.Fatal("failed to read all response of instance ", c.name, ": ", err)
		}
		conn.Close()

		if r := cmp.Diff(c.processor(receive), payload); r != "" {
			t.Error("instance ", c.name, " did not dial through its own hop: ", r)
		}
	}
}

func TestXrayECHQueryThroughOwnInstance(t *testing.T) {
	// Two instances in one process, each with a TLS outbound whose ECH config query goes through its own
	// outbound "ech-out" (echSockopt.dialerProxy) to its own DNS server. A dial of the instance created
	// first has to query its own DNS server, not the one of the instance created last.
	target := tcp.Server{MsgProcessor: xor}
	targetDest, err := target.Start()
	common.Must(err)
	defer target.Close()

	// echDNSServer answers every ECH config query with an HTTPS record, and counts them
	echDNSServer := func(queries *atomic.Int32) *udp.Server {
		return &udp.Server{MsgProcessor: func(msg []byte) []byte {
			queries.Add(1)
			request := new(dns.Msg)
			if err := request.Unpack(msg); err != nil || len(request.Question) == 0 {
				return nil
			}
			response := new(dns.Msg)
			response.SetReply(request)
			response.Answer = append(response.Answer, &dns.HTTPS{SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   ".",
				Value:    []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: []byte{1, 2, 3, 4}}},
			}})
			packed, err := response.Pack()
			common.Must(err)
			return packed
		}}
	}
	var queriesA, queriesB atomic.Int32
	dnsServerA := echDNSServer(&queriesA)
	dnsA, err := dnsServerA.Start()
	common.Must(err)
	defer dnsServerA.Close()
	dnsServerB := echDNSServer(&queriesB)
	dnsB, err := dnsServerB.Start()
	common.Must(err)
	defer dnsServerB.Close()

	// start runs an instance whose default outbound queries its ECH config through "ech-out", which goes to dnsDest
	start := func(dnsDest net.Destination) *core.Instance {
		allow := []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}}
		config := &core.Config{
			App: []*serial.TypedMessage{
				serial.ToTypedMessage(&dispatcher.Config{}),
				serial.ToTypedMessage(&proxyman.InboundConfig{}),
				serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			},
			Outbound: []*core.OutboundHandlerConfig{
				{
					Tag: "proxy",
					SenderSettings: serial.ToTypedMessage(&proxyman.SenderConfig{
						StreamSettings: &internet.StreamConfig{
							SecurityType: serial.GetMessageType(&tls.Config{}),
							SecuritySettings: []*serial.TypedMessage{
								serial.ToTypedMessage(&tls.Config{
									ServerName:        "ech.example",
									EchConfigList:     "ech.example+udp://192.0.2.1",
									EchSocketSettings: &internet.SocketConfig{DialerProxy: "ech-out"},
								}),
							},
						},
					}),
					ProxySettings: serial.ToTypedMessage(&freedom.Config{FinalRules: allow}),
				},
				{
					Tag: "ech-out",
					ProxySettings: serial.ToTypedMessage(&freedom.Config{
						DestinationOverride: &freedom.DestinationOverride{
							Server: &protocol.ServerEndpoint{
								Address: net.NewIPOrDomain(dnsDest.Address),
								Port:    uint32(dnsDest.Port),
							},
						},
						FinalRules: allow,
					}),
				},
			},
		}
		cfgBytes, err := proto.Marshal(config)
		common.Must(err)
		server, err := core.StartInstance("protobuf", cfgBytes)
		common.Must(err)
		return server
	}

	instanceA := start(dnsA)
	defer instanceA.Close()
	instanceB := start(dnsB)
	defer instanceB.Close()

	// the TLS handshake with the plain TCP server fails once the ECH config has been queried
	conn, err := core.Dial(context.Background(), instanceA, targetDest)
	common.Must(err)
	defer conn.Close()
	for deadline := time.Now().Add(5 * time.Second); queriesA.Load()+queriesB.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}

	if queriesA.Load() == 0 || queriesB.Load() != 0 {
		t.Error("the ECH config query of instance A reached its own DNS server ", queriesA.Load(),
			" times and the one of instance B ", queriesB.Load(), " times")
	}
}

func TestXrayDNSOfEachInstance(t *testing.T) {
	// Two instances in one process, whose DNS resolves one domain to different addresses. A domain strategy
	// of the instance created first has to resolve with its own DNS, not with the one of the instance
	// created last, and so does the final rule of its freedom, which blocks the address of the other one.
	// Nothing listens on that address or connects to it: macOS has no 127.0.0.2 by default.
	server := tcp.Server{MsgProcessor: xor}
	dest, err := server.Start()
	common.Must(err)
	defer server.Close()
	target := net.TCPDestination(net.DomainAddress("target.example"), dest.Port)
	otherIP := net.ParseAddress("127.0.0.2")

	for _, strategy := range []struct {
		name   string
		sender *proxyman.SenderConfig
	}{
		{"sockopt domainStrategy", &proxyman.SenderConfig{
			StreamSettings: &internet.StreamConfig{
				SocketSettings: &internet.SocketConfig{DomainStrategy: internet.DomainStrategy_USE_IP4},
			},
		}},
		{"targetStrategy", &proxyman.SenderConfig{TargetStrategy: internet.DomainStrategy_USE_IP4}},
	} {
		// start runs an instance whose DNS resolves target to hostIP, and whose freedom blocks blockedIP
		start := func(hostIP, blockedIP net.Address) *core.Instance {
			config := &core.Config{
				App: []*serial.TypedMessage{
					serial.ToTypedMessage(&appdns.Config{
						StaticHosts: []*appdns.Config_HostMapping{{
							Domain: &geodata.DomainRule{Value: &geodata.DomainRule_Custom{
								Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: target.Address.Domain()},
							}},
							Ip: [][]byte{hostIP.IP()},
						}},
					}),
					serial.ToTypedMessage(&dispatcher.Config{}),
					serial.ToTypedMessage(&proxyman.InboundConfig{}),
					serial.ToTypedMessage(&proxyman.OutboundConfig{}),
				},
				Outbound: []*core.OutboundHandlerConfig{{
					SenderSettings: serial.ToTypedMessage(strategy.sender),
					ProxySettings: serial.ToTypedMessage(&freedom.Config{
						FinalRules: []*freedom.FinalRuleConfig{
							{
								Action: freedom.RuleAction_Block,
								Ip: []*geodata.IPRule{{Value: &geodata.IPRule_Custom{
									Custom: &geodata.CIDRRule{Cidr: &geodata.CIDR{Ip: blockedIP.IP(), Prefix: 32}},
								}}},
							},
							{Action: freedom.RuleAction_Allow},
						},
					}),
				}},
			}
			cfgBytes, err := proto.Marshal(config)
			common.Must(err)
			server, err := core.StartInstance("protobuf", cfgBytes)
			common.Must(err)
			return server
		}

		instanceA := start(dest.Address, otherIP)
		instanceB := start(otherIP, dest.Address)

		conn, err := core.Dial(context.Background(), instanceA, target)
		common.Must(err)

		payload := make([]byte, 1024)
		common.Must2(rand.Read(payload))
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		receive := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, receive); err != nil {
			t.Fatal("instance A did not resolve with its own DNS for ", strategy.name, ": ", err)
		}
		conn.Close()

		if r := cmp.Diff(xor(receive), payload); r != "" {
			t.Error(r)
		}

		instanceA.Close()
		instanceB.Close()
	}
}

func TestXrayDialUDPConn(t *testing.T) {
	udpServer := udp.Server{
		MsgProcessor: xor,
	}
	dest, err := udpServer.Start()
	common.Must(err)
	defer udpServer.Close()

	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	cfgBytes, err := proto.Marshal(config)
	common.Must(err)

	server, err := core.StartInstance("protobuf", cfgBytes)
	common.Must(err)
	defer server.Close()

	conn, err := core.Dial(context.Background(), server, dest)
	common.Must(err)
	defer conn.Close()

	const size = 1024
	payload := make([]byte, size)
	common.Must2(rand.Read(payload))

	for i := 0; i < 2; i++ {
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
	}

	time.Sleep(time.Millisecond * 500)

	receive := make([]byte, size*2)
	for i := 0; i < 2; i++ {
		n, err := conn.Read(receive)
		if err != nil {
			t.Fatal("expect no error, but got ", err)
		}
		if n != size {
			t.Fatal("expect read size ", size, " but got ", n)
		}

		if r := cmp.Diff(xor(receive[:n]), payload); r != "" {
			t.Fatal(r)
		}
	}
}

func TestXrayDialUDP(t *testing.T) {
	udpServer1 := udp.Server{
		MsgProcessor: xor,
	}
	dest1, err := udpServer1.Start()
	common.Must(err)
	defer udpServer1.Close()

	udpServer2 := udp.Server{
		MsgProcessor: xor2,
	}
	dest2, err := udpServer2.Start()
	common.Must(err)
	defer udpServer2.Close()

	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{
				ProxySettings: serial.ToTypedMessage(&freedom.Config{
					FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
				}),
			},
		},
	}

	cfgBytes, err := proto.Marshal(config)
	common.Must(err)

	server, err := core.StartInstance("protobuf", cfgBytes)
	common.Must(err)
	defer server.Close()

	conn, err := core.DialUDP(context.Background(), server)
	common.Must(err)
	defer conn.Close()

	const size = 1024
	{
		payload := make([]byte, size)
		common.Must2(rand.Read(payload))

		if _, err := conn.WriteTo(payload, &net.UDPAddr{
			IP:   dest1.Address.IP(),
			Port: int(dest1.Port),
		}); err != nil {
			t.Fatal(err)
		}

		receive := make([]byte, size)
		if _, _, err := conn.ReadFrom(receive); err != nil {
			t.Fatal(err)
		}

		if r := cmp.Diff(xor(receive), payload); r != "" {
			t.Error(r)
		}
	}

	{
		payload := make([]byte, size)
		common.Must2(rand.Read(payload))

		if _, err := conn.WriteTo(payload, &net.UDPAddr{
			IP:   dest2.Address.IP(),
			Port: int(dest2.Port),
		}); err != nil {
			t.Fatal(err)
		}

		receive := make([]byte, size)
		if _, _, err := conn.ReadFrom(receive); err != nil {
			t.Fatal(err)
		}

		if r := cmp.Diff(xor2(receive), payload); r != "" {
			t.Error(r)
		}
	}
}
