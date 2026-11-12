package internet

import (
	"context"
	"reflect"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

// MemoryStreamConfig is a parsed form of StreamConfig. It is used to reduce the number of Protobuf parses.
type MemoryStreamConfig struct {
	Destination      *net.Destination
	ProtocolName     string
	ProtocolSettings interface{}
	SecurityType     string
	SecuritySettings interface{}
	FinalMask        *finalmask.FinalMask
	QuicParams       *QuicParams
	SocketSettings   *SocketConfig
	DownloadSettings *MemoryStreamConfig
}

// ToMemoryStreamConfig converts a StreamConfig to MemoryStreamConfig. It returns a default non-nil MemoryStreamConfig for nil input.
func ToMemoryStreamConfig(s *StreamConfig) (*MemoryStreamConfig, error) {
	ets, err := s.GetEffectiveTransportSettings()
	if err != nil {
		return nil, err
	}

	mss := &MemoryStreamConfig{
		ProtocolName:     s.GetEffectiveProtocol(),
		ProtocolSettings: ets,
	}

	if s != nil {
		if s.Address != nil {
			mss.Destination = &net.Destination{
				Address: s.Address.AsAddress(),
				Port:    net.Port(s.Port),
				Network: net.Network_TCP,
			}
		}
		mss.SocketSettings = s.SocketSettings
	}

	if s != nil && s.HasSecuritySettings() {
		ess, err := s.GetEffectiveSecuritySettings()
		if err != nil {
			return nil, err
		}
		mss.SecurityType = s.SecurityType
		mss.SecuritySettings = ess
	}
	if s != nil && (len(s.Tcpmasks) != 0 || len(s.Udpmasks) != 0 ||
		len(s.Tcp4Masks) != 0 || len(s.Tcp6Masks) != 0 ||
		len(s.Udp4Masks) != 0 || len(s.Udp6Masks) != 0) {
		buildTCP := func(src []*serial.TypedMessage) []finalmask.TCPMask {
			var out []finalmask.TCPMask
			for i := range src {
				out = append(out, common.Must2(src[i].GetInstance()).(finalmask.TCPMask))
			}
			return out
		}
		buildUDP := func(src []*serial.TypedMessage) []finalmask.UDPMask {
			var out []finalmask.UDPMask
			for i := range src {
				out = append(out, common.Must2(src[i].GetInstance()).(finalmask.UDPMask))
			}
			return out
		}
		tcpMasks := buildTCP(s.Tcpmasks)
		udpMasks := buildUDP(s.Udpmasks)
		tcp4Masks := buildTCP(s.Tcp4Masks)
		tcp6Masks := buildTCP(s.Tcp6Masks)
		udp4Masks := buildUDP(s.Udp4Masks)
		udp6Masks := buildUDP(s.Udp6Masks)

		// Family lists are applied only after a dial-first (to learn the family),
		// so a dial-controlling mask (HandleDial, e.g. udphop/xicmp) has nothing
		// to dial there.
		hasHandleDial := func(m interface{}) bool {
			_, ok := m.(interface{ HandleDial() })
			return ok
		}
		for _, m := range tcp4Masks {
			if hasHandleDial(m) {
				return nil, errors.New(`finalmask: a dial-controlling mask can't be used in "tcp4"`)
			}
		}
		for _, m := range tcp6Masks {
			if hasHandleDial(m) {
				return nil, errors.New(`finalmask: a dial-controlling mask can't be used in "tcp6"`)
			}
		}
		for _, m := range udp4Masks {
			if hasHandleDial(m) {
				return nil, errors.New(`finalmask: a dial-controlling mask (e.g. udphop/xicmp) can't be used in "udp4"`)
			}
		}
		for _, m := range udp6Masks {
			if hasHandleDial(m) {
				return nil, errors.New(`finalmask: a dial-controlling mask (e.g. udphop/xicmp) can't be used in "udp6"`)
			}
		}

		dialTCP := func(ctx context.Context, dest net.Destination) (net.Conn, error) {
			return DialSystem(ctx, dest, mss.SocketSettings)
		}
		listen := func(ctx context.Context, addr net.Addr) (net.Listener, error) {
			return ListenSystem(ctx, addr, mss.SocketSettings)
		}
		dialUDP := func(ctx context.Context, dest net.Destination) (net.PacketConn, net.Addr, error) {
			conn, err := DialSystem(ctx, dest, mss.SocketSettings)
			if err != nil {
				return nil, nil, err
			}
			var newConn net.PacketConn
			var udpAddr net.Addr
			switch c := conn.(type) {
			case *net.PacketConnWrapper:
				newConn = c.PacketConn
				udpAddr = conn.RemoteAddr()
			case *cnc.Connection:
				newConn = &FakePacketConn{Conn: c}
				udpAddr = &net.UDPAddr{IP: []byte{0, 0, 0, 0}, Port: 0}
			default:
				panic(reflect.TypeOf(c))
			}
			return newConn, udpAddr, nil
		}
		listenPacket := func(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
			return ListenSystemPacket(ctx, addr, mss.SocketSettings)
		}
		mss.FinalMask = finalmask.NewFinalMask(tcpMasks, udpMasks, dialTCP, listen, dialUDP, listenPacket)
		mss.FinalMask.SetFamilyMasks(tcp4Masks, tcp6Masks, udp4Masks, udp6Masks)
	}

	if s != nil && s.QuicParams != nil {
		mss.QuicParams = s.QuicParams
	}

	return mss, nil
}
