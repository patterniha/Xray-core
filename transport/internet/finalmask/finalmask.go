package finalmask

import (
	"context"
	"fmt"
	"slices"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

type Dialer struct {
	DialTCP func(net.Destination) (net.Conn, error)
	DialUDP func(net.Destination) (net.Conn, error)
}

type ListenConfig struct {
	Listen       func(net.Addr) (net.Listener, error)
	ListenPacket func(net.Addr) (net.PacketConn, error)
}

type TCPMask interface {
	WrapConnClient(net.Conn, *net.Destination, *Dialer) (net.Conn, error)
	WrapConnServer(net.Conn) (net.Conn, error)
	// Listen(net.Listener) (net.Listener, error)
}

type UDPMask interface {
	WrapPacketConnClient(net.PacketConn, *net.Destination, *Dialer) (net.PacketConn, error)
	WrapPacketConnServer(net.PacketConn, net.Addr, *ListenConfig) (net.PacketConn, error)
}

type FinalMask struct {
	tcpMasks []TCPMask
	udpMasks []UDPMask
	// Family-specific outbound masks: used in place of tcpMasks/udpMasks when the
	// dialed connection's remote IP is of that family. Set via SetFamilyMasks, and
	// mutually exclusive with the generic list of the same protocol (enforced at
	// config build). Dial side only — the listen/accept path keeps the generic lists.
	tcp4Masks    []TCPMask
	tcp6Masks    []TCPMask
	udp4Masks    []UDPMask
	udp6Masks    []UDPMask
	dialTCP      func(context.Context, net.Destination) (net.Conn, error)
	listen       func(context.Context, net.Addr) (net.Listener, error)
	dialUDP      func(context.Context, net.Destination) (net.PacketConn, net.Addr, error)
	listenPacket func(context.Context, net.Addr) (net.PacketConn, error)
}

func NewFinalMask(tcpMasks []TCPMask, udpMasks []UDPMask, dialTCP func(context.Context, net.Destination) (net.Conn, error), listen func(context.Context, net.Addr) (net.Listener, error), dialUDP func(context.Context, net.Destination) (net.PacketConn, net.Addr, error), listenPacket func(context.Context, net.Addr) (net.PacketConn, error)) *FinalMask {
	slices.Reverse(tcpMasks)
	slices.Reverse(udpMasks)
	return &FinalMask{
		tcpMasks:     tcpMasks,
		udpMasks:     udpMasks,
		dialTCP:      dialTCP,
		dialUDP:      dialUDP,
		listen:       listen,
		listenPacket: listenPacket,
	}
}

// SetFamilyMasks sets the family-specific outbound mask lists. Like NewFinalMask
// it reverses each list so config order (first = outermost) becomes apply order.
// These must not contain dial-controlling (HandleDial) masks — the caller dials
// first to learn the family, so there is nothing for such a mask to dial.
func (fm *FinalMask) SetFamilyMasks(tcp4, tcp6 []TCPMask, udp4, udp6 []UDPMask) {
	slices.Reverse(tcp4)
	slices.Reverse(tcp6)
	slices.Reverse(udp4)
	slices.Reverse(udp6)
	fm.tcp4Masks = tcp4
	fm.tcp6Masks = tcp6
	fm.udp4Masks = udp4
	fm.udp6Masks = udp6
}

// addrIsIPv6 reports whether addr's IP is IPv6 (IPv4 and IPv4-mapped count as IPv4).
func addrIsIPv6(addr net.Addr) bool {
	var ip net.IP
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	case *net.IPAddr:
		ip = a.IP
	default:
		if addr == nil {
			return false
		}
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			host = addr.String()
		}
		ip = net.ParseIP(host)
	}
	return ip != nil && ip.To4() == nil
}

func (fm *FinalMask) DialTCP(ctx context.Context, dest net.Destination) (net.Conn, error) {
	if len(fm.tcp4Masks) > 0 || len(fm.tcp6Masks) > 0 {
		// Family-split: dial first, then apply the list for the remote IP family.
		// finalmask runs after the dial, so the real remote IP is known even when
		// dest is a domain. These lists carry no HandleDial masks (rejected at build).
		conn, err := fm.dialTCP(ctx, dest)
		if err != nil {
			return nil, err
		}
		masks := fm.tcp4Masks
		if conn != nil && addrIsIPv6(conn.RemoteAddr()) {
			masks = fm.tcp6Masks
		}
		return fm.wrapClientTCP(ctx, dest, conn, masks)
	}
	if len(fm.tcpMasks) == 0 {
		return fm.dialTCP(ctx, dest)
	}
	for i := range fm.tcpMasks {
		if i > 0 {
			if _, ok := fm.tcpMasks[i].(interface{ HandleDial() }); ok {
				return nil, fmt.Errorf("incorrect index: %d %T", i, fm.tcpMasks[i])
			}
		}
	}
	var conn net.Conn
	var err error
	if _, ok := fm.tcpMasks[0].(interface{ HandleDial() }); !ok {
		conn, err = fm.dialTCP(ctx, dest)
		if err != nil {
			return nil, err
		}
	}
	return fm.wrapClientTCP(ctx, dest, conn, fm.tcpMasks)
}

// wrapClientTCP applies masks (in slice order) over conn. conn may be nil when the
// first mask is a HandleDial mask that dials via the provided Dialer.
func (fm *FinalMask) wrapClientTCP(ctx context.Context, dest net.Destination, conn net.Conn, masks []TCPMask) (net.Conn, error) {
	dialer := &Dialer{
		DialTCP: func(dest net.Destination) (net.Conn, error) {
			return fm.dialTCP(ctx, dest)
		},
		DialUDP: func(dest net.Destination) (net.Conn, error) {
			conn, addr, err := fm.dialUDP(ctx, dest)
			if err != nil {
				return nil, err
			}
			return &net.PacketConnWrapper{PacketConn: conn, Dest: addr}, err
		},
	}
	var err error
	for i := range masks {
		var newConn net.Conn
		newConn, err = masks[i].WrapConnClient(conn, &dest, dialer)
		if err != nil {
			common.CloseIfExists(conn)
			return nil, err
		}
		conn = newConn
	}
	return conn, nil
}

func (fm *FinalMask) Listen(ctx context.Context, addr net.Addr) (net.Listener, error) {
	if len(fm.tcpMasks) == 0 {
		return fm.listen(ctx, addr)
	}
	off := 0
	listener, err := fm.listen(ctx, addr)
	if err != nil {
		return nil, err
	}
	for i := range fm.tcpMasks {
		if _, ok := fm.tcpMasks[i].(interface {
			Listen(net.Listener) (net.Listener, error)
		}); ok {
			if i-off == 0 {
				l, err := fm.tcpMasks[i].(interface {
					Listen(net.Listener) (net.Listener, error)
				}).Listen(listener)
				if err != nil {
					listener.Close()
					return nil, err
				}
				listener = l
			} else {
				l, err := fm.tcpMasks[i].(interface {
					Listen(net.Listener) (net.Listener, error)
				}).Listen(&TCPListener{Listener: listener, tcpMasks: fm.tcpMasks[off:i]})
				if err != nil {
					listener.Close()
					return nil, err
				}
				listener = l
			}
			off = i + 1
		}
	}
	if off < len(fm.tcpMasks) {
		return &TCPListener{Listener: listener, tcpMasks: fm.tcpMasks[off:]}, nil
	}
	return listener, nil
}

func (fm *FinalMask) DialUDP(ctx context.Context, dest net.Destination) (net.Conn, error) {
	if len(fm.udp4Masks) > 0 || len(fm.udp6Masks) > 0 {
		// Family-split: dial first, then apply the list for the remote IP family.
		// These lists carry no HandleDial masks (rejected at config build).
		conn, addr, err := fm.dialUDP(ctx, dest)
		if err != nil {
			return nil, err
		}
		masks := fm.udp4Masks
		if addrIsIPv6(addr) {
			masks = fm.udp6Masks
		}
		return fm.wrapClientUDP(ctx, dest, conn, addr, masks)
	}
	if len(fm.udpMasks) == 0 {
		conn, addr, err := fm.dialUDP(ctx, dest)
		if err != nil {
			return nil, err
		}
		return &net.PacketConnWrapper{PacketConn: conn, Dest: addr}, nil
	}
	for i := range fm.udpMasks {
		if i > 0 {
			if _, ok := fm.udpMasks[i].(interface{ HandleDial() }); ok {
				return nil, fmt.Errorf("incorrect index: %d %T", i, fm.udpMasks[i])
			}
		}
	}
	var conn net.PacketConn
	var addr net.Addr
	var err error
	if _, ok := fm.udpMasks[0].(interface{ HandleDial() }); !ok {
		conn, addr, err = fm.dialUDP(ctx, dest)
		if err != nil {
			return nil, err
		}
	}
	return fm.wrapClientUDP(ctx, dest, conn, addr, fm.udpMasks)
}

// wrapClientUDP applies masks over conn (a dialed packet conn, or nil when the
// first mask is a HandleDial mask that dials via the Dialer), threading header
// masks through headerManagerConn. addr is the resolved remote address, if known.
func (fm *FinalMask) wrapClientUDP(ctx context.Context, dest net.Destination, conn net.PacketConn, addr net.Addr, masks []UDPMask) (net.Conn, error) {
	dialer := &Dialer{
		DialTCP: func(dest net.Destination) (net.Conn, error) {
			return fm.dialTCP(ctx, dest)
		},
		DialUDP: func(dest net.Destination) (net.Conn, error) {
			conn, addr, err := fm.dialUDP(ctx, dest)
			if err != nil {
				return nil, err
			}
			return &net.PacketConnWrapper{PacketConn: conn, Dest: addr}, err
		},
	}
	var sizes []int
	var conns []net.PacketConn
	var err error
	for i := range masks {
		var newConn net.PacketConn
		if _, ok := masks[i].(interface{ HeaderConn() }); ok {
			newConn, err = masks[i].WrapPacketConnClient(nil, nil, nil)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			sizes = append(sizes, newConn.(interface{ Size() int }).Size())
			conns = append(conns, newConn)
		} else {
			if len(conns) > 0 {
				conn = &headerManagerConn{PacketConn: conn, sizes: sizes, conns: conns}
				sizes = nil
				conns = nil
			}
			newConn, err = masks[i].WrapPacketConnClient(conn, &dest, dialer)
			if err != nil {
				common.CloseIfExists(conn)
				return nil, err
			}
			conn = newConn
		}
	}
	if len(conns) > 0 {
		conn = &headerManagerConn{PacketConn: conn, sizes: sizes, conns: conns}
		sizes = nil
		conns = nil
	}
	if addr == nil {
		addr = &net.UDPAddr{IP: []byte{0, 0, 0, 0}}
	}
	return &net.PacketConnWrapper{PacketConn: conn, Dest: addr}, nil
}

func (fm *FinalMask) ListenPacket(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
	if len(fm.udpMasks) == 0 {
		return fm.listenPacket(ctx, addr)
	}
	for i := range fm.udpMasks {
		if i > 0 {
			if _, ok := fm.udpMasks[i].(interface{ HandleListen() }); ok {
				return nil, fmt.Errorf("incorrect index: %d %T", i, fm.udpMasks[i])
			}
		}
	}
	var conn net.PacketConn
	var err error
	if _, ok := fm.udpMasks[0].(interface{ HandleListen() }); !ok {
		conn, err = fm.listenPacket(ctx, addr)
		if err != nil {
			return nil, err
		}
	}
	lc := &ListenConfig{
		Listen:       func(addr net.Addr) (net.Listener, error) { return fm.listen(ctx, addr) },
		ListenPacket: func(addr net.Addr) (net.PacketConn, error) { return fm.listenPacket(ctx, addr) },
	}
	var sizes []int
	var conns []net.PacketConn
	for i := range fm.udpMasks {
		var newConn net.PacketConn
		if _, ok := fm.udpMasks[i].(interface{ HeaderConn() }); ok {
			newConn, err = fm.udpMasks[i].WrapPacketConnServer(nil, nil, nil)
			if err != nil {
				common.CloseIfExists(conn)
				return nil, err
			}
			sizes = append(sizes, newConn.(interface{ Size() int }).Size())
			conns = append(conns, newConn)
		} else {
			if len(conns) > 0 {
				conn = &headerManagerConn{PacketConn: conn, sizes: sizes, conns: conns}
				sizes = nil
				conns = nil
			}
			newConn, err = fm.udpMasks[i].WrapPacketConnServer(conn, addr, lc)
			if err != nil {
				common.CloseIfExists(conn)
				return nil, err
			}
			conn = newConn
		}
	}
	if len(conns) > 0 {
		conn = &headerManagerConn{PacketConn: conn, sizes: sizes, conns: conns}
		sizes = nil
		conns = nil
	}
	return conn, nil
}

const (
	UDPSize = 4096
)

type headerManagerConn struct {
	net.PacketConn

	sizes []int
	conns []net.PacketConn
}

func (c *headerManagerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	b := p
	if len(b) < UDPSize {
		buf := buf.New()
		buf.Resize(0, UDPSize)
		b = buf.Bytes()
		defer buf.Release()
	}

	for {
		n, addr, err = c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		buf := b[:n]

		sum := 0
		for _, size := range c.sizes {
			sum += size
		}

		if n < sum {
			errors.LogError(context.Background(), "[mask] drop packet from ", addr, " with size ", n)
			continue
		}

		for i := range c.conns {
			n, _, err = c.conns[i].ReadFrom(buf)
			if err != nil {
				errors.LogErrorInner(context.Background(), err, "[mask] drop packet from ", addr, " with size ", n)
				break
			}
			buf = buf[c.sizes[i] : n+c.sizes[i]]
		}

		if err != nil {
			continue
		}

		return copy(p, buf), addr, nil
	}
}

func (c *headerManagerConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buf := buf.New()
	buf.Resize(0, UDPSize)
	b := buf.Bytes()
	defer buf.Release()

	sum := 0
	for _, size := range c.sizes {
		sum += size
	}

	if sum+len(p) > UDPSize {
		errors.LogError(context.Background(), "[mask] drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}

	n = copy(b[sum:], p)

	for i := len(c.conns) - 1; i >= 0; i-- {
		n, err = c.conns[i].WriteTo(b[sum-c.sizes[i]:n+sum], nil)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "[mask] drop packet to ", addr, " with size ", len(p))
			return 0, nil
		}
		sum -= c.sizes[i]
	}

	if n > UDPSize {
		errors.LogError(context.Background(), "[mask] drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}

	_, err = c.PacketConn.WriteTo(b[:n], addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

type TCPListener struct {
	net.Listener
	tcpMasks []TCPMask
}

func (l *TCPListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}

	for i := range l.tcpMasks {
		var newConn net.Conn
		newConn, err = l.tcpMasks[i].WrapConnServer(conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = newConn
	}
	return conn, nil
}

type TcpMaskConn interface {
	TcpMaskConn()
	RawConn() net.Conn
	Splice() bool
}

func UnwrapTcpMask(conn net.Conn) net.Conn {
	for {
		if v, ok := conn.(TcpMaskConn); ok {
			if !v.Splice() {
				return conn
			}
			conn = v.RawConn()
		} else {
			return conn
		}
	}
}
