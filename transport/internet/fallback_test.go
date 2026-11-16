package internet

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
)

type fallbackStubConn struct {
	readData []byte
	readErr  error
	remote   net.Addr
}

func (c *fallbackStubConn) Read(b []byte) (int, error) {
	if len(c.readData) > 0 {
		n := copy(b, c.readData)
		c.readData = c.readData[n:]
		return n, nil
	}
	if c.readErr != nil {
		err := c.readErr
		c.readErr = nil
		return 0, err
	}
	return 0, io.EOF
}

func (c *fallbackStubConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *fallbackStubConn) Close() error                { return nil }
func (c *fallbackStubConn) LocalAddr() net.Addr         { return nil }
func (c *fallbackStubConn) RemoteAddr() net.Addr        { return c.remote }
func (c *fallbackStubConn) SetDeadline(t time.Time) error {
	return nil
}
func (c *fallbackStubConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fallbackStubConn) SetWriteDeadline(t time.Time) error { return nil }

// dialFallbackOnce arms a fallbackConn over a primary conn that fails before
// any response, triggers the fallback with a Read, and reports the destination
// the fallback dial was given.
func dialFallbackOnce(t *testing.T, passPrimaryAddr bool) net.Destination {
	t.Helper()

	// Primary remote address deliberately differs from the original target port
	// so the test proves the primary conn's own address is passed through.
	primary := &fallbackStubConn{
		readErr: io.ErrUnexpectedEOF, // RST before any byte: fallback fires
		remote:  &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 8443},
	}
	orig := net.TCPDestination(net.DomainAddress("example.com"), 443)

	var gotDest net.Destination
	fallback := &fallbackStubConn{readData: []byte("ok")}
	conn := newFallbackConn(primary, orig, "fallback-out", defaultFallbackBuffer, 0, passPrimaryAddr,
		func(tag string, dest net.Destination) (net.Conn, error) {
			if tag != "fallback-out" {
				t.Fatalf("unexpected fallback tag %q", tag)
			}
			gotDest = dest
			return fallback, nil
		})

	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("expected replayed fallback read, got n=%d err=%v", n, err)
	}
	return gotDest
}

func TestFallbackDefaultDialsOriginalTarget(t *testing.T) {
	got := dialFallbackOnce(t, false)
	if got.Address.Family().IsDomain() == false || got.Address.String() != "example.com" {
		t.Fatalf("expected original domain target, got %v", got)
	}
	if got.Port != 443 {
		t.Fatalf("fallback dial lost the original port: %v", got)
	}
}

func TestFallbackPassPrimaryConnAddress(t *testing.T) {
	got := dialFallbackOnce(t, true)
	if got.Address.String() != "203.0.113.7" {
		t.Fatalf("expected primary conn remote IP, got %v", got)
	}
	if got.Port != 8443 {
		t.Fatalf("expected primary conn remote port, got %v", got)
	}
	if got.Network != net.Network_TCP {
		t.Fatalf("expected TCP network, got %v", got.Network)
	}
}

func TestFallbackPassPrimaryConnAddressWithoutTCPAddr(t *testing.T) {
	// The primary IP is captured at wrap time; with no TCP remote address
	// captured, the fallback dial keeps the original target.
	primary := &fallbackStubConn{readErr: io.ErrUnexpectedEOF, remote: nil}
	orig := net.TCPDestination(net.DomainAddress("example.com"), 443)

	var gotDest net.Destination
	conn := newFallbackConn(primary, orig, "fallback-out", defaultFallbackBuffer, 0, true,
		func(tag string, dest net.Destination) (net.Conn, error) {
			gotDest = dest
			return &fallbackStubConn{readData: []byte("ok")}, nil
		})

	buf := make([]byte, 8)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("expected replayed fallback read, got %v", err)
	}
	if gotDest.Address.String() != "example.com" {
		t.Fatalf("expected original domain target, got %v", gotDest)
	}
}
