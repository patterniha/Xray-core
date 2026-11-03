//go:build unix || windows

package internet

import (
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// oobConn tags each of the first len(steps) writes as its step says: it either appends that
// step's byte and sends the write as TCP urgent (out-of-band) data, or, for a passthrough
// step, leaves the write untouched. Later writes go straight to the underlying connection.
// A peer that handles urgent data drops the extra byte back out of the stream, while a
// middlebox that mishandles the urgent pointer desyncs on those segments (e.g. a TLS
// ClientHello). A zero-length urgent write still counts: it sends its byte on its own,
// ahead of any real data.
type oobConn struct {
	net.Conn

	steps []oobStep
	idx   int
}

func newOOBConn(conn net.Conn, steps []oobStep) net.Conn {
	return &oobConn{Conn: conn, steps: steps}
}

func (c *oobConn) Write(p []byte) (int, error) {
	if c.idx >= len(c.steps) {
		return c.Conn.Write(p)
	}
	step := c.steps[c.idx]
	c.idx++
	if step.passthrough {
		// A "_" step: send this write as is, with no appended byte and no urgent flag.
		return c.Conn.Write(p)
	}
	oobByte := step.b

	sc, ok := c.Conn.(syscall.Conn)
	if !ok {
		return c.Conn.Write(p)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return c.Conn.Write(p)
	}

	data := make([]byte, len(p)+1)
	copy(data, p)
	data[len(p)] = oobByte

	var sent int
	var sendErr error
	ctrlErr := raw.Write(func(fd uintptr) bool {
		n, e := sendOOB(fd, data)
		if e == syscall.EAGAIN || e == syscall.EWOULDBLOCK {
			return false // socket not writable yet; wait and send again
		}
		sent, sendErr = n, e
		return true
	})
	if ctrlErr != nil {
		return 0, ctrlErr
	}
	if sendErr != nil {
		return 0, sendErr
	}
	// The extra urgent byte is ours, so never report it as the caller's.
	if sent > len(p) {
		sent = len(p)
	}
	if sent < len(p) {
		// A short send is unlikely on these leading writes, but deliver whatever
		// payload is left over the normal path so no data is lost.
		m, e := c.Conn.Write(p[sent:])
		return sent + m, e
	}
	return len(p), nil
}

// SyscallConn keeps the read side's readv fast path working (buf.NewReader checks for it).
func (c *oobConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("oobConn: underlying connection is not a syscall.Conn")
}
