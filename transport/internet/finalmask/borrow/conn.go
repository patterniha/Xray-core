package borrow

import (
	"bytes"
	"net"

	"github.com/xtls/xray-core/common/errors"
)

type borrowConn struct {
	net.Conn
	config *Config
	count  uint64

	server bool
}

func NewConnClient(c *Config, raw net.Conn, server bool) (net.Conn, error) {
	conn := &borrowConn{
		Conn:   raw,
		config: c,

		server: server,
	}

	return conn, nil
}

func NewConnServer(c *Config, raw net.Conn, server bool) (net.Conn, error) {
	return NewConnClient(c, raw, server)
}

func (c *borrowConn) TcpMaskConn() {}

func (c *borrowConn) RawConn() net.Conn {
	return c.Conn
}

func (c *borrowConn) Splice() bool {
	if c.server {
		return false
	}
	return true
}

// Write leaves every packet untouched except the first two: borrow_bytes is
// appended to the first and must lead the second, where it is stripped. Like
// the fragment mask this applies to the writes of whichever side it wraps
// (client-to-server on a client, server-to-client on a server); data received
// from the peer always passes through Read untouched. A second packet that
// does not start with borrow_bytes fails so the connection is closed, since
// the receiver side is no longer in sync.
func (c *borrowConn) Write(p []byte) (int, error) {
	c.count++
	switch c.count {
	case 1:
		if len(c.config.BorrowBytes) == 0 {
			return c.Conn.Write(p)
		}
		b := make([]byte, 0, len(p)+len(c.config.BorrowBytes))
		b = append(b, p...)
		b = append(b, c.config.BorrowBytes...)
		if _, err := c.Conn.Write(b); err != nil {
			return 0, err
		}
		return len(p), nil
	case 2:
		bb := c.config.BorrowBytes
		if len(bb) == 0 {
			return c.Conn.Write(p)
		}
		if len(p) < len(bb) || !bytes.Equal(p[:len(bb)], bb) {
			return 0, errors.New("borrow finalmask: second packet does not start with borrow bytes, closing connection")
		}
		if _, err := c.Conn.Write(p[len(bb):]); err != nil {
			return 0, err
		}
		return len(p), nil
	default:
		return c.Conn.Write(p)
	}
}
