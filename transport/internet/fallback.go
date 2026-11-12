package internet

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
)

const defaultFallbackBuffer = 16384 // 16 KiB

// applyResponseFallback wraps a successfully dialed conn with the no-response
// fallback: if the target sends no byte before the connection ends (FIN/RST/
// error) or waitMs elapses, the buffered request is replayed to dest through the
// outbound tagged Fallback.NoResponseFallbackDialerProxy. dest must be the
// ORIGINAL target (domain preserved, not a resolved IP) so the fallback outbound
// can resolve/route it itself. conn is returned unchanged when none is configured.
func applyResponseFallback(ctx context.Context, dest net.Destination, sockopt *SocketConfig, conn net.Conn) net.Conn {
	if conn == nil || sockopt == nil || sockopt.Fallback == nil || sockopt.Fallback.NoResponseFallbackDialerProxy == "" {
		return conn
	}
	maxBuf := int(sockopt.Fallback.MaxBufferSize)
	if maxBuf <= 0 {
		maxBuf = defaultFallbackBuffer
	}
	waitMs := time.Duration(sockopt.Fallback.WaitMs) * time.Millisecond
	return newFallbackConn(conn, dest, sockopt.Fallback.NoResponseFallbackDialerProxy, maxBuf, waitMs, func(tag string, d net.Destination) (net.Conn, error) {
		return DialThroughOutbound(ctx, d, tag)
	})
}

// fallbackConn sits directly on top of the dialed socket (below TLS and every
// finalmask). It buffers any request bytes; if the underlying conn ends (FIN/RST/
// error) or stalls for waitMs before ANY byte is received, it re-dials dest through
// another outbound, replays the buffer, and swaps the underlying conn — transparently
// to everything above (finalmask, TLS, the proxy). A received byte (including a TLS
// ServerHello, since this is below TLS) commits the connection and disarms the
// fallback for good. No request byte need be sent first: server-first protocols
// (SMTP/IMAP/FTP banners, a TLS ServerHello) fall over too when the server speaks
// and the GFW then resets.
type fallbackConn struct {
	mu   sync.Mutex
	cond *sync.Cond

	inner net.Conn // current underlying conn: primary, then the fallback

	buf       []byte
	maxBuf    int
	armed     bool // still buffering; fallback still possible
	committed bool // a byte arrived, or we fell over, or we gave up — no (further) fallback
	swapped   bool // switched to the fallback conn

	dest         net.Destination
	tag          string
	dialOutbound func(tag string, dest net.Destination) (net.Conn, error)

	waitMs   time.Duration
	waitStop chan struct{}
	wsOnce   sync.Once
}

func newFallbackConn(conn net.Conn, dest net.Destination, tag string, maxBuf int, waitMs time.Duration, dialOutbound func(string, net.Destination) (net.Conn, error)) net.Conn {
	c := &fallbackConn{
		inner:        conn,
		maxBuf:       maxBuf,
		armed:        tag != "" && dialOutbound != nil,
		dest:         dest,
		tag:          tag,
		dialOutbound: dialOutbound,
		waitMs:       waitMs,
		waitStop:     make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)
	if c.armed && waitMs > 0 {
		go c.watchWait()
	}
	return c
}

func (c *fallbackConn) stopWait() { c.wsOnce.Do(func() { close(c.waitStop) }) }

// watchWait fires waitMs after the connection is established: if nothing has come
// back by then, it closes the underlying conn to unblock the Read, which then falls
// over. Anchoring to connect time (not the first send) also covers server-first
// protocols, where no request byte is ever sent.
func (c *fallbackConn) watchWait() {
	t := time.NewTimer(c.waitMs)
	defer t.Stop()
	select {
	case <-t.C:
		c.mu.Lock()
		inner := c.inner
		fire := !c.committed && !c.swapped
		c.mu.Unlock()
		if fire {
			inner.Close() // unblock the blocked Read; it will fall over
		}
	case <-c.waitStop:
	}
}

func (c *fallbackConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.armed && !c.committed {
		if len(c.buf)+len(p) > c.maxBuf {
			c.armed = false // request too large to replay; disarm fallback
			c.buf = nil
		} else {
			c.buf = append(c.buf, p...)
		}
	}
	inner := c.inner
	wasSwapped := c.swapped
	c.mu.Unlock()

	n, err := inner.Write(p)
	if err == nil || wasSwapped {
		return n, err
	}
	// Primary write failed before commit. Nudge a (possibly blocked) Read to fall
	// over by closing the conn, then wait for the swap.
	c.mu.Lock()
	if c.committed {
		c.mu.Unlock()
		return n, err
	}
	inner.Close()
	for !c.swapped && !c.committed {
		c.cond.Wait()
	}
	swapped := c.swapped
	c.mu.Unlock()
	if swapped {
		return len(p), nil // p was buffered and replayed onto the fallback conn
	}
	return n, err
}

func (c *fallbackConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	inner := c.inner
	done := c.committed
	c.mu.Unlock()
	if done {
		return inner.Read(p)
	}
	n, err := inner.Read(p)
	if n > 0 {
		c.mu.Lock()
		if !c.committed {
			c.committed = true
			c.armed = false
			c.cond.Broadcast()
		}
		c.mu.Unlock()
		c.stopWait()
		return n, err
	}
	if err == nil {
		return 0, nil
	}
	return c.fallback(p, err)
}

// fallback runs when the underlying conn returned 0 bytes + an error (or was
// closed by watchWait / a failed Write) before any response was received.
func (c *fallbackConn) fallback(p []byte, origErr error) (int, error) {
	c.mu.Lock()
	if c.committed || c.swapped {
		inner := c.inner
		c.mu.Unlock()
		return inner.Read(p)
	}
	if !c.armed || c.tag == "" || c.dialOutbound == nil {
		c.committed = true // disarmed (overflow) / no fallback configured: give up
		c.cond.Broadcast()
		c.mu.Unlock()
		c.stopWait()
		return 0, origErr
	}
	replay := c.buf
	oldInner := c.inner
	c.mu.Unlock()

	newConn, err := c.dialOutbound(c.tag, c.dest)
	if err != nil {
		c.fail()
		return 0, origErr
	}
	if len(replay) > 0 {
		if _, werr := newConn.Write(replay); werr != nil {
			newConn.Close()
			c.fail()
			return 0, origErr
		}
	}
	c.mu.Lock()
	c.inner = newConn
	c.swapped = true
	c.committed = true // one-shot: no further fallback on this conn
	c.buf = nil
	c.cond.Broadcast()
	c.mu.Unlock()
	c.stopWait()
	oldInner.Close()
	return newConn.Read(p)
}

// fail marks the fallback abandoned (propagate errors, wake any blocked Write).
func (c *fallbackConn) fail() {
	c.mu.Lock()
	c.committed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	c.stopWait()
}

func (c *fallbackConn) Close() error {
	c.mu.Lock()
	c.committed = true
	inner := c.inner
	c.cond.Broadcast()
	c.mu.Unlock()
	c.stopWait()
	return inner.Close()
}

func (c *fallbackConn) current() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inner
}

func (c *fallbackConn) LocalAddr() net.Addr  { return c.current().LocalAddr() }
func (c *fallbackConn) RemoteAddr() net.Addr { return c.current().RemoteAddr() }

func (c *fallbackConn) SetDeadline(t time.Time) error      { return c.current().SetDeadline(t) }
func (c *fallbackConn) SetReadDeadline(t time.Time) error  { return c.current().SetReadDeadline(t) }
func (c *fallbackConn) SetWriteDeadline(t time.Time) error { return c.current().SetWriteDeadline(t) }
