package merge

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

// mergeConn coalesces client->server writes. While it still has budget, every Write is
// buffered instead of sent; the buffer is flushed as one write when either no new write
// arrives for `delay` (the idle timer resets on each write) or the buffer reaches
// `maxBytes`. Each flush counts; after `times` flushes the conn switches to immediate
// pass-through for the rest of its life. Reads (server->client) are never touched.
//
// A zero or negative `times` means "no limit" (coalesce for the whole connection).
type mergeConn struct {
	net.Conn

	delay     time.Duration
	maxBytes  int
	unlimited bool

	mu        sync.Mutex
	buf       []byte
	remaining int
	epoch     uint64
	timer     *time.Timer
	closed    bool
	err       error
}

func newMergeConn(conn net.Conn, times, maxBytes int, delay time.Duration) net.Conn {
	c := &mergeConn{Conn: conn, delay: delay, maxBytes: maxBytes}
	if times <= 0 {
		c.unlimited = true
	} else {
		c.remaining = times
	}
	return c
}

func (c *mergeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.err != nil {
		return 0, c.err
	}
	// Budget spent: send straight through, no buffering, for the rest of the connection.
	if !c.unlimited && c.remaining == 0 {
		n, err := c.Conn.Write(p)
		if err != nil {
			c.err = err
		}
		return n, err
	}

	// append copies p, so the caller may reuse its buffer once Write returns.
	c.buf = append(c.buf, p...)
	if len(c.buf) >= c.maxBytes {
		if err := c.flushLocked(); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	c.armTimerLocked()
	return len(p), nil
}

// armTimerLocked (re)starts the idle timer. A fresh epoch makes any already-fired-but-
// still-waiting timer callback a no-op, which sidesteps the time.Timer reset race.
func (c *mergeConn) armTimerLocked() {
	c.epoch++
	ep := c.epoch
	if c.timer != nil {
		c.timer.Stop()
	}
	c.timer = time.AfterFunc(c.delay, func() { c.onTimer(ep) })
}

func (c *mergeConn) onTimer(ep uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.err != nil || ep != c.epoch {
		return
	}
	_ = c.flushLocked()
}

// flushLocked sends the whole buffer as one write and counts it. Caller holds c.mu.
func (c *mergeConn) flushLocked() error {
	if len(c.buf) == 0 {
		return nil
	}
	c.epoch++ // invalidate any pending timer tied to this buffer
	if c.timer != nil {
		c.timer.Stop()
	}
	data := c.buf
	c.buf = nil
	if _, err := c.Conn.Write(data); err != nil {
		c.err = err
		return err
	}
	if !c.unlimited {
		c.remaining--
	}
	return nil
}

func (c *mergeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.epoch++
	if c.timer != nil {
		c.timer.Stop()
	}
	if len(c.buf) > 0 && c.err == nil {
		data := c.buf
		c.buf = nil
		if _, err := c.Conn.Write(data); err != nil {
			c.err = err
		}
	}
	c.mu.Unlock()
	return c.Conn.Close()
}

// SyscallConn keeps the read side's readv fast path working (buf.NewReader checks for it).
// Writes always go through Write above: net.Buffers.WriteTo and splice both need a concrete
// *net.TCPConn, which this wrapper is not, so neither can bypass the coalescing.
func (c *mergeConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("mergeConn: underlying connection is not a syscall.Conn")
}
