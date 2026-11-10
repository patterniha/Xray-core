package freedom

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"time"
)

// The "close" feature rewrites the FIRST HTTP/1.x request freedom writes to the target. freedom
// writes the plaintext payload into the dialed connection (which carries the stream's TLS, if
// any), so wrapping that write path lets the rewrite run *before* TLS encrypts it — the request
// freedom sees is plaintext even when the outbound adds TLS. Ported from the MITM-DomainFronting
// request-splitter (add_connection_close), request direction only.

const (
	closeDefaultTimeoutMs = 30
	// closeMaxHeaderBytes caps how far CloseWriter buffers the first write while waiting for the
	// end of the request headers (CRLFCRLF). Reaching it is treated like the header timeout.
	closeMaxHeaderBytes = 1 << 16 // 64 KiB
)

var (
	closeHeaderEnd = []byte("\r\n\r\n")
	closeCRLF      = []byte("\r\n")

	errClosedByCloseWriter = errors.New("freedom close: connection closed (non-HTTP, header timeout, or no Host)")

	// Lowercased "METHOD " tokens. Only the first write of a connection is inspected; if it does
	// not start like one of these (e.g. a TLS ClientHello) the "nonHTTP" action decides whether
	// to pass it through or close the connection.
	closeHTTPMethods = [][]byte{
		[]byte("get "), []byte("post "), []byte("put "), []byte("delete "),
		[]byte("head "), []byte("options "), []byte("patch "), []byte("trace "),
		[]byte("connect "),
	}
)

// CloseWriter rewrites the FIRST HTTP/1.x request written to the target, then passes every later
// write straight through. On that first request (see closeRewriteFirstRequest):
//   - Host rewrite / original-host header (if configured) on any request that has a Host.
//   - "Connection: close" on normal requests (skipped for WebSocket/upgrade/SSE).
//
// It buffers the start of the stream until it can see the end of the request headers:
//   - CRLFCRLF seen        -> rewrite and flush; or close if "noHost" is close and there is no Host.
//   - not HTTP-looking     -> "nonHTTP" action: pass the bytes through, or close.
//   - timeout / size cap   -> "onTimeout" action: pass the buffered bytes through, or close.
type CloseWriter struct {
	writer io.Writer
	closer io.Closer

	timeout            time.Duration
	closeOnTimeout     bool
	closeOnNonHTTP     bool
	closeOnNoHost      bool
	rewriteHost        string
	originalHostHeader string

	mu    sync.Mutex
	done  bool // first-request decision made; Write now passes through
	buf   []byte
	timer *time.Timer
	err   error
}

// NewCloseWriter wraps writer (the freedom write path) with the "close" rewrite. closer is the
// underlying connection, torn down when a "close" action fires.
func NewCloseWriter(writer io.Writer, closer io.Closer, config *Close) *CloseWriter {
	timeoutMs := config.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = closeDefaultTimeoutMs
	}
	return &CloseWriter{
		writer:             writer,
		closer:             closer,
		timeout:            time.Duration(timeoutMs) * time.Millisecond,
		closeOnTimeout:     config.CloseOnTimeout,
		closeOnNonHTTP:     config.CloseOnNonHttp,
		closeOnNoHost:      config.CloseOnNoHost,
		rewriteHost:        config.RewriteHost,
		originalHostHeader: config.OriginalHostHeader,
	}
}

func (c *CloseWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.err != nil {
		return 0, c.err
	}
	if c.done {
		n, err := c.writer.Write(p)
		if err != nil {
			c.err = err
		}
		return n, err
	}
	if len(p) == 0 {
		return 0, nil
	}

	// append copies p, so the caller may reuse its buffer once Write returns.
	c.buf = append(c.buf, p...)

	switch {
	case !closeLooksLikeHTTPRequest(c.buf):
		// Not an HTTP request (TLS record, other protocol, ...). Checked BEFORE looking for
		// CRLFCRLF, so binary data that happens to contain it is never parsed as HTTP.
		if c.closeOnNonHTTP {
			return 0, c.abortLocked()
		}
		return c.flushLocked(c.buf, len(p))
	case bytes.Contains(c.buf, closeHeaderEnd):
		// Whole request head is here: apply the rewrites (no-op where they don't apply).
		out, shouldClose := closeRewriteFirstRequest(c.buf, c.rewriteHost, c.originalHostHeader, c.closeOnNoHost)
		if shouldClose {
			return 0, c.abortLocked()
		}
		return c.flushLocked(out, len(p))
	case len(c.buf) >= closeMaxHeaderBytes:
		// Looks like HTTP but the header block never ended; treat like the timeout.
		if c.closeOnTimeout {
			return 0, c.abortLocked()
		}
		return c.flushLocked(c.buf, len(p))
	default:
		// Looks like HTTP, headers not complete yet: keep buffering under a deadline.
		c.armTimerLocked()
		return len(p), nil
	}
}

// flushLocked writes out as the final buffered flush, switches to pass-through, stops the timer,
// and reports consumed (this Write's len(p)). Earlier buffered writes already reported their own.
func (c *CloseWriter) flushLocked(out []byte, consumed int) (int, error) {
	c.done = true
	c.stopTimerLocked()
	c.buf = nil
	if _, err := c.writer.Write(out); err != nil {
		c.err = err
		return 0, err
	}
	return consumed, nil
}

// abortLocked tears the connection down (the "close" action) and makes every later Write fail.
// Buffered bytes are dropped. The err/done guards ensure it runs at most once.
func (c *CloseWriter) abortLocked() error {
	c.done = true
	c.stopTimerLocked()
	c.buf = nil
	c.err = errClosedByCloseWriter
	if c.closer != nil {
		_ = c.closer.Close()
	}
	return c.err
}

func (c *CloseWriter) armTimerLocked() {
	if c.timer == nil {
		c.timer = time.AfterFunc(c.timeout, c.onTimeout)
	}
}

func (c *CloseWriter) stopTimerLocked() {
	if c.timer != nil {
		c.timer.Stop()
	}
}

// onTimeout fires once, `timeout` after buffering began, if CRLFCRLF never arrived.
func (c *CloseWriter) onTimeout() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done || c.err != nil {
		return
	}
	if c.closeOnTimeout {
		_ = c.abortLocked()
		return
	}
	c.done = true
	data := c.buf
	c.buf = nil
	if _, err := c.writer.Write(data); err != nil {
		c.err = err
	}
}

// closeLooksLikeHTTPRequest reports whether buf could be the beginning of an HTTP/1.x request
// line: the shorter of buf and some "METHOD " token is a prefix of the other (case-insensitive).
// "GE" keeps buffering; "POST /..." matches; a TLS record does not.
func closeLooksLikeHTTPRequest(buf []byte) bool {
	for _, m := range closeHTTPMethods {
		n := len(buf)
		if n > len(m) {
			n = len(m)
		}
		if bytes.EqualFold(buf[:n], m[:n]) {
			return true
		}
	}
	return false
}

// closeRewriteFirstRequest applies, on a plain HTTP/1.x request only:
//   - Host rewrite: replace the Host value with rewriteHost (if set) and/or copy the original
//     Host into a header named originalHostHeader (if set). Applies to every request that has a
//     Host, including WebSocket/SSE.
//   - Connection: close: drop existing Connection/Keep-Alive/Proxy-Connection and append
//     "Connection: close" — EXCEPT on WebSocket/upgrade/SSE requests, which keep their headers
//     untouched.
//
// It returns shouldClose=true (with raw) when the request has no Host header and closeOnNoHost is
// set, telling the caller to tear the connection down. CONNECT and responses are returned
// unchanged. Rules mirror MITM-DomainFronting/request-splitter (add_connection_close), request
// direction only.
func closeRewriteFirstRequest(raw []byte, rewriteHost, originalHostHeader string, closeOnNoHost bool) (out []byte, shouldClose bool) {
	idx := bytes.Index(raw, closeHeaderEnd)
	if idx == -1 {
		return raw, false // no complete header block
	}
	head := raw[:idx]
	body := raw[idx+len(closeHeaderEnd):]

	lines := bytes.Split(head, closeCRLF)
	if len(lines) == 0 || len(lines[0]) == 0 {
		return raw, false
	}

	fields := bytes.Fields(bytes.ToLower(lines[0]))
	if len(fields) == 0 {
		return raw, false
	}
	// CONNECT (tunnel) and responses (status line) have no frontable Host and take no
	// Connection: close; leave them entirely alone.
	if bytes.Equal(fields[0], []byte("connect")) || bytes.HasPrefix(fields[0], []byte("http/")) {
		return raw, false
	}

	// Connection: close is skipped for protocol upgrades (WebSocket) and SSE; the Host rewrite
	// still applies to them.
	addClose := true
	hasHost := false
	for _, line := range lines[1:] {
		lower := bytes.ToLower(line)
		switch {
		case bytes.HasPrefix(lower, []byte("host:")):
			hasHost = true
		case bytes.HasPrefix(lower, []byte("connection:")):
			if bytes.Contains(bytes.TrimSpace(lower[len("connection:"):]), []byte("upgrade")) {
				addClose = false
			}
		case bytes.HasPrefix(lower, []byte("upgrade:")):
			addClose = false
		case bytes.HasPrefix(lower, []byte("accept:")):
			if bytes.Contains(bytes.TrimSpace(lower[len("accept:"):]), []byte("text/event-stream")) {
				addClose = false
			}
		case bytes.HasPrefix(lower, []byte("content-type:")):
			if bytes.Contains(bytes.TrimSpace(lower[len("content-type:"):]), []byte("text/event-stream")) {
				addClose = false
			}
		}
	}

	// A request with no Host header: reject it if asked, otherwise fall through (the Host rewrite
	// is a no-op with nothing to replace).
	if !hasHost && closeOnNoHost {
		return raw, true
	}

	doHost := rewriteHost != "" || originalHostHeader != ""
	if !addClose && !doHost {
		return raw, false // nothing to change
	}

	out = make([]byte, 0, len(raw)+len(rewriteHost)+len(originalHostHeader)+len("Connection: close")+3*len(closeCRLF))
	out = append(out, lines[0]...)
	for _, line := range lines[1:] {
		lower := bytes.ToLower(line)

		if doHost && bytes.HasPrefix(lower, []byte("host:")) {
			originalHost := bytes.TrimSpace(line[len("host:"):])
			out = append(out, closeCRLF...)
			out = append(out, []byte("Host: ")...)
			if rewriteHost != "" {
				out = append(out, []byte(rewriteHost)...)
			} else {
				out = append(out, originalHost...)
			}
			if originalHostHeader != "" {
				out = append(out, closeCRLF...)
				out = append(out, []byte(originalHostHeader)...)
				out = append(out, ':', ' ')
				out = append(out, originalHost...)
			}
			continue
		}

		// Only strip connection-management headers when we are adding our own close; an
		// upgrade/SSE request must keep its Connection header intact.
		if addClose && (bytes.HasPrefix(lower, []byte("connection:")) ||
			bytes.HasPrefix(lower, []byte("keep-alive:")) ||
			bytes.HasPrefix(lower, []byte("proxy-connection:"))) {
			continue
		}
		out = append(out, closeCRLF...)
		out = append(out, line...)
	}
	if addClose {
		out = append(out, closeCRLF...)
		out = append(out, []byte("Connection: close")...)
	}
	out = append(out, closeHeaderEnd...)
	out = append(out, body...)
	return out, false
}
