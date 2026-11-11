package freedom

import (
	"bytes"
	"errors"
	"io"
	"sort"
	"strings"
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
// write straight through. On that first request (see rewriteFirstRequest):
//   - Host rewrite / original-host header (if configured) on any request that has a Host.
//   - "Connection: close" on normal requests (skipped for WebSocket/upgrade/SSE).
//   - Header edits: remove, set (override/add), override (only if present), add-if-missing, append.
//   - removeHeaderSpace: drop the optional space between every header name and value.
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
	removeHeaderSpace  bool            // "removeHeaderSpace": drop the optional whitespace between every header name and value
	appendHeaders      [][2]string     // "appendHeaders": always appended (may duplicate), sorted by name
	setHeaders         [][2]string     // "setHeaders": override/add (upsert), sorted by name
	overrideHeaders    [][2]string     // "overrideHeaders": override only when present, never add, sorted by name
	addHeaders         [][2]string     // "addHeaders": add only when absent, sorted by name
	removeNames        map[string]bool // lowercased names dropped from the original (removeHeaders ∪ setHeaders ∪ overrideHeaders)

	mu    sync.Mutex
	done  bool // first-request decision made; Write now passes through
	buf   []byte
	timer *time.Timer
	err   error
}

// sortHeaderMap flattens a header map into a slice sorted by name, so the rewritten request is
// deterministic (Go maps iterate in random order; net/http likewise serializes a header map sorted).
func sortHeaderMap(m map[string]string) [][2]string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][2]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, [2]string{k, m[k]})
	}
	return out
}

// NewCloseWriter wraps writer (the freedom write path) with the "close" rewrite. closer is the
// underlying connection, torn down when a "close" action fires.
func NewCloseWriter(writer io.Writer, closer io.Closer, config *Close) *CloseWriter {
	timeoutMs := config.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = closeDefaultTimeoutMs
	}
	// removeHeaders and setHeaders both cause the matching original header to be dropped (set then
	// re-appends its own value); collect their lowercased names once.
	var removeNames map[string]bool
	if len(config.RemoveHeaders) > 0 || len(config.SetHeaders) > 0 || len(config.OverrideHeaders) > 0 {
		removeNames = make(map[string]bool, len(config.RemoveHeaders)+len(config.SetHeaders)+len(config.OverrideHeaders))
		for _, n := range config.RemoveHeaders {
			removeNames[strings.ToLower(n)] = true
		}
		for n := range config.SetHeaders {
			removeNames[strings.ToLower(n)] = true
		}
		for n := range config.OverrideHeaders {
			removeNames[strings.ToLower(n)] = true
		}
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
		removeHeaderSpace:  config.RemoveHeaderSpace,
		appendHeaders:      sortHeaderMap(config.AppendHeaders),
		setHeaders:         sortHeaderMap(config.SetHeaders),
		overrideHeaders:    sortHeaderMap(config.OverrideHeaders),
		addHeaders:         sortHeaderMap(config.AddHeaders),
		removeNames:        removeNames,
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
		out, shouldClose := c.rewriteFirstRequest(c.buf)
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

// closeHeaderName returns the lowercased header name of an already-lowercased header line (the
// part before the first ':'), or "" if the line has no colon.
func closeHeaderName(lowerLine []byte) string {
	if i := bytes.IndexByte(lowerLine, ':'); i > 0 {
		return string(lowerLine[:i])
	}
	return ""
}

func appendHeaderLine(out []byte, h [2]string) []byte {
	out = append(out, closeCRLF...)
	out = append(out, h[0]...)
	out = append(out, ':', ' ')
	out = append(out, h[1]...)
	return out
}

// rewriteFirstRequest applies, on a plain HTTP/1.x request only (CONNECT and responses are
// returned unchanged):
//   - Host rewrite: replace the Host value with rewriteHost (if set) and/or copy the original Host
//     into a header named originalHostHeader (if set). Applies to every request that has a Host,
//     including WebSocket/SSE.
//   - Connection: close: drop existing Connection/Keep-Alive/Proxy-Connection and append
//     "Connection: close" — EXCEPT on WebSocket/upgrade/SSE requests, which keep their headers.
//   - Header edits, each applied whenever the request is rewritten: removeHeaders drop the named
//     headers; setHeaders override-or-add; overrideHeaders override only when the header is present
//     (never add); addHeaders append only when the request lacks that name; appendHeaders
//     ("appendHeaders") always append. All added headers are emitted sorted by name.
//   - removeHeaderSpace: once every header above is in place, drop the optional whitespace between
//     each header name and its value, across the whole header block (the request line is kept).
//
// It returns shouldClose=true (with raw) when the request has no Host header and closeOnNoHost is
// set, telling the caller to tear the connection down. Rules mirror MITM-DomainFronting/
// request-splitter (add_connection_close), request direction only.
func (c *CloseWriter) rewriteFirstRequest(raw []byte) (out []byte, shouldClose bool) {
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
	// CONNECT (tunnel) and responses (status line) have no frontable Host and take no edits;
	// leave them entirely alone.
	if bytes.Equal(fields[0], []byte("connect")) || bytes.HasPrefix(fields[0], []byte("http/")) {
		return raw, false
	}

	// Connection: close is skipped for protocol upgrades (WebSocket) and SSE; the other edits
	// still apply to them.
	addClose := true
	hasHost := false
	var present map[string]bool // lowercased names present in the original (for addHeaders / overrideHeaders)
	if len(c.addHeaders) > 0 || len(c.overrideHeaders) > 0 {
		present = make(map[string]bool, len(lines))
	}
	for _, line := range lines[1:] {
		lower := bytes.ToLower(line)
		if present != nil {
			if name := closeHeaderName(lower); name != "" {
				present[name] = true
			}
		}
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
	if !hasHost && c.closeOnNoHost {
		return raw, true
	}

	doHost := c.rewriteHost != "" || c.originalHostHeader != ""
	if !addClose && !doHost && len(c.appendHeaders) == 0 && len(c.setHeaders) == 0 && len(c.overrideHeaders) == 0 && len(c.addHeaders) == 0 && len(c.removeNames) == 0 && !c.removeHeaderSpace {
		return raw, false // nothing to change
	}

	extra := len("Connection: close") + len(c.rewriteHost) + len(c.originalHostHeader) + 8*len(closeCRLF)
	for _, set := range [][][2]string{c.setHeaders, c.overrideHeaders, c.addHeaders, c.appendHeaders} {
		for _, h := range set {
			extra += len(h[0]) + len(h[1]) + len(": ") + len(closeCRLF)
		}
	}
	out = make([]byte, 0, len(raw)+extra)
	out = append(out, lines[0]...)
	for _, line := range lines[1:] {
		lower := bytes.ToLower(line)

		if doHost && bytes.HasPrefix(lower, []byte("host:")) {
			originalHost := bytes.TrimSpace(line[len("host:"):])
			out = append(out, closeCRLF...)
			out = append(out, []byte("Host: ")...)
			if c.rewriteHost != "" {
				out = append(out, []byte(c.rewriteHost)...)
			} else {
				out = append(out, originalHost...)
			}
			if c.originalHostHeader != "" {
				out = append(out, closeCRLF...)
				out = append(out, []byte(c.originalHostHeader)...)
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

		// Drop headers slated for removal or override (setHeaders re-adds its value below).
		if c.removeNames != nil {
			if name := closeHeaderName(lower); name != "" && c.removeNames[name] {
				continue
			}
		}

		out = append(out, closeCRLF...)
		out = append(out, line...)
	}
	// setHeaders: override/add (matching originals were dropped above).
	for _, h := range c.setHeaders {
		out = appendHeaderLine(out, h)
	}
	// overrideHeaders: override only when the header was present (dropped above); never add.
	for _, h := range c.overrideHeaders {
		if !present[strings.ToLower(h[0])] {
			continue
		}
		out = appendHeaderLine(out, h)
	}
	// addHeaders: add only when the original request lacked that name.
	for _, h := range c.addHeaders {
		if present[strings.ToLower(h[0])] {
			continue
		}
		out = appendHeaderLine(out, h)
	}
	// headers: always append.
	for _, h := range c.appendHeaders {
		out = appendHeaderLine(out, h)
	}
	if addClose {
		out = append(out, closeCRLF...)
		out = append(out, []byte("Connection: close")...)
	}
	// removeHeaderSpace: drop the optional whitespace (RFC 9110 OWS) between every header name and
	// its value ("Host: x" -> "Host:x") to send fewer bytes. Applied to the whole header block at
	// once, so it covers both the original headers and the ones added above; the request line is
	// left untouched, as it may legitimately carry a colon (an absolute-form URI, a port).
	if c.removeHeaderSpace {
		reqLine := out[:len(lines[0])]
		out = append(reqLine, removeHeaderBlockSpaces(out[len(lines[0]):])...)
	}
	out = append(out, closeHeaderEnd...)
	out = append(out, body...)
	return out, false
}

// removeHeaderBlockSpaces removes the optional whitespace after the colon of every header line in a
// CRLF-separated header block ("\r\nHost: x\r\nAccept: y" -> "\r\nHost:x\r\nAccept:y"). The leading
// empty segment and any line without a colon are left unchanged. See removeHeaderSpace.
func removeHeaderBlockSpaces(block []byte) []byte {
	lines := bytes.Split(block, closeCRLF)
	for i, line := range lines {
		lines[i] = stripHeaderLineSpace(line)
	}
	return bytes.Join(lines, closeCRLF)
}

// stripHeaderLineSpace removes the run of spaces and tabs between a header line's name and value
// ("Host: \twww.example.com" -> "Host:www.example.com"). A line with no colon is returned as is.
func stripHeaderLineSpace(line []byte) []byte {
	i := bytes.IndexByte(line, ':')
	if i < 0 {
		return line
	}
	j := i + 1
	for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
		j++
	}
	if j == i+1 {
		return line
	}
	out := make([]byte, 0, i+1+len(line)-j)
	out = append(out, line[:i+1]...)
	return append(out, line[j:]...)
}
