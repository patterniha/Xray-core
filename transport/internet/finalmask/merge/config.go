package merge

import (
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const (
	defaultDelayMs  = 30
	defaultMaxBytes = 16384
)

func (c *Config) WrapConnClient(conn net.Conn, dest *net.Destination, dialer *finalmask.Dialer) (net.Conn, error) {
	delayMs := c.DelayMs
	if delayMs <= 0 {
		delayMs = defaultDelayMs
	}
	maxBytes := int(c.MaxBytes)
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	return newMergeConn(conn, int(c.Times), maxBytes, time.Duration(delayMs)*time.Millisecond), nil
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	// Merge only shapes the client->server (outbound) write side; a server leaves it as is.
	return conn, nil
}
