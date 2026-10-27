//go:build !unix && !windows

package internet

import "github.com/xtls/xray-core/common/net"

// newOOBConn is a no-op where TCP urgent-data send is unavailable: the "oob." dialMode
// stays a legal value, but no urgent byte is appended.
func newOOBConn(conn net.Conn, _ []byte) net.Conn {
	return conn
}
