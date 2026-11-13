package internet

import (
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// dialMode is a ";"-separated list of options applied to a dialed connection; unknown
// options are rejected. The only options so far are the "oob" family below, and future
// options are added as new ";"-separated entries.
const dialModeSeparator = ";"

// The "oob" dialMode options apply to the first writes to the dialed TCP connection: each
// appends one byte to a leading write and flags that write as urgent (TCP out-of-band)
// data, using the i-th listed byte for the i-th write, then stops (later writes pass
// through untouched). Each byte is 0..255: "oob.0" appends 0x00 to the first write only;
// "oob.0,32,65" appends 0x00, 0x20, 0x41 to the first three writes. A "_" in place of a
// byte leaves that write untouched (no byte, no urgent flag) while still counting as one
// of the leading writes, so "oob.0,_,12" tags the first and third writes and sends the
// second as is.
//
// "oob.<list>" applies to any remote IP family; "oob4.<list>" only when the dialed
// connection's remote IP is IPv4; "oob6.<list>" only when it is IPv6. "oob" can't be
// combined with "oob4"/"oob6", e.g. "oob4.0,0;oob6.5,_,8" sends oob.0,0 on IPv4 and
// oob.5,_,8 on IPv6.
const (
	oobDialModePrefix  = "oob."  // any family
	oob4DialModePrefix = "oob4." // IPv4 remote only
	oob6DialModePrefix = "oob6." // IPv6 remote only
)

// oobPassthroughToken, in place of a byte in an oob list, leaves the write at its
// position untouched.
const oobPassthroughToken = "_"

// oobStep is one entry of an oob list: a byte to append to that write (sending it as TCP
// urgent data) or, for oobPassthroughToken, a passthrough that leaves the write as is.
type oobStep struct {
	passthrough bool
	b           byte
}

// oobDialOption is one parsed oob option: an IP-family filter plus the per-write steps.
type oobDialOption struct {
	onlyIPv4 bool
	onlyIPv6 bool
	steps    []oobStep
}

// appliesTo reports whether this option applies to a connection whose remote IP is IPv6
// (ipv6) or IPv4 (!ipv6). An unfiltered "oob" option applies to both.
func (o oobDialOption) appliesTo(ipv6 bool) bool {
	switch {
	case o.onlyIPv4:
		return !ipv6
	case o.onlyIPv6:
		return ipv6
	default:
		return true
	}
}

// parseDialMode splits a dialMode into its ";"-separated options and parses each. Today
// every option is an oob variant; "oob" can't be combined with "oob4"/"oob6", and each
// IP family can carry at most one option.
func parseDialMode(dialMode string) ([]oobDialOption, error) {
	var opts []oobDialOption
	var hasAny, hasV4, hasV6 bool
	for _, entry := range strings.Split(dialMode, dialModeSeparator) {
		var o oobDialOption
		var list string
		switch {
		case strings.HasPrefix(entry, oob4DialModePrefix):
			if hasV4 {
				return nil, errors.New("duplicate oob4 option in dialMode: ", dialMode)
			}
			o.onlyIPv4, hasV4, list = true, true, entry[len(oob4DialModePrefix):]
		case strings.HasPrefix(entry, oob6DialModePrefix):
			if hasV6 {
				return nil, errors.New("duplicate oob6 option in dialMode: ", dialMode)
			}
			o.onlyIPv6, hasV6, list = true, true, entry[len(oob6DialModePrefix):]
		case strings.HasPrefix(entry, oobDialModePrefix):
			if hasAny {
				return nil, errors.New("duplicate oob option in dialMode: ", dialMode)
			}
			hasAny, list = true, entry[len(oobDialModePrefix):]
		default:
			return nil, errors.New("unsupported dialMode: ", dialMode)
		}
		steps, err := parseOOBList(list, dialMode)
		if err != nil {
			return nil, err
		}
		o.steps = steps
		opts = append(opts, o)
	}
	if hasAny && (hasV4 || hasV6) {
		return nil, errors.New(`dialMode: "oob" can't be combined with "oob4"/"oob6": `, dialMode)
	}
	return opts, nil
}

// parseOOBList parses an oob "<b1>,<b2>,..." list (one entry per leading write): a byte
// 0..255 to append and mark urgent, or oobPassthroughToken to leave that write as is.
func parseOOBList(list, dialMode string) ([]oobStep, error) {
	if list == "" {
		return nil, errors.New("invalid dialMode: ", dialMode)
	}
	parts := strings.Split(list, ",")
	steps := make([]oobStep, 0, len(parts))
	for _, part := range parts {
		if part == oobPassthroughToken {
			steps = append(steps, oobStep{passthrough: true})
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return nil, errors.New("invalid dialMode: ", dialMode)
		}
		steps = append(steps, oobStep{b: byte(n)})
	}
	return steps, nil
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
