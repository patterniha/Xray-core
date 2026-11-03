package internet

import (
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

// oobDialModePrefix marks the "oob.<byte>,<byte>,..." dialMode family. Such a mode applies
// to the first writes to the dialed TCP connection: it appends one byte to each and flags
// that write as urgent (TCP out-of-band) data, using the i-th listed byte for the i-th
// write, then stops (later writes pass through untouched). Each byte is 0..255: "oob.0"
// appends 0x00 to the first write only; "oob.0,32,65" appends 0x00, 0x20, 0x41 to the
// first three writes. A "_" in place of a byte leaves that write untouched (no byte and
// no urgent flag) while still counting as one of the leading writes, so "oob.0,_,12" tags
// the first and third writes and sends the second as is.
const oobDialModePrefix = "oob."

// oobPassthroughToken, in place of a byte in an "oob." list, leaves the write at its
// position untouched.
const oobPassthroughToken = "_"

// oobStep is one entry of an "oob." list: a byte to append to that write (sending it as
// TCP urgent data) or, for oobPassthroughToken, a passthrough that leaves the write as is.
type oobStep struct {
	passthrough bool
	b           byte
}

// parseOOBDialMode reads the list (one entry per leading write) from an "oob." dialMode: a
// byte 0..255 to append and mark urgent, or oobPassthroughToken to leave that write as is.
func parseOOBDialMode(dialMode string) ([]oobStep, error) {
	list := dialMode[len(oobDialModePrefix):]
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
