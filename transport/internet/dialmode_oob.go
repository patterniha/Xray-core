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
// first three writes.
const oobDialModePrefix = "oob."

// parseOOBDialMode reads the byte list (one per leading write) from an "oob." dialMode.
func parseOOBDialMode(dialMode string) ([]byte, error) {
	list := dialMode[len(oobDialModePrefix):]
	if list == "" {
		return nil, errors.New("invalid dialMode: ", dialMode)
	}
	parts := strings.Split(list, ",")
	oobBytes := make([]byte, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return nil, errors.New("invalid dialMode: ", dialMode)
		}
		oobBytes = append(oobBytes, byte(n))
	}
	return oobBytes, nil
}
