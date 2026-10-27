//go:build unix

package internet

import "golang.org/x/sys/unix"

// sendOOB sends b on the connected socket fd with the TCP urgent (MSG_OOB) flag.
// unix.Send reports no byte count, so a nil error means the whole buffer was sent.
func sendOOB(fd uintptr, b []byte) (int, error) {
	if err := unix.Send(int(fd), b, unix.MSG_OOB); err != nil {
		return 0, err
	}
	return len(b), nil
}
