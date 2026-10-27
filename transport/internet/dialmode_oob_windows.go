//go:build windows

package internet

import "golang.org/x/sys/windows"

// sendOOB sends b on the connected socket fd with the TCP urgent (MSG_OOB) flag.
func sendOOB(fd uintptr, b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	buf := windows.WSABuf{Len: uint32(len(b)), Buf: &b[0]}
	var sent uint32
	err := windows.WSASend(windows.Handle(fd), &buf, 1, &sent, windows.MSG_OOB, nil, nil)
	return int(sent), err
}
