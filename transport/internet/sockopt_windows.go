package internet

import (
	"context"
	"encoding/binary"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/windows"
)

// tcpKeepAlivePerSocketSupported reports whether this Windows build supports the
// per-socket TCP_KEEPIDLE/TCP_KEEPINTVL/TCP_KEEPCNT options, which were added in
// Windows 10, version 1709 (build 16299). On older builds (e.g. Windows Server
// 2016) only SO_KEEPALIVE can be toggled and the probe count is not settable.
var tcpKeepAlivePerSocketSupported = sync.OnceValue(func() bool {
	_, _, build := windows.RtlGetNtVersionNumbers()
	return build >= 16299
})

// tcpMaxRtSupported reports whether this Windows build supports TCP_MAXRTMS, the
// equivalent of Linux TCP_USER_TIMEOUT, added in Windows 8 / Server 2012 (build
// 9200). On older builds (e.g. Windows 7) the connection timeout is left at the
// OS default.
var tcpMaxRtSupported = sync.OnceValue(func() bool {
	_, _, build := windows.RtlGetNtVersionNumbers()
	return build >= 9200
})

// tcpMaxRtMs is the TCP_MAXRTMS value for a tcpUserTimeout of ms milliseconds.
// Windows refuses anything below 20 (WSAEINVAL), so 1-19 are raised to 20, the
// shortest timeout it takes.
func tcpMaxRtMs(ms int32) int {
	return max(int(ms), 20)
}

const (
	TCP_FASTOPEN    = 15
	IP_UNICAST_IF   = 31
	IPV6_UNICAST_IF = 31
)

func setTFO(fd syscall.Handle, tfo int) error {
	if tfo > 0 {
		tfo = 1
	}
	if tfo >= 0 {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_FASTOPEN, tfo); err != nil {
			return err
		}
	}
	return nil
}

func applyOutboundSocketOptions(network string, address string, fd uintptr, config *SocketConfig) error {
	if config.Interface != "" {
		inf, err := net.InterfaceByName(config.Interface)
		if err != nil {
			return NewBindError(errors.New("failed to find the interface").Base(err))
		}
		// easy way to check if the address is ipv4
		isV4 := strings.Contains(address, ".")
		// note: DO NOT trust the passed network variable, it can be udp6 even if the address is ipv4
		// because operating system might(always) use ipv6 socket to process ipv4
		host, _, err := net.SplitHostPort(address)
		if isV4 {
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], uint32(inf.Index))
			idx := *(*uint32)(unsafe.Pointer(&bytes[0]))
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, IP_UNICAST_IF, int(idx)); err != nil {
				return NewBindError(errors.New("failed to set IP_UNICAST_IF").Base(err))
			}
			if ip := net.ParseIP(host); ip != nil && ip.IsMulticast() && isUDPSocket(network) {
				if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, int(idx)); err != nil {
					return NewBindError(errors.New("failed to set IP_MULTICAST_IF").Base(err))
				}
			}
		} else {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, IPV6_UNICAST_IF, inf.Index); err != nil {
				return NewBindError(errors.New("failed to set IPV6_UNICAST_IF").Base(err))
			}
			if ip := net.ParseIP(host); ip != nil && ip.IsMulticast() && isUDPSocket(network) {
				if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, inf.Index); err != nil {
					return NewBindError(errors.New("failed to set IPV6_MULTICAST_IF").Base(err))
				}
			}
		}
	}

	if isTCPSocket(network) {
		if err := setTFO(syscall.Handle(fd), config.ParseTFOValue()); err != nil {
			return err
		}
		if config.TcpKeepAliveIdle > 0 {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
				return errors.New("failed to set SO_KEEPALIVE", err)
			}
		} else if config.TcpKeepAliveIdle < 0 {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 0); err != nil {
				return errors.New("failed to unset SO_KEEPALIVE", err)
			}
		}

		if config.TcpUserTimeout > 0 && tcpMaxRtSupported() {
			// TCP_MAXRTMS (milliseconds) is the Windows equivalent of Linux
			// TCP_USER_TIMEOUT: abort the connection after this long with
			// unacknowledged data. Skipped (OS default) on builds older than
			// Windows 8 / Server 2012.
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, windows.TCP_MAXRTMS, tcpMaxRtMs(config.TcpUserTimeout)); err != nil {
				return errors.New("failed to set TCP_MAXRTMS", err)
			}
		}
	}

	if len(config.CustomSockopt) > 0 {
		for _, custom := range config.CustomSockopt {
			if custom.System != "" && custom.System != runtime.GOOS {
				errors.LogDebug(context.Background(), "CustomSockopt system not match: ", "want ", custom.System, " got ", runtime.GOOS)
				continue
			}
			// Skip unwanted network type
			// network might be tcp4 or tcp6
			// use HasPrefix so that "tcp" can match tcp4/6 with "tcp" if user want to control all tcp (udp is also the same)
			// if it is empty, strings.HasPrefix will always return true to make it apply for all networks
			if !strings.HasPrefix(network, custom.Network) {
				continue
			}
			level := 0x6 // default TCP
			var opt int
			if len(custom.Opt) == 0 {
				return errors.New("No opt!")
			} else {
				opt, _ = strconv.Atoi(custom.Opt)
			}
			if custom.Level != "" {
				level, _ = strconv.Atoi(custom.Level)
			}
			if custom.Type == "int" {
				value, _ := strconv.Atoi(custom.Value)
				if err := syscall.SetsockoptInt(syscall.Handle(fd), level, opt, value); err != nil {
					return errors.New("failed to set CustomSockoptInt", opt, value, err)
				}
			} else if custom.Type == "str" {
				return errors.New("failed to set CustomSockoptString: Str type does not supported on windows")
			} else {
				return errors.New("unknown CustomSockopt type:", custom.Type)
			}
		}
	}

	return nil
}

func applyInboundSocketOptions(network string, fd uintptr, config *SocketConfig) error {
	if isTCPSocket(network) {
		if err := setTFO(syscall.Handle(fd), config.ParseTFOValue()); err != nil {
			return err
		}
		if config.TcpKeepAliveIdle > 0 || config.TcpKeepAliveInterval > 0 || config.TcpKeepAliveCount > 0 {
			// TCP_KEEPIDLE/TCP_KEEPINTVL/TCP_KEEPCNT are per-socket options since
			// Windows 10, version 1709. On older builds we still enable SO_KEEPALIVE
			// (unchanged behaviour), but the probe count stays the OS default.
			if tcpKeepAlivePerSocketSupported() {
				if config.TcpKeepAliveIdle > 0 {
					if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, windows.TCP_KEEPIDLE, int(config.TcpKeepAliveIdle)); err != nil {
						return errors.New("failed to set TCP_KEEPIDLE", err)
					}
				}
				if config.TcpKeepAliveInterval > 0 {
					if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, windows.TCP_KEEPINTVL, int(config.TcpKeepAliveInterval)); err != nil {
						return errors.New("failed to set TCP_KEEPINTVL", err)
					}
				}
				if config.TcpKeepAliveCount > 0 {
					if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, windows.TCP_KEEPCNT, int(config.TcpKeepAliveCount)); err != nil {
						return errors.New("failed to set TCP_KEEPCNT", err)
					}
				}
			}
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
				return errors.New("failed to set SO_KEEPALIVE", err)
			}
		} else if config.TcpKeepAliveInterval < 0 || config.TcpKeepAliveIdle < 0 {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 0); err != nil {
				return errors.New("failed to unset SO_KEEPALIVE", err)
			}
		}

		if config.TcpUserTimeout > 0 && tcpMaxRtSupported() {
			// TCP_MAXRTMS (milliseconds) is the Windows equivalent of Linux
			// TCP_USER_TIMEOUT: abort the connection after this long with
			// unacknowledged data. Skipped (OS default) on builds older than
			// Windows 8 / Server 2012.
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, windows.TCP_MAXRTMS, tcpMaxRtMs(config.TcpUserTimeout)); err != nil {
				return errors.New("failed to set TCP_MAXRTMS", err)
			}
		}
	}

	if config.V6Only {
		if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1); err != nil {
			return errors.New("failed to set IPV6_V6ONLY").Base(err)
		}
	}

	if len(config.CustomSockopt) > 0 {
		for _, custom := range config.CustomSockopt {
			if custom.System != "" && custom.System != runtime.GOOS {
				errors.LogDebug(context.Background(), "CustomSockopt system not match: ", "want ", custom.System, " got ", runtime.GOOS)
				continue
			}
			// Skip unwanted network type
			// network might be tcp4 or tcp6
			// use HasPrefix so that "tcp" can match tcp4/6 with "tcp" if user want to control all tcp (udp is also the same)
			// if it is empty, strings.HasPrefix will always return true to make it apply for all networks
			if !strings.HasPrefix(network, custom.Network) {
				continue
			}
			level := 0x6 // default TCP
			var opt int
			if len(custom.Opt) == 0 {
				return errors.New("No opt!")
			} else {
				opt, _ = strconv.Atoi(custom.Opt)
			}
			if custom.Level != "" {
				level, _ = strconv.Atoi(custom.Level)
			}
			if custom.Type == "int" {
				value, _ := strconv.Atoi(custom.Value)
				if err := syscall.SetsockoptInt(syscall.Handle(fd), level, opt, value); err != nil {
					return errors.New("failed to set CustomSockoptInt", opt, value, err)
				}
			} else if custom.Type == "str" {
				return errors.New("failed to set CustomSockoptString: Str type does not supported on windows")
			} else {
				return errors.New("unknown CustomSockopt type:", custom.Type)
			}
		}
	}

	return nil
}

func setReuseAddr(fd uintptr) error {
	return nil
}

func setReusePort(fd uintptr) error {
	return nil
}
