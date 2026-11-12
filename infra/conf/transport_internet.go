package conf

import (
	"context"
	"slices"
	"strings"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type TransportProtocol string

// Build implements Buildable.
func (p TransportProtocol) Build() (string, error) {
	switch strings.ToLower(string(p)) {
	case "raw", "tcp":
		return "tcp", nil
	case "xhttp", "splithttp":
		return "splithttp", nil
	case "kcp", "mkcp":
		return "mkcp", nil
	case "grpc":
		errors.PrintNonRemovalDeprecatedFeatureWarning("gRPC transport (with unnecessary costs, etc.)", "XHTTP stream-up H2")
		return "grpc", nil
	case "ws", "websocket":
		errors.PrintNonRemovalDeprecatedFeatureWarning("WebSocket transport (with ALPN http/1.1, etc.)", "XHTTP H2 & H3")
		return "websocket", nil
	case "httpupgrade":
		errors.PrintNonRemovalDeprecatedFeatureWarning("HTTPUpgrade transport (with ALPN http/1.1, etc.)", "XHTTP H2 & H3")
		return "httpupgrade", nil
	case "h2", "h3", "http":
		return "", errors.PrintRemovedFeatureError("HTTP transport (without header padding, etc.)", "XHTTP stream-one H2 & H3")
	case "quic":
		return "", errors.PrintRemovedFeatureError("QUIC transport (without web service, etc.)", "XHTTP stream-one H3")
	case "hysteria":
		return "hysteria", nil
	case "masque":
		return "masque", nil
	case "xdrive":
		return "xdrive", nil
	default:
		return "", errors.New("Config: unknown transport protocol: ", p)
	}
}

type StreamConfig struct {
	Address             *Address           `json:"address"`
	Port                uint16             `json:"port"`
	Method              *TransportProtocol `json:"method"`
	Network             *TransportProtocol `json:"network"`
	Security            string             `json:"security"`
	FinalMask           *FinalMask         `json:"finalmask"`
	TLSSettings         *TLSConfig         `json:"tlsSettings"`
	REALITYSettings     *REALITYConfig     `json:"realitySettings"`
	RAWSettings         *TCPConfig         `json:"rawSettings"`
	TCPSettings         *TCPConfig         `json:"tcpSettings"`
	XHTTPSettings       *SplitHTTPConfig   `json:"xhttpSettings"`
	SplitHTTPSettings   *SplitHTTPConfig   `json:"splithttpSettings"`
	KCPSettings         *KCPConfig         `json:"kcpSettings"`
	GRPCSettings        *GRPCConfig        `json:"grpcSettings"`
	WSSettings          *WebSocketConfig   `json:"wsSettings"`
	HTTPUPGRADESettings *HttpUpgradeConfig `json:"httpupgradeSettings"`
	HysteriaSettings    *HysteriaConfig    `json:"hysteriaSettings"`
	MASQUESettings      *MasqueConfig      `json:"masqueSettings"`
	XDRIVESettings      *XDriveConfig      `json:"xdriveSettings"`
	SocketSettings      *SocketConfig      `json:"sockopt"`
}

// Build implements Buildable.
func (c *StreamConfig) Build() (*internet.StreamConfig, error) {
	config := &internet.StreamConfig{
		Port:         uint32(c.Port),
		ProtocolName: "tcp",
	}
	if c.Address != nil {
		config.Address = c.Address.Build()
	}
	if c.Method != nil {
		c.Network = c.Method
	}
	if c.Network != nil {
		protocol, err := c.Network.Build()
		if err != nil {
			return nil, err
		}
		config.ProtocolName = protocol
	}

	var xdriveH3 bool
	switch strings.ToLower(c.Security) {
	case "", "none":
	case "tls":
		tlsSettings := c.TLSSettings
		if tlsSettings == nil {
			tlsSettings = &TLSConfig{}
		}
		ts, err := tlsSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build TLS config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
		xdriveH3 = config.ProtocolName == "xdrive" && tlsSettings.ALPN != nil && slices.Equal(*tlsSettings.ALPN, StringList{"h3"})
		if config.ProtocolName == "xdrive" && tlsSettings.ALPN != nil && slices.Equal(*tlsSettings.ALPN, StringList{"http/1.1"}) && tlsSettings.ECHConfigList == "" {
			// a fingerprint puts its own ALPN into the hello, except Go TLS and the
			// randomized ones, which take it from the config or send none
			if fp := tls.GetFingerprint(strings.ToLower(tlsSettings.Fingerprint)); fp != nil && fp.Client != utls.HelloGolang.Client &&
				!strings.HasPrefix(fp.Client, utls.HelloRandomized.Client) {
				errors.LogWarning(context.Background(), `XDRIVE: "alpn" ["http/1.1"] reaches the wire only inside ECH, without "echConfigList" the hello carries the ALPN of the fingerprint and the server may pick h2`)
			}
		}
	case "reality":
		if config.ProtocolName != "tcp" && config.ProtocolName != "splithttp" && config.ProtocolName != "grpc" {
			return nil, errors.New("REALITY only supports RAW, XHTTP and gRPC for now.")
		}
		if c.REALITYSettings == nil {
			return nil, errors.New(`REALITY: Empty "realitySettings".`)
		}
		ts, err := c.REALITYSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build REALITY config.").Base(err)
		}
		tm := serial.ToTypedMessage(ts)
		config.SecuritySettings = append(config.SecuritySettings, tm)
		config.SecurityType = tm.Type
	case "xtls":
		return nil, errors.PrintRemovedFeatureError(`Legacy XTLS`, `xtls-rprx-vision with TLS or REALITY`)
	default:
		return nil, errors.New(`Unknown security "` + c.Security + `".`)
	}

	if c.RAWSettings != nil {
		c.TCPSettings = c.RAWSettings
	}
	if c.TCPSettings != nil {
		ts, err := c.TCPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build RAW config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "tcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.XHTTPSettings != nil {
		c.SplitHTTPSettings = c.XHTTPSettings
	}
	if c.SplitHTTPSettings != nil {
		hs, err := c.SplitHTTPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build XHTTP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "splithttp",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.KCPSettings != nil {
		ts, err := c.KCPSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build mKCP config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "mkcp",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.GRPCSettings != nil {
		gs, err := c.GRPCSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build gRPC config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "grpc",
			Settings:     serial.ToTypedMessage(gs),
		})
	}
	if c.WSSettings != nil {
		ts, err := c.WSSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build WebSocket config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "websocket",
			Settings:     serial.ToTypedMessage(ts),
		})
	}
	if c.HTTPUPGRADESettings != nil {
		hs, err := c.HTTPUPGRADESettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build HTTPUpgrade config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "httpupgrade",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.HysteriaSettings != nil {
		hs, err := c.HysteriaSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build Hysteria config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "hysteria",
			Settings:     serial.ToTypedMessage(hs),
		})
	}
	if c.MASQUESettings != nil {
		ms, err := c.MASQUESettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build MASQUE config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "masque",
			Settings:     serial.ToTypedMessage(ms),
		})
	}
	if c.XDRIVESettings != nil {
		c.XDRIVESettings.h3 = xdriveH3
		xs, err := c.XDRIVESettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build XDRIVE config.").Base(err)
		}
		config.TransportSettings = append(config.TransportSettings, &internet.TransportConfig{
			ProtocolName: "xdrive",
			Settings:     serial.ToTypedMessage(xs),
		})
	}
	if c.SocketSettings != nil {
		ss, err := c.SocketSettings.Build()
		if err != nil {
			return nil, errors.New("Failed to build sockopt.").Base(err)
		}
		config.SocketSettings = ss
	}

	if c.FinalMask != nil {
		// "tcp4"/"tcp6" (and "udp4"/"udp6") are the family-specific forms of "tcp"
		// ("udp"); mixing a generic list with its family forms is ambiguous.
		if len(c.FinalMask.Tcp) > 0 && (len(c.FinalMask.Tcp4) > 0 || len(c.FinalMask.Tcp6) > 0) {
			return nil, errors.New(`finalmask: "tcp" can't be combined with "tcp4"/"tcp6"`)
		}
		if len(c.FinalMask.Udp) > 0 && (len(c.FinalMask.Udp4) > 0 || len(c.FinalMask.Udp6) > 0) {
			return nil, errors.New(`finalmask: "udp" can't be combined with "udp4"/"udp6"`)
		}
		buildTcp := func(masks []Mask) ([]*serial.TypedMessage, error) {
			var out []*serial.TypedMessage
			for _, mask := range masks {
				proto, err := mask.Build(true)
				if err != nil {
					return nil, errors.New("failed to build mask with type ", mask.Type).Base(err)
				}
				out = append(out, serial.ToTypedMessage(proto))
			}
			return out, nil
		}
		buildUdp := func(masks []Mask) ([]*serial.TypedMessage, error) {
			var out []*serial.TypedMessage
			for _, mask := range masks {
				proto, err := mask.Build(false)
				if err != nil {
					return nil, errors.New("failed to build mask with type ", mask.Type).Base(err)
				}
				out = append(out, serial.ToTypedMessage(proto))
			}
			return out, nil
		}
		var err error
		if config.Tcpmasks, err = buildTcp(c.FinalMask.Tcp); err != nil {
			return nil, err
		}
		if config.Tcp4Masks, err = buildTcp(c.FinalMask.Tcp4); err != nil {
			return nil, err
		}
		if config.Tcp6Masks, err = buildTcp(c.FinalMask.Tcp6); err != nil {
			return nil, err
		}
		if config.Udpmasks, err = buildUdp(c.FinalMask.Udp); err != nil {
			return nil, err
		}
		if config.Udp4Masks, err = buildUdp(c.FinalMask.Udp4); err != nil {
			return nil, err
		}
		if config.Udp6Masks, err = buildUdp(c.FinalMask.Udp6); err != nil {
			return nil, err
		}
		if c.FinalMask.QuicParams != nil {
			proto, err := c.FinalMask.QuicParams.Build()
			if err != nil {
				return nil, err
			}
			config.QuicParams = proto.(*internet.QuicParams)
		}
	}

	if xdriveH3 && c.FinalMask != nil {
		if c.XDRIVESettings != nil && c.XDRIVESettings.Service == "google-drive" {
			// noise only sends datagrams of its own ahead of the QUIC ones, the
			// other masks change those or need a peer that undoes them
			for _, masks := range [][]Mask{c.FinalMask.Udp, c.FinalMask.Udp4, c.FinalMask.Udp6} {
				for _, mask := range masks {
					if strings.ToLower(mask.Type) != "noise" {
						return nil, errors.New(`XDRIVE: over h3 to Google Drive the only "udp" mask that works is "noise", not "`, mask.Type, `"`)
					}
				}
			}
		}
		if config.QuicParams != nil && (config.QuicParams.Congestion == "brutal" || config.QuicParams.Congestion == "force-brutal") {
			return nil, errors.New(`XDRIVE: brutal is for Hysteria servers, over h3 "congestion" is "bbr" or "reno", not "`, config.QuicParams.Congestion, `"`)
		}
	}

	return config, nil
}
