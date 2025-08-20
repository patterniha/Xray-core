package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport/internet"
)

func TestFreedomConfig(t *testing.T) {
	creator := func() Buildable {
		return new(FreedomConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"domainStrategy": "AsIs",
				"redirect": "127.0.0.1:3366",
				"userLevel": 1
			}`,
			Parser: loadJSON(creator),
			Output: &freedom.Config{
				DomainStrategy: internet.DomainStrategy_AS_IS,
				DestinationOverride: &freedom.DestinationOverride{
					Server: &protocol.ServerEndpoint{
						Address: &net.IPOrDomain{
							Address: &net.IPOrDomain_Ip{
								Ip: []byte{127, 0, 0, 1},
							},
						},
						Port: 3366,
					},
				},
				UserLevel: 1,
			},
		},
	})
}

func TestFakeQUICNoise(t *testing.T) {
	// Test parsing fake_quic noise type
	noise := &Noise{
		Type:   "fake_quic",
		Packet: "100",  // size parameter
	}
	
	parsed, err := ParseNoise(noise)
	if err != nil {
		t.Errorf("Failed to parse fake_quic noise: %v", err)
	}
	
	if parsed.Packet == nil {
		t.Error("fake_quic noise packet is nil")
	}
	
	if len(parsed.Packet) != 100 {
		t.Errorf("Expected fake_quic packet length 100, got %d", len(parsed.Packet))
	}
	
	// Test range parsing (min-max format)
	noiseRange := &Noise{
		Type:   "fake_quic", 
		Packet: "50-150", // range format
	}
	
	parsedRange, err := ParseNoise(noiseRange)
	if err != nil {
		t.Errorf("Failed to parse fake_quic noise with range: %v", err)
	}
	
	// Should use the max value (150)
	if len(parsedRange.Packet) != 150 {
		t.Errorf("Expected fake_quic packet length 150 for range, got %d", len(parsedRange.Packet))
	}
	
	// Test minimum size enforcement
	noise2 := &Noise{
		Type:   "fake_quic",
		Packet: "10", // smaller than minimum
	}
	
	parsed2, err := ParseNoise(noise2)
	if err != nil {
		t.Errorf("Failed to parse fake_quic noise with small size: %v", err)
	}
	
	if len(parsed2.Packet) < 20 {
		t.Errorf("Expected minimum fake_quic packet length 20, got %d", len(parsed2.Packet))
	}
	
	// Test default size when no packet parameter is provided
	noise3 := &Noise{
		Type:   "fake_quic",
		Packet: "", // no size specified
	}
	
	parsed3, err := ParseNoise(noise3)
	if err != nil {
		t.Errorf("Failed to parse fake_quic noise with default size: %v", err)
	}
	
	if len(parsed3.Packet) != 100 {
		t.Errorf("Expected default fake_quic packet length 100, got %d", len(parsed3.Packet))
	}
}
