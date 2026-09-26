package tls

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

func TestECHDial(t *testing.T) {
	config := &Config{
		ServerName:    "cloudflare.com",
		EchConfigList: "encryptedsni.com+udp://1.1.1.1",
	}
	// test concurrent Dial(to test cache problem)
	wg := sync.WaitGroup{}
	for range 10 {
		wg.Go(func() {
			TLSConfig := config.GetTLSConfig()
			TLSConfig.NextProtos = []string{"http/1.1"}
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: TLSConfig,
				},
			}
			resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
			common.Must(err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			common.Must(err)
			if !strings.Contains(string(body), "sni=encrypted") {
				t.Error("ECH Dial success but SNI is not encrypted")
			}
		})
	}
	wg.Wait()
	// check cache
	echConfigCache, ok := GlobalECHConfigCache.Load(ECHCacheKey("udp://1.1.1.1", "encryptedsni.com", nil))
	if !ok {
		t.Error("ECH config cache not found")
	}
	ok = echConfigCache.UpdateLock.TryLock()
	if !ok {
		t.Error("ECH config cache dead lock detected")
	}
	echConfigCache.UpdateLock.Unlock()
	configRecord := echConfigCache.configRecord.Load()
	if configRecord == nil {
		t.Error("ECH config record not found in cache")
	}
}

func TestECHDialFail(t *testing.T) {
	config := &Config{
		ServerName:    "cloudflare.com",
		EchConfigList: "udp://0.0.0.0",
	}
	tlsConfig := config.GetTLSConfig()
	ApplyECH(context.Background(), config, tlsConfig)
	if !slices.Equal(tlsConfig.EncryptedClientHelloConfigList, []byte{1, 1, 4, 5, 1, 4}) {
		t.Error("ECH config should be invalid when query failed", " but got ", tlsConfig.EncryptedClientHelloConfigList)
	}
}

// echQueryOutbound is an outbound tagged "ech-out" that answers the ECH config query it gets over UDP
// with an HTTPS record carrying echConfig.
type echQueryOutbound struct {
	echConfig []byte
	queried   atomic.Bool
}

func (o *echQueryOutbound) Start() error                         { return nil }
func (o *echQueryOutbound) Close() error                         { return nil }
func (o *echQueryOutbound) Tag() string                          { return "ech-out" }
func (o *echQueryOutbound) SenderSettings() *serial.TypedMessage { return nil }
func (o *echQueryOutbound) ProxySettings() *serial.TypedMessage  { return nil }

func (o *echQueryOutbound) Dispatch(ctx context.Context, link *transport.Link) {
	o.queried.Store(true)
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return
	}
	query := make([]byte, mb.Len())
	mb.Copy(query)
	buf.ReleaseMulti(mb)
	request := new(dns.Msg)
	if err := request.Unpack(query); err != nil || len(request.Question) == 0 {
		return
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = append(response.Answer, &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
		Priority: 1,
		Target:   ".",
		Value:    []dns.SVCBKeyValue{&dns.SVCBECHConfig{ECH: o.echConfig}},
	}})
	packed, err := response.Pack()
	if err != nil {
		return
	}
	link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(packed)})
}

// echQueryOutbounds is the outbound manager of an instance whose only outbound is handler.
type echQueryOutbounds struct {
	handler outbound.Handler
}

func (m *echQueryOutbounds) Type() interface{} { return outbound.ManagerType() }
func (m *echQueryOutbounds) Start() error      { return nil }
func (m *echQueryOutbounds) Close() error      { return nil }

func (m *echQueryOutbounds) GetHandler(tag string) outbound.Handler {
	if tag == m.handler.Tag() {
		return m.handler
	}
	return nil
}

func (m *echQueryOutbounds) GetDefaultHandler() outbound.Handler { return m.handler }

func (m *echQueryOutbounds) AddHandler(ctx context.Context, handler outbound.Handler) error {
	return nil
}

func (m *echQueryOutbounds) RemoveHandler(ctx context.Context, tag string) error { return nil }

func (m *echQueryOutbounds) ListHandlers(ctx context.Context) []outbound.Handler {
	return []outbound.Handler{m.handler}
}

func TestECHQueryThroughDialerProxyOfTheDial(t *testing.T) {
	// The ECH config query goes through the echSockopt dialerProxy of the instance that the dial belongs
	// to, whose outbound manager the context of the dial carries, even when another instance was created
	// after it. A context without one keeps using the instance created last.
	own := &echQueryOutbound{echConfig: []byte{1, 2, 3, 4}}
	last := &echQueryOutbound{echConfig: []byte{5, 6, 7, 8}}
	internet.InitSystemDialer(nil, &echQueryOutbounds{handler: last})
	defer internet.InitSystemDialer(nil, nil)

	// a new config each time: the ECH config cache is kept per echSockopt
	newConfig := func() *Config {
		return &Config{
			ServerName:        "ech.example",
			EchConfigList:     "ech.example+udp://192.0.2.1",
			EchSocketSettings: &internet.SocketConfig{DialerProxy: "ech-out"},
		}
	}
	ctx := internet.ContextWithOutboundManager(context.Background(), &echQueryOutbounds{handler: own})

	if got := newConfig().GetTLSConfigWithContext(ctx).EncryptedClientHelloConfigList; !slices.Equal(got, own.echConfig) {
		t.Error("the ECH config ", got, " did not come through the dialerProxy of the instance of the dial")
	}
	if last.queried.Load() {
		t.Error("the ECH config query went through the dialerProxy of the instance created last")
	}
	if got := newConfig().GetTLSConfig().EncryptedClientHelloConfigList; !slices.Equal(got, last.echConfig) {
		t.Error("without an outbound manager in the context, the ECH config ", got, " did not come through the instance created last")
	}
}
