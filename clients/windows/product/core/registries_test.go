package main

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"testing"
)

func TestProductRegistryConfigurationSurface(t *testing.T) {
	for _, carrier := range []string{nativeType, quicType, relayType} {
		body := `{"inbounds":[{"type":"socks","tag":"probe","users":[{"username":"service","password":"synthetic"}]},{"type":"tun","tag":"device","stack":"mixed","auto_route":true,"strict_route":true}],"dns":{"servers":[{"type":"udp","server":"1.1.1.1","detour":"wg"}]},"endpoints":[{"type":"wireguard","tag":"wg","system":false,"address":["10.77.0.2/32","fd77::2/128"]}],"outbounds":[{"type":"direct","tag":"uu-direct"},{"type":"` + carrier + `","tag":"carrier"}]}`
		config, err := json.UnmarshalExtendedContext[option.Options](productContext(), []byte(body))
		if err != nil {
			t.Fatalf("carrier %s rejected: %v", carrier, err)
		}
		if len(config.Inbounds) != 2 || len(config.Endpoints) != 1 || len(config.Outbounds) != 2 {
			t.Fatal("incomplete config")
		}
	}
	for _, typ := range []string{"vmess", "shadowsocks", "trojan"} {
		if _, err := json.UnmarshalExtendedContext[option.Options](productContext(), []byte(`{"outbounds":[{"type":"`+typ+`"}]}`)); err == nil {
			t.Fatalf("unused %s registered", typ)
		}
	}
}
