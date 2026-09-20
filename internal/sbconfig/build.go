package sbconfig

// ServerParams 是构建服务端 config.json 需要的全部输入值，对应原脚本里那一大
// 堆全局变量（BEST_DOMAIN / REALITY_PRIVATE_KEY / 各协议端口和 UUID/密码 等）。
// 调用方（后续会补的 main 编排逻辑）负责用 randgen/certgen/端口探测/域名探测
// 几个包把这些值准备好，这个包只管"给定这些值，拼出合法的 config.json"。
type ServerParams struct {
	BestDomain string // Reality 伪装域名，同时也是自签证书的 CN/SAN

	RealityPrivateKey string
	ShortIDsVLESS     []string
	ShortIDsTrojan    []string
	ShortIDsAnyTLS    []string
	ShortIDsVmessReal []string

	PortHysteria2    int
	PortTUIC         int
	PortVLESS        int
	PortTrojan       int
	PortAnyTLS       int
	PortVmessReality int
	PortVmessWSTLS   int
	PortVlessWS      int

	UUIDVLESS        string
	UUIDTUIC         string
	UUIDVmessReality string
	UUIDVmessWSTLS   string
	UUIDVlessWS      string

	PasswordHysteria2 string
	PasswordTUIC      string
	PasswordTrojan    string
	PasswordAnyTLS    string

	HY2ObfsType     string // 固定 "salamander"
	HY2ObfsPassword string

	PaddingScheme []string // anytls 用

	PathVmessWSTLS string
	PathVLESSWS    string

	// 自签证书，hysteria2 / tuic / vmess-ws-tls 三处共用同一份
	CertLines []string
	KeyLines  []string
}

// BuildServerConfig 对应原脚本里那一长串 heredoc 拼 config.json 的逻辑。
func BuildServerConfig(p ServerParams) *Config {
	dns := DNSConfig{
		Servers: []DNSServer{
			{Type: "hosts", Tag: TagHostsDNS, Predefined: dnsHostsPredefined},
			{Type: "https", Tag: TagCloudflareDNS, DomainResolver: TagHostsDNS, Server: "cloudflare-dns.com", Path: "/dns-query"},
			{Type: "https", Tag: TagGoogleDNS, DomainResolver: TagHostsDNS, Server: "dns.google"},
		},
		Rules: []DNSRule{
			{Action: "evaluate", Server: TagHostsDNS},
			{MatchResponse: true, ResponseRcode: "NOERROR", Action: "respond"},
			{RuleSet: []string{"geosite-category-ads-all", "megamori"}, Action: "predefined", Rcode: "NXDOMAIN"},
			{Domain: AdDomains, Action: "predefined", Rcode: "NXDOMAIN"},
		},
		Final: TagCloudflareDNS,
	}

	ntp := NTPConfig{Enabled: true, Interval: "30m0s", Server: "time.cloudflare.com", ServerPort: 123}

	httpClients := []HTTPClient{
		{Tag: TagHTTPDefault},
		{Tag: TagHTTPDirectRoute, Detour: "direct"},
		{Tag: TagHTTPZhiLian, Detour: TagDirect},
		{Tag: TagHTTPDaili, Detour: TagProxy},
	}

	realityFor := func(port int, shortIDs []string) *TLSConfig {
		return &TLSConfig{
			Enabled:    true,
			ServerName: p.BestDomain,
			Reality: &Reality{
				Enabled:    true,
				Handshake:  RealityHandshake{Server: p.BestDomain, ServerPort: 443},
				PrivateKey: p.RealityPrivateKey,
				ShortID:    shortIDs,
			},
		}
	}

	inbounds := []Inbound{
		{
			Type: "hysteria2", Tag: InboundHysteria2, Listen: "::", ListenPort: p.PortHysteria2,
			Users: []User{{Password: p.PasswordHysteria2}},
			Obfs:  &Obfs{Type: p.HY2ObfsType, Password: p.HY2ObfsPassword},
			TLS: &TLSConfig{
				Enabled: true, ServerName: p.BestDomain, ALPN: []string{"h3"},
				Certificate: p.CertLines, Key: p.KeyLines,
			},
		},
		{
			Type: "tuic", Tag: InboundTUIC, Listen: "::", ListenPort: p.PortTUIC,
			Users:             []User{{UUID: p.UUIDTUIC, Password: p.PasswordTUIC}},
			CongestionControl: "bbr",
			TLS: &TLSConfig{
				Enabled: true, ServerName: p.BestDomain, ALPN: []string{"h3"},
				Certificate: p.CertLines, Key: p.KeyLines,
			},
		},
		{
			Type: "vless", Tag: InboundVLESS, Listen: "::", ListenPort: p.PortVLESS,
			Users: []User{{Name: StrPtr(""), UUID: p.UUIDVLESS, Flow: "xtls-rprx-vision"}},
			TLS:   realityFor(p.PortVLESS, p.ShortIDsVLESS),
		},
		{
			Type: "trojan", Tag: InboundTrojan, Listen: "::", ListenPort: p.PortTrojan,
			Users: []User{{Name: StrPtr(""), Password: p.PasswordTrojan}},
			TLS:   realityFor(p.PortTrojan, p.ShortIDsTrojan),
		},
		{
			Type: "anytls", Tag: InboundAnyTLS, Listen: "::", ListenPort: p.PortAnyTLS,
			TLS:           realityFor(p.PortAnyTLS, p.ShortIDsAnyTLS),
			Users:         []User{{Name: StrPtr("anyuser"), Password: p.PasswordAnyTLS}},
			PaddingScheme: p.PaddingScheme,
		},
		{
			Type: "vmess", Tag: InboundVmessReality, Listen: "::", ListenPort: p.PortVmessReality,
			Users: []User{{Name: StrPtr(""), UUID: p.UUIDVmessReality}},
			TLS:   realityFor(p.PortVmessReality, p.ShortIDsVmessReal),
		},
		{
			Type: "vmess", Tag: InboundVmessWSTLS, Listen: "::", ListenPort: p.PortVmessWSTLS,
			Users: []User{{Name: StrPtr(""), UUID: p.UUIDVmessWSTLS}},
			TLS: &TLSConfig{
				Enabled: true, ServerName: p.BestDomain, ALPN: []string{"http/1.1"},
				Certificate: p.CertLines, Key: p.KeyLines,
			},
			Transport: &Transport{
				Type: "ws", Path: p.PathVmessWSTLS,
				Headers:             map[string]string{"Host": p.BestDomain},
				MaxEarlyData:        2560,
				EarlyDataHeaderName: "Sec-WebSocket-Protocol",
			},
		},
		{
			Type: "vless", Tag: InboundVlessWS, Listen: "::", ListenPort: p.PortVlessWS,
			Users: []User{{Name: StrPtr(""), UUID: p.UUIDVlessWS}},
			Transport: &Transport{
				Type: "ws", Path: p.PathVLESSWS,
				MaxEarlyData:        2560,
				EarlyDataHeaderName: "Sec-WebSocket-Protocol",
			},
		},
	}

	outbounds := []Outbound{
		{Type: "direct", Tag: TagDirect},
		{Type: "selector", Tag: TagProxy, Outbounds: []string{TagDirect}},
	}

	route := RouteConfig{
		Rules: []RouteRule{
			{Protocol: "dns", Action: "hijack-dns"},
			{Port: 53, Action: "hijack-dns"},
			{ProcessName: []string{"sing-box.exe", "sing-box", "io.nekohasekai.sfa"}, Outbound: TagProxy},
			{RuleSet: []string{"geosite-category-ads-all", "megamori"}, Action: "reject"},
			{Domain: AdDomains, Action: "reject"},
			{
				Inbound: []string{
					InboundHysteria2, InboundTUIC, InboundVLESS, InboundTrojan,
					InboundAnyTLS, InboundVmessReality, InboundVmessWSTLS, InboundVlessWS,
				},
				Action: "sniff",
			},
		},
		RuleSet:               serverRuleSets,
		Final:                 TagProxy,
		AutoDetectInterface:   true,
		DefaultDomainResolver: TagGoogleDNS,
		DefaultHTTPClient:     TagHTTPDefault,
	}

	return &Config{
		Log:         LogConfig{Level: "info", Timestamp: true},
		DNS:         dns,
		NTP:         ntp,
		HTTPClients: httpClients,
		Inbounds:    inbounds,
		Outbounds:   outbounds,
		Route:       route,
	}
}
