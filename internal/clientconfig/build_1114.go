package clientconfig

// Build1114 生成 client_1.11.4.json：DNS/Inbounds/Experimental 是那个版本
// 专属的旧版 schema，AnyTLS 不支持所以不含 anytls 出站，但路由规则、
// rule_set 列表（走 download_detour 而不是 http_client）、CF 隧道节点、
// 共享的 7 个协议出站都还在。
func Build1114(p Params, randHex func() string) *Config {
	cfObs, cfTags := cfOutbounds(p, randHex)

	outbounds := groupOutbounds(p, false, cfTags)
	outbounds = append(outbounds, RegionalURLTestOutbounds()...)
	outbounds = append(outbounds, sharedProtocolOutbounds(p)...)
	outbounds = append(outbounds, cfObs...)

	dns := Legacy1114DNS{
		Servers: []Legacy1114DNSServer{
			{Tag: "解析223555_469138946ba5fa", Address: "223.5.5.5"},
			{Tag: "解析ALIDNS_469138946ba5fa", AddressResolver: "解析223555_469138946ba5fa", Address: "https://dns.alidns.com/dns-query"},
			{Tag: "解析CLOUDFLAREDNS_469138946ba5fa", Detour: "代理_469138946ba5fa", AddressResolver: "解析223555_469138946ba5fa", Address: "https://cloudflare-dns.com/dns-query"},
			{Tag: "dns_block", Address: "rcode://name_error"},
		},
		Rules: []Legacy1114DNSRule{
			{RuleSet: "geosite-duolingo", Server: "解析CLOUDFLAREDNS_469138946ba5fa"},
			{RuleSet: []string{"geosite-category-ads-all", "megamori"}, Server: "dns_block", DisableCache: true},
			{Domain: adDomainsAny(), Server: "dns_block", DisableCache: true},
			{RuleSet: "category-ai-!cn", Server: "解析CLOUDFLAREDNS_469138946ba5fa"}, // 原为 geosite-openai → overseas-ai → category-ai-!cn
			{RuleSet: []string{"geosite-private", "geoip-cn"}, Server: "解析ALIDNS_469138946ba5fa"},
			{RuleSet: "geosite-geolocation-!cn", Server: "解析CLOUDFLAREDNS_469138946ba5fa"},
		},
		Final: "解析CLOUDFLAREDNS_469138946ba5fa", IndependentCache: true,
	}

	inbounds := []any{
		MixedInbound{Type: "mixed", Tag: "混合入站_469138946ba5fa", Listen: "127.0.0.1", ListenPort: 7890},
		TunInbound{
			Type: "tun", Tag: "TUN入站_469138946ba5fa",
			AutoRoute: true, StrictRoute: false, Stack: "system",
			Address:                []string{"172.19.0.1/28", "fdfe:dcba:9876::1/126"},
			Platform:               TunPlatform{HTTPProxy: HTTPProxyPlatform{Enabled: true, Server: "127.0.0.1", ServerPort: 7890}},
			EndpointIndependentNat: true,
		},
	}

	return &Config{
		Log:         LogConfig{Level: "warn", Timestamp: true},
		DNS:         dns,
		NTP:         NTPConfig{Enabled: true, Interval: "30m0s", Server: "ntp.aliyun.com", ServerPort: 123},
		HTTPClients: nil, // 1.11.4 完全没有 http_clients 这个 key
		Inbounds:    inbounds,
		Outbounds:   outbounds,
		Route: RouteConfig{
			Rules:               buildRouteRules(true), // 1.11.4 也带 geosite-private 直连规则
			RuleSet:             legacy1114RouteRuleSets(),
			Final:               "代理_469138946ba5fa",
			AutoDetectInterface: true,
			// 没有 default_domain_resolver / default_http_client，这两个 1.11.4 时代还不存在
		},
		Experimental: Experimental{
			CacheFile: CacheFile{Enabled: true, Path: "sing-box-cache.db", StoreRDRC: true},
			ClashAPI: ClashAPI{ExternalController: "127.0.0.1:9999", ExternalUI: "ui",
				ExternalUIDownloadURL:    "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip",
				ExternalUIDownloadDetour: "代理_469138946ba5fa"},
		},
	}
}
