package clientconfig

import "singboxprovision/internal/sbconfig"

// LatestOptions 控制 client.json 和 OpenWrt 变体之间那 5 处差异
// （原脚本 gen_client() 的 6 个参数，除了输出文件名）。
type LatestOptions struct {
	TUNInterfaceName   string // OpenWrt 传 "tun0"，client.json 传空
	MixedListen        string // client.json/1.11.4 用 "0.0.0.0"；这里两个最新版本都用 "0.0.0.0"
	IncludeCF          bool   // 是否拼入 CF 隧道出站节点（client.json 是，OpenWrt 否）
	IncludePrivateRule bool   // 是否加 geosite-private 直连规则（client.json 是，OpenWrt 否）
	IncludeAnyTLS      bool   // 是否包含 AnyTLS 出站（两个最新版本都是 true）
}

func adDomainsAny() []string { return sbconfig.AdDomains }

// buildLatestDNS 对应 gen_client() 里 _D_DNS 的"最新版本"分支。
func buildLatestDNS() DNSConfig {
	return DNSConfig{
		Servers: []DNSServer{
			{Type: "hosts", Tag: "解析HOSTS_469138946ba5fa", Predefined: clientDNSHostsPredefined},
			{Type: "https", Tag: "解析ALIDNS_469138946ba5fa", DomainResolver: "解析HOSTS_469138946ba5fa", Server: "dns.alidns.com", Path: "/dns-query"},
			{Type: "https", Tag: "解析DOH_469138946ba5fa", DomainResolver: "解析HOSTS_469138946ba5fa", Server: "doh.pub", Path: "/dns-query"},
			{Type: "https", Tag: "解析CLOUDFLAREDNS_469138946ba5fa", Detour: "代理_469138946ba5fa", DomainResolver: "解析HOSTS_469138946ba5fa", Server: "cloudflare-dns.com", Path: "/dns-query"},
			{Type: "https", Tag: "解析GOOGLE_469138946ba5fa", Detour: "代理_469138946ba5fa", DomainResolver: "解析HOSTS_469138946ba5fa", Server: "dns.google", Path: "/dns-query"},
			{Type: "fakeip", Tag: "解析FAKEIP_469138946ba5fa", Inet4Range: "198.18.0.0/15", Inet6Range: "fc00::/18"},
		},
		Rules: []DNSRule{
			{Action: "evaluate", Server: "解析HOSTS_469138946ba5fa"},
			{MatchResponse: true, ResponseRcode: "NOERROR", Action: "respond"},
			{RuleSet: []string{"geosite-category-ads-all", "megamori"}, Action: "predefined", Rcode: "NXDOMAIN"},
			{Domain: adDomainsAny(), Action: "predefined", Rcode: "NXDOMAIN"},
			{RuleSet: []string{"geosite-private", "geosite-cn"}, Server: "解析ALIDNS_469138946ba5fa"},
			{RuleSet: "geosite-duolingo", Server: "解析CLOUDFLAREDNS_469138946ba5fa"},
			{RuleSet: "category-ai-!cn", Server: "解析CLOUDFLAREDNS_469138946ba5fa"}, // 原为 geosite-openai → overseas-ai → category-ai-!cn
			{RuleSet: "geosite-geolocation-!cn", Server: "解析CLOUDFLAREDNS_469138946ba5fa"},
			{QueryType: []string{"A", "AAAA"}, Server: "解析FAKEIP_469138946ba5fa"},
		},
		Final: "解析CLOUDFLAREDNS_469138946ba5fa", Strategy: "prefer_ipv4",
		ReverseMapping: true, CacheCapacity: 4096,
	}
}

func buildLatestInbounds(opt LatestOptions) []any {
	return []any{
		MixedInbound{Type: "mixed", Tag: "混合入站_469138946ba5fa", Listen: "0.0.0.0", ListenPort: 7890},
		TunInbound{
			Type: "tun", Tag: "TUN入站_469138946ba5fa", InterfaceName: opt.TUNInterfaceName,
			AutoRoute: true, StrictRoute: false,
			Address:                []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			Platform:               TunPlatform{HTTPProxy: HTTPProxyPlatform{Enabled: true, Server: "0.0.0.0", ServerPort: 7890}},
			EndpointIndependentNat: true,
		},
	}
}

// buildRouteRules 对应 gen_client() 里 route.rules 数组；latest 和 1.11.4
// 两个变体的路由规则其实是一样的（只有 rule_set schema 版本、DNS、
// experimental 不同），所以两边共用这一个函数，只有 includePrivateRule
// 这一处会变。
func buildRouteRules(includePrivateRule bool) []RouteRule {
	rules := []RouteRule{
		// 邮件协议端口（IMAP/POP3/SMTP）走代理，只按端口匹配，不带
		// domain_suffix/ip_cidr——这两个字段以前是 AND 关系强制同时满足：
		// sing-box 对这几个端口天生不做协议嗅探（服务端先说话的协议，
		// 没法从客户端字节里偷看域名），domain_suffix 在这里永远不可能
		// 匹配上，是死代码；ip_cidr 硬编码单个 IP 又跟不上邮件服务商
		// 自己的 IP 池变化（实测：网易邮箱换了一个没在名单里的 IP，
		// 直接判给了 geoip-cn 走直连，超时）。原脚本端口列表里的 994
		// 不是任何标准邮件协议端口，查证据大概率是 587（SMTP 提交端口，
		// 现代邮件客户端发信最常用的端口）的笔误，这里换回了 587。
		{Port: []int{25, 110, 143, 465, 587, 993, 995}, Outbound: "代理_469138946ba5fa"},
		{PackageName: []string{"com.duolingo"}, Outbound: "代理_469138946ba5fa"},
		{RuleSet: "geosite-duolingo", Outbound: "代理_469138946ba5fa"},
		{Protocol: "dns", Action: "hijack-dns"},
		{Port: 53, Action: "hijack-dns"},
		{ProcessName: []string{"sing-box.exe", "sing-box", "io.nekohasekai.sfa"}, Outbound: "直连_469138946ba5fa"},
		{RuleSet: []string{"geosite-category-ads-all", "megamori"}, Action: "reject"},
		{Domain: adDomainsAny(), Action: "reject"},
		{Inbound: []string{"混合入站_469138946ba5fa", "TUN入站_469138946ba5fa"}, Action: "sniff"},
		{IPIsPrivate: true, Outbound: "直连_469138946ba5fa"},
	}
	if includePrivateRule {
		rules = append(rules, RouteRule{RuleSet: "geosite-private", Outbound: "直连_469138946ba5fa"})
	}
	rules = append(rules,
		RouteRule{RuleSet: "geosite-cn", Outbound: "直连_469138946ba5fa"},
		RouteRule{RuleSet: "geoip-cn", Outbound: "直连_469138946ba5fa"},
		RouteRule{RuleSet: "category-ai-!cn", Outbound: "智能_469138946ba5fa"}, // 原为 geosite-openai → overseas-ai → category-ai-!cn
		RouteRule{RuleSet: "geosite-geolocation-!cn", Outbound: "代理_469138946ba5fa"},
	)
	return rules
}

// groupOutbounds 拼 direct/代理/自动/手动/智能 这几个分组，
// autoManualExtra 是要额外挂进"自动"和"手动"两个组的 tag 列表
// （CF 节点 tag，client.json 才有，OpenWrt/1.11.4 传 nil）。
func groupOutbounds(p Params, includeAnyTLS bool, autoManualExtra []string) []Outbound {
	autoTags := []string{p.Tags.VLESS, p.Tags.Trojan}
	if includeAnyTLS {
		autoTags = append(autoTags, p.Tags.AnyTLS)
	}
	autoTags = append(autoTags, p.Tags.VmessReality, p.Tags.VmessWSTLS, p.Tags.VlessWS)
	autoTags = append(autoTags, autoManualExtra...)

	manualTags := []string{p.Tags.TUIC, p.Tags.Hysteria2, p.Tags.VLESS, p.Tags.Trojan}
	if includeAnyTLS {
		manualTags = append(manualTags, p.Tags.AnyTLS)
	}
	manualTags = append(manualTags, p.Tags.VmessReality, p.Tags.VmessWSTLS, p.Tags.VlessWS)
	manualTags = append(manualTags, autoManualExtra...)

	proxyGroupRefs := selectorGroupTags()

	return []Outbound{
		{Type: "direct", Tag: "直连_469138946ba5fa"},
		{Type: "selector", Tag: "代理_469138946ba5fa", Outbounds: proxyGroupRefs},
		{Type: "urltest", Tag: "自动_469138946ba5fa", Outbounds: autoTags,
			URL: "http://cp.cloudflare.com/generate_204", Interval: "10m0s", Tolerance: 100},
		{Type: "selector", Tag: "手动_469138946ba5fa", Outbounds: manualTags},
		{Type: "selector", Tag: "智能_469138946ba5fa", Outbounds: proxyGroupRefs},
	}
}

// BuildLatest 生成 client.json（IncludeCF=true）或 OpenWrt 版
// （IncludeCF=false，TUNInterfaceName="tun0"）。
func BuildLatest(p Params, opt LatestOptions, randHex func() string) *Config {
	var cfObs []Outbound
	var cfTags []string
	if opt.IncludeCF {
		cfObs, cfTags = cfOutbounds(p, randHex)
	}

	outbounds := groupOutbounds(p, opt.IncludeAnyTLS, cfTags)
	outbounds = append(outbounds, RegionalURLTestOutbounds()...)
	if opt.IncludeAnyTLS {
		outbounds = append(outbounds, anytlsOutbound(p))
	}
	outbounds = append(outbounds, sharedProtocolOutbounds(p)...)
	outbounds = append(outbounds, cfObs...)

	return &Config{
		Log: LogConfig{Level: "warn", Timestamp: true},
		DNS: buildLatestDNS(),
		NTP: NTPConfig{Enabled: true, Interval: "30m0s", Server: "ntp.aliyun.com", ServerPort: 123},
		HTTPClients: []sbconfig.HTTPClient{
			{Tag: "全局HTTP客户端路由DEFAULT"},
			{Tag: "全局HTTP客户端路由DIRECT", Detour: "direct"},
			{Tag: "全局HTTP客户端路由直连", Detour: "直连_469138946ba5fa"},
			{Tag: "全局HTTP客户端路由代理", Detour: "代理_469138946ba5fa"},
		},
		Inbounds:  buildLatestInbounds(opt),
		Outbounds: outbounds,
		Route: RouteConfig{
			Rules:                 buildRouteRules(opt.IncludePrivateRule),
			RuleSet:               latestRouteRuleSets(),
			Final:                 "代理_469138946ba5fa",
			AutoDetectInterface:   true,
			DefaultDomainResolver: "解析CLOUDFLAREDNS_469138946ba5fa",
			DefaultHTTPClient:     "全局HTTP客户端路由DEFAULT",
		},
		Experimental: Experimental{
			CacheFile: CacheFile{Enabled: true, Path: "sing-box-cache.db", StoreFakeIP: true, StoreDNS: true},
			ClashAPI: ClashAPI{ExternalController: ":9999", ExternalUI: "ui",
				ExternalUIDownloadURL:    "https://github.com/Zephyruso/zashboard/releases/latest/download/dist.zip",
				ExternalUIDownloadDetour: "代理_469138946ba5fa"},
		},
	}
}
