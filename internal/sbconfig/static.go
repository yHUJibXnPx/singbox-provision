package sbconfig

// dnsHostsPredefined 对应服务端 config.json 里那个 "解析HOSTS_..." DNS server
// 的 predefined 表，内容跟原脚本内嵌在 heredoc 里的那段完全一致。
var dnsHostsPredefined = map[string][]string{
	"dns.google":                       {"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"},
	"dns.alidns.com":                   {"223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"},
	"one.one.one.one":                  {"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"},
	"1dot1dot1dot1.cloudflare-dns.com": {"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"},
	"cloudflare-dns.com":               {"104.16.249.249", "104.16.248.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"},
	"dns.cloudflare.com":               {"104.16.132.229", "104.16.133.229", "2606:4700::6810:84e5", "2606:4700::6810:85e5"},
	"dot.pub":                          {"1.12.12.12", "120.53.53.53"},
	"doh.pub":                          {"1.12.12.12", "120.53.53.53"},
	"dns.quad9.net":                    {"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"},
	"dns.yandex.net":                   {"77.88.8.8", "77.88.8.1", "2a02:6b8::feed:ff", "2a02:6b8:0:1::feed:ff"},
	"dns.sb":                           {"185.222.222.222", "2a09::"},
	"dns.umbrella.com":                 {"208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53"},
	"dns.sse.cisco.com":                {"208.67.220.220", "208.67.222.222", "2620:119:35::35", "2620:119:53::53"},
	"engage.cloudflareclient.com":      {"162.159.192.1", "2606:4700:d0::a29f:c001"},
}

// AdDomains 对应原脚本的 _AD_DOMAINS（DNS 规则和路由规则各用一次，原脚本里
// 是重复写了 6 次的同一份列表，这里只保留一份）。
var AdDomains = []string{
	"books-analytics-events.apple.com",
	"pagead2.googlesyndication.com",
	"pagead2.googleadservices.com",
	"afs.googlesyndication.com",
	"stats.g.doubleclick.net",
	"ad.doubleclick.net",
	"stats.wp.com",
	"trk.pinterest.com",
	"ads.yahoo.com",
	"analytics.query.yahoo.com",
	"partnerads.ysm.yahoo.com",
	"api.ad.xiaomi.com",
	"data.mistat.xiaomi.com",
	"sdkconfig.ad.xiaomi.com",
	"business-api.tiktok.com",
	"grs.hicloud.com",
}

// serverRuleSets 对应服务端 config.json 的 route.rule_set。
var serverRuleSets = []RuleSet{
	{
		Type: "remote", Tag: "geosite-category-ads-all", Format: "binary",
		URL:            "https://github.com/SagerNet/sing-geosite/raw/refs/heads/rule-set/geosite-category-ads-all.srs",
		HTTPClient:     "全局HTTP客户端路由DEFAULT",
		UpdateInterval: "24h0m0s",
	},
	{
		Type: "remote", Tag: "megamori", Format: "binary",
		URL:            "https://github.com/neomikanagi/megamori/raw/refs/heads/main/megamori.srs",
		HTTPClient:     "全局HTTP客户端路由DEFAULT",
		UpdateInterval: "24h0m0s",
	},
}

// 固定 tag 名（跟原脚本的 INBOUND_* / 直连_.../代理_... 常量一一对应）。
const (
	TagDirect          = "直连_469138946ba5fa"
	TagProxy           = "代理_469138946ba5fa"
	TagHostsDNS        = "解析HOSTS_469138946ba5fa"
	TagCloudflareDNS   = "解析CLOUDFLAREDNS_469138946ba5fa"
	TagGoogleDNS       = "解析GOOGLE_469138946ba5fa"
	TagHTTPDefault     = "全局HTTP客户端路由DEFAULT"
	TagHTTPDirectRoute = "全局HTTP客户端路由DIRECT"
	TagHTTPZhiLian     = "全局HTTP客户端路由直连"
	TagHTTPDaili       = "全局HTTP客户端路由代理"

	InboundHysteria2    = "hysteria2-in"
	InboundTUIC         = "tuic-in"
	InboundVLESS        = "vless-in"
	InboundTrojan       = "trojan-in"
	InboundAnyTLS       = "anytls-in"
	InboundVmessReality = "vmess-reality-in"
	InboundVmessWSTLS   = "vmess-ws-tls-in"
	InboundVlessWS      = "vless-ws-in"
)
