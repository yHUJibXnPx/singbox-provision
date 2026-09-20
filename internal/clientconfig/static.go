package clientconfig

import "singboxprovision/internal/sbconfig"

// clientDNSHostsPredefined 对应 _DNS_SERVERS 里的 hosts predefined 表。
//
// 注意这里的 "cloudflare-dns.com" 比服务端 config.json 里同名的那份多了
// 开头两个 IP（1.1.1.1 / 1.0.0.1）——这不是我抄错了，是原脚本客户端和
// 服务端两份 heredoc 本来就写的不一样，照抄服务端那份会产生一个跟原脚本
// 不一致的客户端配置。
var clientDNSHostsPredefined = map[string][]string{
	"dns.google":                       {"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"},
	"dns.alidns.com":                   {"223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"},
	"one.one.one.one":                  {"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"},
	"1dot1dot1dot1.cloudflare-dns.com": {"1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"},
	"cloudflare-dns.com":               {"1.1.1.1", "1.0.0.1", "104.16.249.249", "104.16.248.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"},
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

// regionTagsDefOrder 是 12 个地区 urltest 分组**被定义**时的顺序
// （对应 _REGIONAL_URLTEST 那段 heredoc 本身的顺序）。
var regionTagsDefOrder = []string{
	"台湾", "新加坡", "日本", "美国", "韩国", "香港",
	"英国", "加拿大", "澳大利亚", "法国", "荷兰", "德国",
}

// regionTagsRefOrder 是这 12 个分组在"代理"/"智能" selector 的 outbounds
// 引用列表里出现的顺序——注意"德国"在这里排在"香港"后面、"英国"前面，
// 跟上面定义处的顺序不一样。这不是我写错了：原脚本这两处本来就是分开维护
// 的两份硬编码列表，某次改动加错了位置，从此就没同步过。两个顺序都原样
// 保留，只是各用各的常量，不强行"修正"成一致——这类顺序不一致不影响功能
// （反正都是同一组 12 个 tag），但确实是原脚本"改着改着不同步"的一个
// 具体例子。
var regionTagsRefOrder = []string{
	"台湾", "新加坡", "日本", "美国", "韩国", "香港",
	"德国", "英国", "加拿大", "澳大利亚", "法国", "荷兰",
}

// RegionalURLTestOutbounds 生成那 13 个占位 urltest 分组——原作者自己在
// 注释里都写了"占位标记，可能未来替换等作用？"，也就是说这些分组本来就
// 只是预留的空壳，多数会一直指向"直连"（除非节点 tag 恰好匹配上对应地区
// 的名字，那是脚本末尾另一段"自动分类"逻辑做的事，见 README 里的说明）。
func RegionalURLTestOutbounds() []Outbound {
	out := make([]Outbound, 0, len(regionTagsDefOrder))
	for _, tag := range regionTagsDefOrder {
		out = append(out, Outbound{
			Type: "urltest", Tag: tag + "_469138946ba5fa",
			Outbounds: []string{"直连_469138946ba5fa"},
			URL:       "http://cp.cloudflare.com/generate_204",
			Interval:  "10m0s", Tolerance: 100,
		})
	}
	return out
}

// selectorGroupTags 是"代理"和"智能"两个 selector 分组共用的引用列表。
func selectorGroupTags() []string {
	tags := []string{"自动_469138946ba5fa", "手动_469138946ba5fa", "直连_469138946ba5fa"}
	for _, r := range regionTagsRefOrder {
		tags = append(tags, r+"_469138946ba5fa")
	}
	return tags
}

// cfNodeSpec 对应 CF_NODES 表里的一行："显示名|服务器|端口|是否tls"。
type cfNodeSpec struct {
	name string
	host string
	port int
	tls  bool
}

// CFParams 是构建 CF（cloudflared 隧道）系列出站节点需要的额外参数——
// 只有配了 cloudflared 隧道才用得上这一套，对应原脚本 build_cf_data()。
type CFParams struct {
	Domain      string // CLOUDFLARED_DOMAIN_VLESS_WS
	NATServer   string // SERVER_CFNAT，留空则不生成 *-NAT 那几个节点
	NATPort     int
	ProxyIP     string // CLOUDFLARED_PROXYIP，留空则不生成 CF-ProxyIP 节点
	ProxyIPPort int
}

// cfNodeTable 对应 CF_NODES 静态表本体（"唯一数据源"）。
func cfNodeTable(p CFParams) []cfNodeSpec {
	specs := []cfNodeSpec{
		{"CF-104.16-443", "104.16.0.0", 443, true},
	}
	addNAT := func(name string, tls bool) {
		if p.NATServer != "" {
			specs = append(specs, cfNodeSpec{name + "-NAT", p.NATServer, p.NATPort, tls})
		}
	}
	addNAT("CF-104.16-443", true)
	specs = append(specs, cfNodeSpec{"CF-104.17-8443", "104.17.0.0", 8443, true})
	addNAT("CF-104.17-8443", true)
	specs = append(specs, cfNodeSpec{"CF-104.18-2053", "104.18.0.0", 2053, true})
	addNAT("CF-104.18-2053", true)
	specs = append(specs, cfNodeSpec{"CF-104.19-2083", "104.19.0.0", 2083, true})
	addNAT("CF-104.19-2083", true)
	specs = append(specs, cfNodeSpec{"CF-104.20-2087", "104.20.0.0", 2087, true})
	addNAT("CF-104.20-2087", true)
	specs = append(specs, cfNodeSpec{"CF-104.21-80", "104.21.0.0", 80, false})
	addNAT("CF-104.21-80", false)
	specs = append(specs, cfNodeSpec{"CF-104.22-8080", "104.22.0.0", 8080, false})
	addNAT("CF-104.22-8080", false)
	specs = append(specs, cfNodeSpec{"CF-104.24-8880", "104.24.0.0", 8880, false})
	addNAT("CF-104.24-8880", false)
	if p.Domain != "" {
		specs = append(specs, cfNodeSpec{"CF-Domain-443", p.Domain, 443, true})
		addNAT("CF-Domain-443", true)
		specs = append(specs, cfNodeSpec{"CF-Domain-80", p.Domain, 80, false})
		addNAT("CF-Domain-80", false)
	}
	if p.ProxyIP != "" {
		specs = append(specs, cfNodeSpec{"CF-ProxyIP", p.ProxyIP, p.ProxyIPPort, true})
	}
	return specs
}

// latestRouteRuleSets 对应 _ROUTE_RULESETS（client.json / OpenWrt 共用）。
//
// "category-ai-!cn" 这一条原脚本里是 SagerNet 官方维护的 geosite-openai
// （只覆盖 OpenAI 一家）。应用户要求，先换成社区维护的
// viewer12/OverseasAI.list（覆盖面更广，但是单一维护者的小仓库），后来
// 用户进一步要求换成 MetaCubeX/meta-rules-dat 的 category-ai-!cn——这是
// mihomo/Clash.Meta 生态下规模更大、活跃度更高的规则集仓库，跟这个项目
// 已经在用的 geosite-duolingo 是同一个来源。tag 名字每次跟着换，路由/DNS
// 里所有引用这个 tag 的地方都要跟着改——具体改了哪几处见 build_latest.go
// 和 build_1114.go 里对应位置的注释。规则内容本身（爬哪些域名）由该规则集
// 上游仓库维护，这里只负责引用哪个规则集、指向哪个出站，不对规则集内容
// 本身做任何审核或背书。
func latestRouteRuleSets() []sbconfig.RuleSet {
	mk := func(tag, url string) sbconfig.RuleSet {
		return sbconfig.RuleSet{Type: "remote", Tag: tag, Format: "binary", URL: url,
			HTTPClient: "全局HTTP客户端路由代理", UpdateInterval: "24h0m0s"}
	}
	const base = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/"
	const baseSite = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/"
	return []sbconfig.RuleSet{
		mk("geoip-cn", base+"geoip-cn.srs"),
		mk("geosite-private", baseSite+"geosite-private.srs"),
		mk("geosite-cn", baseSite+"geosite-cn.srs"),
		mk("geosite-geolocation-!cn", baseSite+"geosite-geolocation-!cn.srs"),
		mk("geosite-category-ads-all", baseSite+"geosite-category-ads-all.srs"),
		mk("megamori", "https://raw.githubusercontent.com/neomikanagi/megamori/main/megamori.srs"),
		mk("category-ai-!cn", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/category-ai-!cn.srs"),
		mk("geosite-duolingo", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/duolingo.srs"),
	}
}

// legacy1114RouteRuleSets 对应 _ROUTE_RULESETS_1114：跟上面几乎一样，
// 差别只是用 download_detour 而不是 http_client 去指定下载走哪个出站
// （1.11.4 时代 sing-box 的 rule_set 还不支持通过具名 http_client 下载）。
func legacy1114RouteRuleSets() []sbconfig.RuleSet {
	rs := latestRouteRuleSets()
	out := make([]sbconfig.RuleSet, len(rs))
	for i, r := range rs {
		r.HTTPClient = ""
		r.DownloadDetour = "代理_469138946ba5fa"
		out[i] = r
	}
	return out
}
