// Package clientconfig 生成三份客户端配置（client.json / OpenWrt /
// client_1.11.4.json），对应原脚本 gen_client() 及其依赖的一堆 _D_XXX 变量。
//
// 这个包不复用 internal/sbconfig 的类型，是刻意的：客户端和服务端两份
// config.json 长得像，但细节上有好几处容易踩坑的差异——比如：
//   - DNS：客户端多了 alidns/doh/fakeip 几个 server，还有 detour 字段；
//     服务端没有。
//   - route 里 sing-box 自身进程的规则：服务端指向"代理"（自己的流量要走
//     代理转发出去），客户端指向"直连"（不能又给自己转发一遍，否则死循环）。
//   - default_domain_resolver：服务端是 GOOGLE，客户端是
//     CLOUDFLAREDNS——照抄服务端那份会用错。
//   - NTP 服务器：服务端 time.cloudflare.com，客户端 ntp.aliyun.com。
//
// 这些差异原脚本里也是用完全独立的两套 heredoc 分别写的，用独立的类型
// 复刻这个"分开维护"的现实，比硬凑一个大而全的共享类型更不容易出错。
package clientconfig

import "singboxprovision/internal/sbconfig"

type Config struct {
	Log          LogConfig             `json:"log"`
	DNS          any                   `json:"dns"` // DNSConfig（新版）或 Legacy1114DNS（1.11.4）
	NTP          NTPConfig             `json:"ntp"`
	HTTPClients  []sbconfig.HTTPClient `json:"http_clients,omitempty"`
	Inbounds     []any                 `json:"inbounds"` // MixedInbound / TunInbound，两种形状差异较大，直接放 any
	Outbounds    []Outbound            `json:"outbounds"`
	Route        RouteConfig           `json:"route"`
	Experimental Experimental          `json:"experimental"`
}

type LogConfig struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

type NTPConfig struct {
	Enabled    bool   `json:"enabled"`
	Interval   string `json:"interval"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

// DNSServer 覆盖客户端用到的 5 种 DNS server（hosts/https.../fakeip）。
type DNSServer struct {
	Type           string              `json:"type"`
	Tag            string              `json:"tag"`
	Predefined     map[string][]string `json:"predefined,omitempty"`
	DomainResolver string              `json:"domain_resolver,omitempty"`
	Server         string              `json:"server,omitempty"`
	Path           string              `json:"path,omitempty"`
	Detour         string              `json:"detour,omitempty"`
	Inet4Range     string              `json:"inet4_range,omitempty"`
	Inet6Range     string              `json:"inet6_range,omitempty"`
}

// DNSRule 里 RuleSet 用 any：原脚本里同一份配置中，rule_set 有时是数组
// （命中多个规则集共用一个结果时）有时是单个字符串（只命中一个规则集时），
// 这里用 any 直接按调用方给的值序列化，不强行统一成数组。
type DNSRule struct {
	Action        string   `json:"action,omitempty"`
	Server        string   `json:"server,omitempty"`
	RuleSet       any      `json:"rule_set,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	QueryType     []string `json:"query_type,omitempty"`
	MatchResponse bool     `json:"match_response,omitempty"`
	ResponseRcode string   `json:"response_rcode,omitempty"`
	Rcode         string   `json:"rcode,omitempty"`
}

type DNSConfig struct {
	Servers        []DNSServer `json:"servers"`
	Rules          []DNSRule   `json:"rules"`
	Final          string      `json:"final"`
	Strategy       string      `json:"strategy,omitempty"`
	ReverseMapping bool        `json:"reverse_mapping,omitempty"`
	CacheCapacity  int         `json:"cache_capacity,omitempty"`
}

type MixedInbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen"`
	ListenPort int    `json:"listen_port"`
}

type HTTPProxyPlatform struct {
	Enabled    bool   `json:"enabled"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

type TunPlatform struct {
	HTTPProxy HTTPProxyPlatform `json:"http_proxy"`
}

// TunInbound：InterfaceName 只有 OpenWrt 变体会设置（"tun0"）。Stack 加了
// omitempty——sing-box 1.15.0 开始把 TUN 的 stack 选项标为弃用、1.17.0 会
// 彻底移除（跑 testing 频道下载到的版本已经会在 check/启动时打印这条弃用
// 警告，这是实测跑出来发现的，不是我凭空预判的）。client.json/OpenWrt 这两个
// "跟随最新 sing-box"的变体不再设置这个字段，交给 sing-box 自己选默认栈；
// client_1.11.4.json 走的是完全独立的旧版 schema，是给那个版本的客户端用的，
// 不受这个弃用影响，继续显式设置。
type TunInbound struct {
	Type                   string      `json:"type"`
	Tag                    string      `json:"tag"`
	InterfaceName          string      `json:"interface_name,omitempty"`
	AutoRoute              bool        `json:"auto_route"`
	StrictRoute            bool        `json:"strict_route"`
	Stack                  string      `json:"stack,omitempty"`
	Address                []string    `json:"address"`
	Platform               TunPlatform `json:"platform"`
	EndpointIndependentNat bool        `json:"endpoint_independent_nat"`
}

// UTLS / ClientReality：客户端侧的 TLS reality 配置用 public_key + 单个
// short_id 字符串，跟服务端侧 private_key + short_id 数组是两码事，
// 千万不能共用一个类型。
type UTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}

type ClientReality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
}

type ClientTLS struct {
	Enabled     bool           `json:"enabled"`
	ServerName  string         `json:"server_name,omitempty"`
	Insecure    bool           `json:"insecure"`
	ALPN        []string       `json:"alpn,omitempty"`
	Certificate []string       `json:"certificate,omitempty"`
	UTLS        *UTLS          `json:"utls,omitempty"`
	Reality     *ClientReality `json:"reality,omitempty"`
}

// Outbound 是一个"什么协议都能装"的共享结构体（跟 sbconfig.Inbound 是
// 同一种取舍：客户端出站种类比服务端入站还多——除了 8 种协议本身，还有
// direct/selector/urltest 这几种"分组"类型），字段按需要 omitempty。
type Outbound struct {
	Type              string              `json:"type"`
	Tag               string              `json:"tag"`
	Server            string              `json:"server,omitempty"`
	ServerPort        int                 `json:"server_port,omitempty"`
	UUID              string              `json:"uuid,omitempty"`
	Password          string              `json:"password,omitempty"`
	Flow              string              `json:"flow,omitempty"`
	Security          string              `json:"security,omitempty"`
	PacketEncoding    string              `json:"packet_encoding,omitempty"`
	CongestionControl string              `json:"congestion_control,omitempty"`
	Obfs              *sbconfig.Obfs      `json:"obfs,omitempty"`
	TLS               *ClientTLS          `json:"tls,omitempty"`
	Transport         *sbconfig.Transport `json:"transport,omitempty"`
	Outbounds         []string            `json:"outbounds,omitempty"`
	URL               string              `json:"url,omitempty"`
	Interval          string              `json:"interval,omitempty"`
	Tolerance         int                 `json:"tolerance,omitempty"`
}

type RouteRule struct {
	Port         any      `json:"port,omitempty"` // 有时是单个 int，有时是 []int
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	IPCidr       []string `json:"ip_cidr,omitempty"`
	PackageName  []string `json:"package_name,omitempty"`
	Protocol     string   `json:"protocol,omitempty"`
	ProcessName  []string `json:"process_name,omitempty"`
	RuleSet      any      `json:"rule_set,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	Inbound      []string `json:"inbound,omitempty"`
	IPIsPrivate  bool     `json:"ip_is_private,omitempty"`
	QueryType    []string `json:"query_type,omitempty"`
	Outbound     string   `json:"outbound,omitempty"`
	Action       string   `json:"action,omitempty"`
}

type RouteConfig struct {
	Rules                 []RouteRule        `json:"rules"`
	RuleSet               []sbconfig.RuleSet `json:"rule_set"`
	Final                 string             `json:"final"`
	AutoDetectInterface   bool               `json:"auto_detect_interface"`
	DefaultDomainResolver string             `json:"default_domain_resolver,omitempty"`
	DefaultHTTPClient     string             `json:"default_http_client,omitempty"`
}

type CacheFile struct {
	Enabled     bool   `json:"enabled"`
	Path        string `json:"path"`
	StoreRDRC   bool   `json:"store_rdrc,omitempty"`
	StoreFakeIP bool   `json:"store_fakeip,omitempty"`
	StoreDNS    bool   `json:"store_dns,omitempty"`
}

type ClashAPI struct {
	ExternalController       string `json:"external_controller"`
	ExternalUI               string `json:"external_ui"`
	ExternalUIDownloadURL    string `json:"external_ui_download_url"`
	ExternalUIDownloadDetour string `json:"external_ui_download_detour"`
}

type Experimental struct {
	CacheFile CacheFile `json:"cache_file"`
	ClashAPI  ClashAPI  `json:"clash_api"`
}
