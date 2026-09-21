// Package sbconfig 生成 sing-box 服务端 config.json，用真正的结构体 + json.Marshal
// 取代原脚本里几十个 _D_XXX 字符串变量 + heredoc 拼接的写法。
//
// 这么做直接解决的问题：原脚本任何一处漏加/多加一个逗号、忘记转义一个引号，
// 只有实际跑一次 `sing-box check` 才会暴露；这里换成结构体后，字段拼错了
// 是编译期错误，值给错了也只是 JSON 内容不对，不会出现语法上不合法的 JSON。
package sbconfig

// Config 是 sing-box 顶层配置结构。
type Config struct {
	Log          LogConfig     `json:"log"`
	DNS          DNSConfig     `json:"dns"`
	NTP          NTPConfig     `json:"ntp"`
	HTTPClients  []HTTPClient  `json:"http_clients,omitempty"`
	Inbounds     []Inbound     `json:"inbounds"`
	Outbounds    []Outbound    `json:"outbounds"`
	Route        RouteConfig   `json:"route"`
	Experimental *Experimental `json:"experimental,omitempty"`
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

type HTTPClient struct {
	Tag    string `json:"tag"`
	Detour string `json:"detour,omitempty"`
}

type DNSServer struct {
	Type           string              `json:"type"`
	Tag            string              `json:"tag"`
	Predefined     map[string][]string `json:"predefined,omitempty"`
	DomainResolver string              `json:"domain_resolver,omitempty"`
	Server         string              `json:"server,omitempty"`
	Path           string              `json:"path,omitempty"`
}

type DNSRule struct {
	Action        string   `json:"action,omitempty"`
	Server        string   `json:"server,omitempty"`
	RuleSet       []string `json:"rule_set,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	MatchResponse bool     `json:"match_response,omitempty"`
	ResponseRcode string   `json:"response_rcode,omitempty"`
	Rcode         string   `json:"rcode,omitempty"`
}

type DNSConfig struct {
	Servers []DNSServer `json:"servers"`
	Rules   []DNSRule   `json:"rules"`
	Final   string      `json:"final"`
}

// User 对应各协议入站里的用户对象。Name 用指针是为了精确还原原脚本的行为：
// vless/vmess/trojan/anytls 的用户对象里 "name" 字段会显式写成空字符串 ""，
// 而 hysteria2/tuic 的用户对象里根本没有 "name" 这个 key。
// 用 *string + omitempty：nil 时整个字段消失，指向 "" 时字段以空字符串出现。
type User struct {
	Name     *string `json:"name,omitempty"`
	UUID     string  `json:"uuid,omitempty"`
	Password string  `json:"password,omitempty"`
	Flow     string  `json:"flow,omitempty"`
}

func StrPtr(s string) *string { return &s }

type Obfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type RealityHandshake struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

type Reality struct {
	Enabled    bool             `json:"enabled"`
	Handshake  RealityHandshake `json:"handshake"`
	PrivateKey string           `json:"private_key"`
	ShortID    []string         `json:"short_id"`
}

type TLSConfig struct {
	Enabled     bool     `json:"enabled"`
	ServerName  string   `json:"server_name,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Certificate []string `json:"certificate,omitempty"`
	Key         []string `json:"key,omitempty"`
	Reality     *Reality `json:"reality,omitempty"`
}

type Transport struct {
	Type                string            `json:"type"`
	Path                string            `json:"path,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	MaxEarlyData        int               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string            `json:"early_data_header_name,omitempty"`
}

type Inbound struct {
	Type              string     `json:"type"`
	Tag               string     `json:"tag"`
	Listen            string     `json:"listen"`
	ListenPort        int        `json:"listen_port"`
	Users             []User     `json:"users,omitempty"`
	Obfs              *Obfs      `json:"obfs,omitempty"`
	TLS               *TLSConfig `json:"tls,omitempty"`
	CongestionControl string     `json:"congestion_control,omitempty"`
	PaddingScheme     []string   `json:"padding_scheme,omitempty"`
	Transport         *Transport `json:"transport,omitempty"`
}

type Outbound struct {
	Type      string   `json:"type"`
	Tag       string   `json:"tag"`
	Outbounds []string `json:"outbounds,omitempty"`
}

type RouteRule struct {
	Protocol    string   `json:"protocol,omitempty"`
	Port        int      `json:"port,omitempty"`
	ProcessName []string `json:"process_name,omitempty"`
	RuleSet     []string `json:"rule_set,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	Inbound     []string `json:"inbound,omitempty"`
	Outbound    string   `json:"outbound,omitempty"`
	Action      string   `json:"action,omitempty"`
}

type RuleSet struct {
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	Format         string `json:"format"`
	URL            string `json:"url"`
	HTTPClient     string `json:"http_client,omitempty"`
	DownloadDetour string `json:"download_detour,omitempty"`
	UpdateInterval string `json:"update_interval"`
}

type RouteConfig struct {
	Rules                 []RouteRule `json:"rules"`
	RuleSet               []RuleSet   `json:"rule_set"`
	Final                 string      `json:"final"`
	AutoDetectInterface   bool        `json:"auto_detect_interface"`
	DefaultDomainResolver string      `json:"default_domain_resolver,omitempty"`
	DefaultHTTPClient     string      `json:"default_http_client,omitempty"`
}

type Experimental struct {
	CacheFile map[string]any `json:"cache_file,omitempty"`
	ClashAPI  map[string]any `json:"clash_api,omitempty"`
}
