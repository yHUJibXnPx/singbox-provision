package clientconfig

// Legacy1114DNS 对应 _DNS_BLOCK_1114：sing-box 1.11.4 时代的旧版 DNS
// schema（用 "address" 直接写 DNS 地址/DoH URL，而不是新版的
// "type"+"server"+"domain_resolver" 三件套），跟 DNSConfig 是两码事，
// 不能共用类型。
type Legacy1114DNSServer struct {
	Tag             string `json:"tag"`
	Address         string `json:"address"`
	AddressResolver string `json:"address_resolver,omitempty"`
	Detour          string `json:"detour,omitempty"`
}

type Legacy1114DNSRule struct {
	RuleSet      any      `json:"rule_set,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	Server       string   `json:"server,omitempty"`
	DisableCache bool     `json:"disable_cache,omitempty"`
}

type Legacy1114DNS struct {
	Servers          []Legacy1114DNSServer `json:"servers"`
	Rules            []Legacy1114DNSRule   `json:"rules"`
	Final            string                `json:"final"`
	IndependentCache bool                  `json:"independent_cache"`
}
