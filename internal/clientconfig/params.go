package clientconfig

// Variant 对应原脚本三次调用 gen_client() 传的不同参数组合。
type Variant int

const (
	VariantLatest  Variant = iota // client.json
	VariantOpenWrt                // client_openwrt_sing-box.json
	Variant1114                   // client_1.11.4.json
)

// Params 是构建任意一个客户端配置变体需要的全部输入。跟 sbconfig.ServerParams
// 有大量重复字段（同一批 UUID/密码/端口本来就是服务端和客户端共享的），
// 这里没有强行合并成一个大结构体，是因为客户端还需要一些服务端完全用不到
// 的东西（single short_id、Reality 公钥、CF 节点参数、tag 名字）。
type Params struct {
	ServerIP        string
	BestDomain      string
	PublicKey       string // Reality 公钥（由 randgen.RealityKeyPair 生成的那对里的公钥）
	FingerprintType string // 固定 "firefox"

	UUIDVLESS, UUIDTUIC, UUIDVmessReality, UUIDVmessWSTLS, UUIDVlessWS string

	PasswordHysteria2, PasswordTUIC, PasswordTrojan, PasswordAnyTLS string

	// 客户端链接/配置里每种 Reality 协议只用得上"一个" short_id（服务端是
	// 一整组，供多个客户端各自选用），对应原脚本 pick_random_short_id()。
	ShortIDVLESS, ShortIDTrojan, ShortIDAnyTLS, ShortIDVmessReality string

	PortVLESS, PortTrojan, PortAnyTLS, PortVmessReality, PortVmessWSTLS, PortVlessWS, PortHysteria2, PortTUIC int

	HY2ObfsType, HY2ObfsPassword string
	CertLines                    []string // 自签证书，Hysteria2/TUIC/VmessWSTLS 客户端出站拿它验证服务端

	PathVmessWSTLS, PathVLESSWS string

	// RegionTag 对应 NODE_REGION_TAG（默认空字符串），会被加到每一个协议
	// tag 和每一个 CF 节点 tag 的最前面。
	RegionTag string

	Tags Tags
	CF   CFParams
}

// Tags 是各协议出站的 tag 名字，格式固定为
// "{地区标记}{协议}-out-{32位十六进制}"，对应原脚本 OUTBOUND_* 变量。
type Tags struct {
	Hysteria2, TUIC, VLESS, Trojan, AnyTLS, VmessReality, VmessWSTLS, VlessWS string
}

// NewTags 用给定的地区标记（可以是空字符串）和一个"生成不带连字符的十六进制
// 串"的函数（生产环境传 randgen.NewUUID 去掉横线的版本）构建全部 8 个 tag。
func NewTags(regionTag string, randHex func() string) Tags {
	return Tags{
		Hysteria2:    regionTag + "hysteria2-out-" + randHex(),
		TUIC:         regionTag + "tuic-out-" + randHex(),
		VLESS:        regionTag + "vless-out-" + randHex(),
		Trojan:       regionTag + "trojan-out-" + randHex(),
		AnyTLS:       regionTag + "anytls-out-" + randHex(),
		VmessReality: regionTag + "vmess-reality-out-" + randHex(),
		VmessWSTLS:   regionTag + "vmess-ws-tls-out-" + randHex(),
		VlessWS:      regionTag + "vless-ws-out-" + randHex(),
	}
}
