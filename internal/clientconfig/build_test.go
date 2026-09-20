package clientconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewTags_FormatsAsRegionProtocolOutRandhex(t *testing.T) {
	i := 0
	fixedHex := func() string {
		i++
		return "deadbeef"
	}
	tags := NewTags("美国", fixedHex)
	if tags.VLESS != "美国vless-out-deadbeef" {
		t.Fatalf("VLESS tag 格式不对: %q", tags.VLESS)
	}
	if tags.Hysteria2 != "美国hysteria2-out-deadbeef" {
		t.Fatalf("Hysteria2 tag 格式不对: %q", tags.Hysteria2)
	}
	if i != 8 {
		t.Fatalf("8 个协议应该各调用一次 randHex，实际调用了 %d 次", i)
	}
}

func TestNewTags_EmptyRegionTagIsFine(t *testing.T) {
	tags := NewTags("", func() string { return "abc123" })
	if tags.VLESS != "vless-out-abc123" {
		t.Fatalf("空地区标记时 tag 不该多出前缀: %q", tags.VLESS)
	}
}

// minimalParams 造一份"能编译出合法配置"的最小参数集，用于冒烟测试——
// 不追求跟哪个真实抓包一致，只验证三个 BuildXXX 函数在正常输入下不会
// panic，且输出的是合法 JSON。
func minimalParams() Params {
	certLines := []string{"-----BEGIN CERTIFICATE-----", "AAAA", "-----END CERTIFICATE-----"}
	return Params{
		ServerIP: "203.0.113.1", BestDomain: "example.com",
		PublicKey: "pubkey", FingerprintType: "firefox",
		UUIDVLESS: "u1", UUIDTUIC: "u2", UUIDVmessReality: "u3", UUIDVmessWSTLS: "u4", UUIDVlessWS: "u5",
		PasswordHysteria2: "p1", PasswordTUIC: "p2", PasswordTrojan: "p3", PasswordAnyTLS: "p4",
		ShortIDVLESS: "s1", ShortIDTrojan: "s2", ShortIDAnyTLS: "s3", ShortIDVmessReality: "s4",
		PortVLESS: 1, PortTrojan: 2, PortAnyTLS: 3, PortVmessReality: 4,
		PortVmessWSTLS: 5, PortVlessWS: 6, PortHysteria2: 7, PortTUIC: 8,
		HY2ObfsType: "salamander", HY2ObfsPassword: "op", CertLines: certLines,
		PathVmessWSTLS: "/a", PathVLESSWS: "/b",
		RegionTag: "测试",
		Tags:      NewTags("测试", func() string { return "abc" }),
		CF:        CFParams{}, // 留空：不应该生成任何 CF 节点
	}
}

func mustValidJSON(t *testing.T, label string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s 序列化失败: %v", label, err)
	}
	var round any
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("%s 生成的不是合法 JSON: %v", label, err)
	}
}

func TestBuildLatest_ProducesValidJSON(t *testing.T) {
	p := minimalParams()
	cfg := BuildLatest(p, LatestOptions{IncludeCF: false, IncludePrivateRule: true, IncludeAnyTLS: true}, func() string { return "x" })
	mustValidJSON(t, "BuildLatest", cfg)
}

// TestBuildLatest_EmptyCFParamsOnlyDropsConditionalNodes 记录了一个原脚本里
// 就存在、这里如实保留的行为：CF_NODES 表里 8 个"字面 Cloudflare IP"的条目
// （CF-104.16-443 等）不依赖任何变量，即使从没配置过 cloudflared 隧道也会
// 生成；只有依赖 SERVER_CFNAT/CLOUDFLARED_DOMAIN_VLESS_WS/CLOUDFLARED_PROXYIP
// 的那几个（*-NAT、CF-Domain-*、CF-ProxyIP）才会真的消失。没有隧道域名时，
// 这 8 个节点的 TLS server_name 会是空字符串，实际连不通——这是原脚本的
// 固有行为，不是这次移植引入的，先如实保留，要不要在 cmd/provision 里加一层
// "完全没配置 CF 隧道就干脆不生成任何 CF 节点"的判断，等做那部分时再决定。
func TestBuildLatest_EmptyCFParamsOnlyDropsConditionalNodes(t *testing.T) {
	p := minimalParams() // CF 留空
	cfg := BuildLatest(p, LatestOptions{IncludeCF: true, IncludeAnyTLS: true}, func() string { return "x" })

	var cfTags []string
	for _, ob := range cfg.Outbounds {
		if strings.Contains(ob.Tag, "cf-ob-") {
			cfTags = append(cfTags, ob.Tag)
		}
	}
	if len(cfTags) != 8 {
		t.Fatalf("CF 参数留空时应该只剩 8 个不依赖变量的字面 IP 节点，实际 %d 个: %v", len(cfTags), cfTags)
	}
	for _, tag := range cfTags {
		if strings.Contains(tag, "NAT") || strings.Contains(tag, "Domain") || strings.Contains(tag, "ProxyIP") {
			t.Fatalf("这个节点依赖留空的 CF 参数，不该出现: %q", tag)
		}
	}
}

func TestBuild1114_ProducesValidJSON(t *testing.T) {
	p := minimalParams()
	cfg := Build1114(p, func() string { return "x" })
	mustValidJSON(t, "Build1114", cfg)
	if cfg.HTTPClients != nil {
		t.Fatal("1.11.4 变体不应该带 http_clients 字段")
	}
}

func TestBuildLatest_OpenWrtHasInterfaceName(t *testing.T) {
	p := minimalParams()
	cfg := BuildLatest(p, LatestOptions{TUNInterfaceName: "tun0", IncludeAnyTLS: true}, func() string { return "x" })
	tun, ok := cfg.Inbounds[1].(TunInbound)
	if !ok {
		t.Fatalf("第二个 inbound 应该是 TunInbound，实际是 %T", cfg.Inbounds[1])
	}
	if tun.InterfaceName != "tun0" {
		t.Fatalf("OpenWrt 变体的 TUN interface_name 应为 tun0，实际 %q", tun.InterfaceName)
	}
}

// TestBuildLatest_TUNStackOmitted 对应实测踩到的一个真实兼容性问题：
// sing-box 1.15.0 开始把 TUN 的 stack 选项标为弃用、1.17.0 会移除，
// testing 频道下载到的版本已经会在启动时打印弃用警告。client.json/
// OpenWrt 这两个跟随最新 sing-box 的变体不该再显式设置这个字段。
func TestBuildLatest_TUNStackOmitted(t *testing.T) {
	p := minimalParams()
	cfg := BuildLatest(p, LatestOptions{IncludeAnyTLS: true}, func() string { return "x" })
	tun := cfg.Inbounds[1].(TunInbound)
	if tun.Stack != "" {
		t.Fatalf("latest 变体的 TUN 不该再设置 stack（已弃用），实际是 %q", tun.Stack)
	}

	b, err := json.Marshal(tun)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"stack"`) {
		t.Fatalf("stack 字段应该整个从 JSON 里消失（omitempty），实际输出包含它: %s", b)
	}
}

// TestBuild1114_TUNStackStillSet 对应同一个兼容性问题的另一面：
// client_1.11.4.json 走的是完全独立的旧版 schema，是给那个版本的客户端用
// 的，不受新版 sing-box 的弃用影响，必须继续显式设置 stack。
func TestBuild1114_TUNStackStillSet(t *testing.T) {
	p := minimalParams()
	cfg := Build1114(p, func() string { return "x" })
	tun := cfg.Inbounds[1].(TunInbound)
	if tun.Stack != "system" {
		t.Fatalf("1.11.4 变体的 TUN 应该保留 stack=system，实际 %q", tun.Stack)
	}
}
