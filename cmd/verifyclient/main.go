// cmd/verifyclient 跟 cmd/verify 是同一个思路：不凭空造测试数据，而是拿
// 你上传的真实 client.json 反推出参数，再喂回生成器，看结果是否一致。
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"singboxprovision/internal/clientconfig"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func strSlice(v any) []string {
	arr := v.([]any)
	out := make([]string, len(arr))
	for i, x := range arr {
		out[i] = x.(string)
	}
	return out
}

func loadOutbounds(path string) map[string]map[string]any {
	raw := must(os.ReadFile(path))
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		panic(err)
	}
	byTag := map[string]map[string]any{}
	for _, ob := range doc["outbounds"].([]any) {
		m := ob.(map[string]any)
		byTag[m["tag"].(string)] = m
	}
	return byTag
}

// findTag 在 outbounds 里找 tag 里含 needle 子串的那一个（用来在不知道
// 完整随机后缀的情况下，按协议名字定位到对应的出站块）。
func findTag(byTag map[string]map[string]any, needle string) (string, map[string]any) {
	for tag, m := range byTag {
		if len(tag) >= len(needle) && contains(tag, needle) {
			return tag, m
		}
	}
	panic("找不到包含 " + needle + " 的 tag")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func main() {
	byTag := loadOutbounds("testdata/golden_client.json")

	tagVLESS, vless := findTag(byTag, "vless-out-")
	tagTrojan, trojan := findTag(byTag, "trojan-out-")
	tagAnyTLS, anytls := findTag(byTag, "anytls-out-")
	tagHy2, hy2 := findTag(byTag, "hysteria2-out-")
	tagTUIC, tuic := findTag(byTag, "tuic-out-")
	tagVmessReal, vmessReal := findTag(byTag, "vmess-reality-out-")
	tagVmessWS, vmessWS := findTag(byTag, "vmess-ws-tls-out-")
	tagVlessWS, vlessWS := findTag(byTag, "vless-ws-out-")

	realityOf := func(m map[string]any) map[string]any { return m["tls"].(map[string]any)["reality"].(map[string]any) }

	// CF 相关参数：域名从任意一个不带 "-NAT" 后缀的 "CF-Domain-443" 节点反推，
	// NAT server/port 从任意一个 "-NAT" 节点反推，代理 IP 从 "CF-ProxyIP" 反推。
	var cfDomainOb map[string]any
	for tag, m := range byTag {
		if contains(tag, "cf-ob-CF-Domain-443-") && !contains(tag, "NAT") {
			cfDomainOb = m
			break
		}
	}
	var natServer string
	var natPort int
	for tag, m := range byTag {
		if contains(tag, "cf-ob-CF-104.16-443-NAT") {
			natServer = m["server"].(string)
			natPort = int(m["server_port"].(float64))
			_ = tag
			break
		}
	}
	var proxyIP string
	var proxyIPPort int
	for tag, m := range byTag {
		if contains(tag, "cf-ob-CF-ProxyIP-") {
			proxyIP = m["server"].(string)
			proxyIPPort = int(m["server_port"].(float64))
			_ = tag
			break
		}
	}

	p := clientconfig.Params{
		ServerIP:        vless["server"].(string),
		BestDomain:      vless["tls"].(map[string]any)["server_name"].(string),
		PublicKey:       realityOf(vless)["public_key"].(string),
		FingerprintType: vless["tls"].(map[string]any)["utls"].(map[string]any)["fingerprint"].(string),

		UUIDVLESS:        vless["uuid"].(string),
		UUIDTUIC:         tuic["uuid"].(string),
		UUIDVmessReality: vmessReal["uuid"].(string),
		UUIDVmessWSTLS:   vmessWS["uuid"].(string),
		UUIDVlessWS:      vlessWS["uuid"].(string),

		PasswordHysteria2: hy2["password"].(string),
		PasswordTUIC:      tuic["password"].(string),
		PasswordTrojan:    trojan["password"].(string),
		PasswordAnyTLS:    anytls["password"].(string),

		ShortIDVLESS:        realityOf(vless)["short_id"].(string),
		ShortIDTrojan:       realityOf(trojan)["short_id"].(string),
		ShortIDAnyTLS:       realityOf(anytls)["short_id"].(string),
		ShortIDVmessReality: realityOf(vmessReal)["short_id"].(string),

		PortVLESS: int(vless["server_port"].(float64)), PortTrojan: int(trojan["server_port"].(float64)),
		PortAnyTLS: int(anytls["server_port"].(float64)), PortVmessReality: int(vmessReal["server_port"].(float64)),
		PortVmessWSTLS: int(vmessWS["server_port"].(float64)), PortVlessWS: int(vlessWS["server_port"].(float64)),
		PortHysteria2: int(hy2["server_port"].(float64)), PortTUIC: int(tuic["server_port"].(float64)),

		HY2ObfsType:     hy2["obfs"].(map[string]any)["type"].(string),
		HY2ObfsPassword: hy2["obfs"].(map[string]any)["password"].(string),
		CertLines:       strSlice(hy2["tls"].(map[string]any)["certificate"]),

		PathVmessWSTLS: vmessWS["transport"].(map[string]any)["path"].(string),
		PathVLESSWS:    vlessWS["transport"].(map[string]any)["path"].(string),

		RegionTag: tagVLESS[:indexOf(tagVLESS, "vless-out-")],

		Tags: clientconfig.Tags{
			Hysteria2: tagHy2, TUIC: tagTUIC, VLESS: tagVLESS, Trojan: tagTrojan,
			AnyTLS: tagAnyTLS, VmessReality: tagVmessReal, VmessWSTLS: tagVmessWS, VlessWS: tagVlessWS,
		},
		CF: clientconfig.CFParams{
			Domain:    cfDomainOb["server"].(string),
			NATServer: natServer, NATPort: natPort,
			ProxyIP: proxyIP, ProxyIPPort: proxyIPPort,
		},
	}

	// 重放 CF 节点 tag 里的随机后缀：按 cfNodeTable 的固定顺序，把 golden
	// 文件里对应的 21 个 "cf-ob-*" tag 后缀依次弹出，而不是重新随机生成——
	// 这样生成结果才能跟 golden 逐字节对上。
	cfSuffixes := extractCFSuffixesInOrder("testdata/golden_client.json")
	idx := 0
	nextSuffix := func() string {
		s := cfSuffixes[idx]
		idx++
		return s
	}

	writeConfig := func(name string, cfg *clientconfig.Config) {
		out := must(json.MarshalIndent(cfg, "", "  "))
		if err := os.WriteFile(name, out, 0o644); err != nil {
			panic(err)
		}
	}

	latest := clientconfig.BuildLatest(p, clientconfig.LatestOptions{
		IncludeCF: true, IncludePrivateRule: true, IncludeAnyTLS: true, MixedListen: "0.0.0.0",
	}, nextSuffix)
	clientconfig.ApplyClassification(latest)
	writeConfig("generated_client.json", latest)

	// OpenWrt 用同一批 UUID/密码/端口（因为都是同一次运行产出的三份文件），
	// 但没有 CF 节点，所以不消耗 nextSuffix。
	openwrt := clientconfig.BuildLatest(p, clientconfig.LatestOptions{
		TUNInterfaceName: "tun0", IncludeCF: false, IncludePrivateRule: false, IncludeAnyTLS: true,
	}, nextSuffix)
	clientconfig.ApplyClassification(openwrt)
	writeConfig("generated_client_openwrt.json", openwrt)

	idx = 0 // 1.11.4 是另一份独立文件，重新从头消耗同一批 CF 后缀
	legacy := clientconfig.Build1114(p, nextSuffix)
	clientconfig.ApplyClassification(legacy)
	writeConfig("generated_client_1114.json", legacy)

	fmt.Println("生成完毕: generated_client.json / generated_client_openwrt.json / generated_client_1114.json")
}

func extractCFSuffixesInOrder(path string) []string {
	raw := must(os.ReadFile(path))
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		panic(err)
	}
	// 固定顺序，跟 clientconfig 内部 cfNodeTable() 的表顺序一致。按长度从长到短
	// 排列做前缀匹配，这样 "CF-104.16-443-NAT" 不会被短的 "CF-104.16-443" 抢先误配。
	order := []string{
		"CF-104.16-443", "CF-104.16-443-NAT", "CF-104.17-8443", "CF-104.17-8443-NAT",
		"CF-104.18-2053", "CF-104.18-2053-NAT", "CF-104.19-2083", "CF-104.19-2083-NAT",
		"CF-104.20-2087", "CF-104.20-2087-NAT", "CF-104.21-80", "CF-104.21-80-NAT",
		"CF-104.22-8080", "CF-104.22-8080-NAT", "CF-104.24-8880", "CF-104.24-8880-NAT",
		"CF-Domain-443", "CF-Domain-443-NAT", "CF-Domain-80", "CF-Domain-80-NAT", "CF-ProxyIP",
	}
	byLenDesc := append([]string(nil), order...)
	for i := 0; i < len(byLenDesc); i++ {
		for j := i + 1; j < len(byLenDesc); j++ {
			if len(byLenDesc[j]) > len(byLenDesc[i]) {
				byLenDesc[i], byLenDesc[j] = byLenDesc[j], byLenDesc[i]
			}
		}
	}

	tags := make(map[string]string) // name -> 随机后缀
	for _, ob := range doc["outbounds"].([]any) {
		m := ob.(map[string]any)
		tag := m["tag"].(string)
		i := indexOf(tag, "cf-ob-")
		if i < 0 {
			continue
		}
		rest := tag[i+len("cf-ob-"):] // 例如 "CF-104.16-443-NAT-c892ff...54022"
		for _, name := range byLenDesc {
			prefix := name + "-"
			if len(rest) > len(prefix) && rest[:len(prefix)] == prefix {
				tags[name] = rest[len(prefix):]
				break
			}
		}
	}

	suffixes := make([]string, 0, len(order))
	for _, name := range order {
		suffix, ok := tags[name]
		if !ok {
			panic("golden client.json 里缺少 CF 节点: " + name)
		}
		suffixes = append(suffixes, suffix)
	}
	return suffixes
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
