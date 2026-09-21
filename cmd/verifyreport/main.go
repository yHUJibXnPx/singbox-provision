package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"singboxprovision/internal/report"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func loadJSON(path string) map[string]any {
	raw := must(os.ReadFile(path))
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(err)
	}
	return m
}

func inboundsByTag(doc map[string]any) map[string]map[string]any {
	m := map[string]map[string]any{}
	for _, ib := range doc["inbounds"].([]any) {
		x := ib.(map[string]any)
		m[x["tag"].(string)] = x
	}
	return m
}

func outboundsByTag(doc map[string]any) map[string]map[string]any {
	m := map[string]map[string]any{}
	for _, ob := range doc["outbounds"].([]any) {
		x := ob.(map[string]any)
		if tag, ok := x["tag"].(string); ok {
			m[tag] = x
		}
	}
	return m
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func findByTag(m map[string]map[string]any, needle string, excludeCF bool) (string, map[string]any) {
	for tag, v := range m {
		if !contains(tag, needle) {
			continue
		}
		if excludeCF && contains(tag, "cf-ob-") {
			continue
		}
		return tag, v
	}
	panic("找不到 " + needle)
}

func strSlice(v any) []string {
	arr := v.([]any)
	out := make([]string, len(arr))
	for i, x := range arr {
		out[i] = x.(string)
	}
	return out
}

func main() {
	server := loadJSON("testdata/golden_config.json")
	client := loadJSON("testdata/golden_client.json")
	sIn := inboundsByTag(server)
	cOut := outboundsByTag(client)

	_, sVLESS := findByTag(sIn, "vless-in", false)
	_, sTrojan := findByTag(sIn, "trojan-in", false)
	_, sAnyTLS := findByTag(sIn, "anytls-in", false)
	_, sVmessReal := findByTag(sIn, "vmess-reality-in", false)
	realityOfServer := func(m map[string]any) map[string]any { return m["tls"].(map[string]any)["reality"].(map[string]any) }

	_, cVLESS := findByTag(cOut, "vless-out-", true)
	_, cTrojan := findByTag(cOut, "trojan-out-", true)
	_, cAnyTLS := findByTag(cOut, "anytls-out-", true)
	_, cHy2 := findByTag(cOut, "hysteria2-out-", true)
	_, cTUIC := findByTag(cOut, "tuic-out-", true)
	_, cVmessReal := findByTag(cOut, "vmess-reality-out-", true)
	_, cVmessWS := findByTag(cOut, "vmess-ws-tls-out-", true)
	_, cVlessWS := findByTag(cOut, "vless-ws-out-", true)

	realityOfClient := func(m map[string]any) map[string]any { return m["tls"].(map[string]any)["reality"].(map[string]any) }
	publicKey := realityOfClient(cVLESS)["public_key"].(string)
	bestDomain := cVLESS["tls"].(map[string]any)["server_name"].(string)
	serverIP := cVLESS["server"].(string)

	// CF 节点：按 golden result.txt 里出现的顺序重建（跟 verifylinks 用的
	// 是同一个"按订阅文件真实顺序排序"的技巧）。
	subRaw := string(must(os.ReadFile("testdata/golden_subscription.txt")))
	var cfTags []string
	for tag := range cOut {
		if contains(tag, "cf-ob-") {
			cfTags = append(cfTags, tag)
		}
	}
	orderIndex := func(tag string) int { return indexOf(subRaw, "#"+tag) }
	for i := 1; i < len(cfTags); i++ {
		for j := i; j > 0 && orderIndex(cfTags[j-1]) > orderIndex(cfTags[j]); j-- {
			cfTags[j-1], cfTags[j] = cfTags[j], cfTags[j-1]
		}
	}

	// 从 subscription.txt 里把链接原文抠出来，不重新拼一遍——链接内容本身
	// 已经在 verifylinks 里逐字节验证过了，report 这一步只关心排版格式
	// 对不对。8 个直连协议链接用"按固定顺序取行"而不是"按 #tag 找"：
	// vmess:// 链接的 tag 是编码在 base64 JSON 里的（ps 字段），URI 本身
	// 没有 "#tag" 这个片段，用 marker 搜索会找不到——这是写这一步时
	// 真实踩到的一个坑，CF 节点（都是 vless://）不受影响，只有两条
	// vmess 链接需要换成按行号取。
	subLines := strings.Split(strings.TrimRight(subRaw, "\n"), "\n")
	coreLink := func(i int) string { return subLines[i] } // 0=VLESS 1=Trojan 2=AnyTLS 3=Hysteria2 4=TUIC 5=VmessReality 6=VmessWSTLS 7=VlessWS

	extractLink := func(tag string) string {
		marker := "#" + tag
		pos := strings.Index(subRaw, marker)
		lineStart := strings.LastIndex(subRaw[:pos], "\n") + 1
		lineEnd := strings.Index(subRaw[lineStart:], "\n") + lineStart
		return subRaw[lineStart:lineEnd]
	}

	var cfEntries []report.CFEntry
	for _, tag := range cfTags {
		cfEntries = append(cfEntries, report.CFEntry{Tag: tag, Link: extractLink(tag)})
	}

	p := report.Params{
		ServerIP:       serverIP,
		SingBoxVersion: "v1.15.0-alpha.2",
		PublicKey:      publicKey,
		PrivateKey:     realityOfServer(sVLESS)["private_key"].(string),

		UUIDVLESS: cVLESS["uuid"].(string), UUIDTUIC: cTUIC["uuid"].(string),
		UUIDVmessReality: cVmessReal["uuid"].(string), UUIDVmessWSTLS: cVmessWS["uuid"].(string),
		UUIDVlessWS: cVlessWS["uuid"].(string),

		PasswordHysteria2: cHy2["password"].(string), PasswordTUIC: cTUIC["password"].(string),
		PasswordTrojan: cTrojan["password"].(string), PasswordAnyTLS: cAnyTLS["password"].(string),

		HY2ObfsType:     cHy2["obfs"].(map[string]any)["type"].(string),
		HY2ObfsPassword: cHy2["obfs"].(map[string]any)["password"].(string),

		BestDomain:             bestDomain,
		CloudflaredDomain:      "eddie-adding-preferences-accessibility.trycloudflare.com",
		CloudflaredProxyIP:     "cloudflare.182682.xyz",
		CloudflaredProxyIPPort: 443,
		ServerCFNAT:            "127.0.0.1",
		PortCFNAT:              1234,

		PortVLESS: int(cVLESS["server_port"].(float64)), PortTrojan: int(cTrojan["server_port"].(float64)),
		PortAnyTLS: int(cAnyTLS["server_port"].(float64)), PortHysteria2: int(cHy2["server_port"].(float64)),
		PortTUIC: int(cTUIC["server_port"].(float64)), PortVmessReality: int(cVmessReal["server_port"].(float64)),
		PortVmessWSTLS: int(cVmessWS["server_port"].(float64)), PortVlessWS: int(cVlessWS["server_port"].(float64)),

		ShortIDsVLESS: strSlice(realityOfServer(sVLESS)["short_id"]), ShortIDsTrojan: strSlice(realityOfServer(sTrojan)["short_id"]),
		ShortIDsAnyTLS:       strSlice(realityOfServer(sAnyTLS)["short_id"]),
		ShortIDsVmessReality: strSlice(realityOfServer(sVmessReal)["short_id"]),

		// subscription.txt 里 8 条直连链接的行号顺序是 VLESS,Trojan,AnyTLS,
		// Hysteria2,TUIC,VmessReality,VmessWSTLS,VlessWS（跟 SUBSCRIPTION_
		// CONTENT 的拼接顺序一致），但 result.txt 里 [1]~[8] 展示的顺序是
		// VLESS,Trojan,VmessReality,VmessWSTLS,VlessWS,Hysteria2,TUIC,AnyTLS
		// ——两处顺序不一样，是原脚本自己的设计（不是我搞乱的），报告模板要
		// 用后一种顺序，所以这里显式按名字取行号，不能直接按下标顺序照搬。
		LinkVLESS: coreLink(0), LinkTrojan: coreLink(1), LinkAnyTLS: coreLink(2),
		LinkHysteria2: coreLink(3), LinkTUIC: coreLink(4),
		LinkVmessReality: coreLink(5), LinkVmessWSTLS: coreLink(6), LinkVlessWS: coreLink(7),

		CFEntries:          cfEntries,
		SubscriptionBase64: strings.TrimRight(string(must(os.ReadFile("testdata/golden_subscription_base64.txt"))), "\n"),

		WorkDir: "/root",
	}

	out := report.Build(p)
	must(writeFile("generated_result.txt", out))
	fmt.Println("生成完毕: generated_result.txt")
}

func writeFile(path, content string) (int, error) {
	return 0, os.WriteFile(path, []byte(content), 0o644)
}

func indexOf(s, sub string) int {
	i := strings.Index(s, sub)
	return i
}
