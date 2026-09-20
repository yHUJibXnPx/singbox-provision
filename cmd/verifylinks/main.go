// cmd/verifylinks 用真实的 golden_config.json + golden_client.json 反推
// 参数，生成全部分享链接和订阅文件，字节级比对 testdata 里的原始
// subscription.txt / subscription_base64.txt。
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"singboxprovision/internal/links"
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

func outboundsByTag(doc map[string]any) map[string]map[string]any {
	byTag := map[string]map[string]any{}
	for _, ob := range doc["outbounds"].([]any) {
		m := ob.(map[string]any)
		if tag, ok := m["tag"].(string); ok {
			byTag[tag] = m
		}
	}
	return byTag
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func findTag(byTag map[string]map[string]any, needle string) (string, map[string]any) {
	for tag, m := range byTag {
		if contains(tag, needle) && !contains(tag, "cf-ob-") {
			return tag, m
		}
	}
	panic("找不到包含 " + needle + " 的非-CF tag")
}

func main() {
	server := outboundsByTag(loadJSON("testdata/golden_config.json")) // 未使用，保留以防以后要对服务端字段
	_ = server
	client := outboundsByTag(loadJSON("testdata/golden_client.json"))

	tagVLESS, cVLESS := findTag(client, "vless-out-")
	tagTrojan, cTrojan := findTag(client, "trojan-out-")
	tagAnyTLS, cAnyTLS := findTag(client, "anytls-out-")
	tagHy2, cHy2 := findTag(client, "hysteria2-out-")
	tagTUIC, cTUIC := findTag(client, "tuic-out-")
	tagVmessReal, cVmessReal := findTag(client, "vmess-reality-out-")
	tagVmessWS, cVmessWS := findTag(client, "vmess-ws-tls-out-")
	tagVlessWS, cVlessWS := findTag(client, "vless-ws-out-")

	bestDomain := cVLESS["tls"].(map[string]any)["server_name"].(string)
	realityOfClient := func(m map[string]any) map[string]any { return m["tls"].(map[string]any)["reality"].(map[string]any) }
	publicKeyStr := realityOfClient(cVLESS)["public_key"].(string)

	serverIP := cVLESS["server"].(string)

	allLinks := []string{
		links.VLESS(links.RealityLink{
			Credential: cVLESS["uuid"].(string), ServerIP: serverIP, Port: int(cVLESS["server_port"].(float64)),
			SNI: bestDomain, Insecure: "0", Fingerprint: "firefox", PublicKey: publicKeyStr,
			ShortID: realityOfClient(cVLESS)["short_id"].(string), Tag: tagVLESS,
		}),
		links.Trojan(links.RealityLink{
			Credential: cTrojan["password"].(string), ServerIP: serverIP, Port: int(cTrojan["server_port"].(float64)),
			SNI: bestDomain, Insecure: "0", Fingerprint: "firefox", PublicKey: publicKeyStr,
			ShortID: realityOfClient(cTrojan)["short_id"].(string), Tag: tagTrojan,
		}),
		links.AnyTLS(links.RealityLink{
			Credential: cAnyTLS["password"].(string), ServerIP: serverIP, Port: int(cAnyTLS["server_port"].(float64)),
			SNI: bestDomain, Insecure: "0", Fingerprint: "firefox", PublicKey: publicKeyStr,
			ShortID: realityOfClient(cAnyTLS)["short_id"].(string), Tag: tagAnyTLS,
		}),
		links.Hysteria2(links.Hysteria2Params{
			Password: cHy2["password"].(string), ServerIP: serverIP, Port: int(cHy2["server_port"].(float64)),
			ObfsType:     cHy2["obfs"].(map[string]any)["type"].(string),
			ObfsPassword: cHy2["obfs"].(map[string]any)["password"].(string),
			ALPN:         "h3", SNI: bestDomain, Insecure: "1", Tag: tagHy2,
		}),
		links.TUIC(links.TUICParams{
			UUID: cTUIC["uuid"].(string), Password: cTUIC["password"].(string), ServerIP: serverIP,
			Port: int(cTUIC["server_port"].(float64)), ALPN: "h3", SNI: bestDomain, Insecure: "1", Tag: tagTUIC,
		}),
		links.VmessReality(links.VmessRealityParams{
			Tag: tagVmessReal, ServerIP: serverIP, Port: int(cVmessReal["server_port"].(float64)),
			UUID: cVmessReal["uuid"].(string), SNI: bestDomain, PublicKey: publicKeyStr,
			ShortID: realityOfClient(cVmessReal)["short_id"].(string), Fingerprint: "firefox", AllowInsecure: "0",
		}),
		links.VmessWSTLS(links.VmessWSTLSParams{
			Tag: tagVmessWS, ServerIP: serverIP, Port: int(cVmessWS["server_port"].(float64)),
			UUID: cVmessWS["uuid"].(string), Host: bestDomain,
			Path: cVmessWS["transport"].(map[string]any)["path"].(string),
			SNI:  bestDomain, AllowInsecure: "1", ALPN: "http/1.1",
		}),
		links.VlessWS(links.VlessWSParams{
			Tag: tagVlessWS, UUID: cVlessWS["uuid"].(string), ServerIP: serverIP,
			Port: int(cVlessWS["server_port"].(float64)), Host: bestDomain,
			Path: cVlessWS["transport"].(map[string]any)["path"].(string), TLS: false,
		}),
	}

	// CF 节点链接：按 golden client.json 里出现的顺序遍历所有 cf-ob- 出站。
	var cfTagsInOrder []string
	for tag := range client {
		if contains(tag, "cf-ob-") {
			cfTagsInOrder = append(cfTagsInOrder, tag)
		}
	}
	// 用 subscription.txt 里的真实顺序而不是 map 遍历顺序：读订阅文件，
	// 按其中出现的 tag 顺序排序 cfTagsInOrder。
	subRaw := string(must(os.ReadFile("testdata/golden_subscription.txt")))
	orderIndex := func(tag string) int {
		return indexOf(subRaw, "#"+tag)
	}
	sortByOrder(cfTagsInOrder, orderIndex)

	vlessWSUUID := cVlessWS["uuid"].(string)
	vlessWSPath := cVlessWS["transport"].(map[string]any)["path"].(string)
	for _, tag := range cfTagsInOrder {
		ob := client[tag]
		hasTLS := ob["tls"] != nil
		p := links.VlessWSParams{
			Tag: tag, UUID: vlessWSUUID, ServerIP: ob["server"].(string),
			Port: int(ob["server_port"].(float64)), Path: vlessWSPath,
		}
		if hasTLS {
			tls := ob["tls"].(map[string]any)
			p.TLS = true
			p.Host = tls["server_name"].(string)
			p.SNI = tls["server_name"].(string)
			p.AllowInsecure = "0"
			p.ALPN = "http/1.1"
			p.Fingerprint = "firefox"
		} else {
			p.Host = ob["transport"].(map[string]any)["headers"].(map[string]any)["Host"].(string)
		}
		allLinks = append(allLinks, links.VlessWS(p))
	}

	subContent, subBase64 := links.Subscription(allLinks)
	must(writeFile("generated_subscription.txt", subContent))
	must(writeFile("generated_subscription_base64.txt", subBase64))
	fmt.Println("生成完毕: generated_subscription.txt / generated_subscription_base64.txt")
}

func writeFile(path, content string) (int, error) {
	return 0, os.WriteFile(path, []byte(content), 0o644)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func sortByOrder(tags []string, orderIndex func(string) int) {
	for i := 1; i < len(tags); i++ {
		for j := i; j > 0 && orderIndex(tags[j-1]) > orderIndex(tags[j]); j-- {
			tags[j-1], tags[j] = tags[j], tags[j-1]
		}
	}
}
