// cmd/verify 不是最终交付的程序，是这一轮用来"自证"的验证脚手架：
// 把你上传的真实 config.json 里的参数抠出来，喂给 sbconfig.BuildServerConfig，
// 看 Go 生成的结构跟真实跑出来的原文件是否一致。
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"singboxprovision/internal/sbconfig"
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

func main() {
	raw := must(os.ReadFile("testdata/golden_config.json"))
	var golden map[string]any
	if err := json.Unmarshal(raw, &golden); err != nil {
		panic(err)
	}

	inbounds := golden["inbounds"].([]any)
	byTag := map[string]map[string]any{}
	for _, ib := range inbounds {
		m := ib.(map[string]any)
		byTag[m["tag"].(string)] = m
	}

	hy2 := byTag["hysteria2-in"]
	tuic := byTag["tuic-in"]
	vless := byTag["vless-in"]
	trojan := byTag["trojan-in"]
	anytls := byTag["anytls-in"]
	vmessReal := byTag["vmess-reality-in"]
	vmessWS := byTag["vmess-ws-tls-in"]
	vlessWS := byTag["vless-ws-in"]

	firstUser := func(m map[string]any) map[string]any {
		return m["users"].([]any)[0].(map[string]any)
	}
	tlsOf := func(m map[string]any) map[string]any { return m["tls"].(map[string]any) }
	realityOf := func(m map[string]any) map[string]any { return tlsOf(m)["reality"].(map[string]any) }

	params := sbconfig.ServerParams{
		BestDomain:        tlsOf(vless)["server_name"].(string),
		RealityPrivateKey: realityOf(vless)["private_key"].(string),
		ShortIDsVLESS:     strSlice(realityOf(vless)["short_id"]),
		ShortIDsTrojan:    strSlice(realityOf(trojan)["short_id"]),
		ShortIDsAnyTLS:    strSlice(realityOf(anytls)["short_id"]),
		ShortIDsVmessReal: strSlice(realityOf(vmessReal)["short_id"]),

		PortHysteria2:    int(hy2["listen_port"].(float64)),
		PortTUIC:         int(tuic["listen_port"].(float64)),
		PortVLESS:        int(vless["listen_port"].(float64)),
		PortTrojan:       int(trojan["listen_port"].(float64)),
		PortAnyTLS:       int(anytls["listen_port"].(float64)),
		PortVmessReality: int(vmessReal["listen_port"].(float64)),
		PortVmessWSTLS:   int(vmessWS["listen_port"].(float64)),
		PortVlessWS:      int(vlessWS["listen_port"].(float64)),

		UUIDVLESS:        firstUser(vless)["uuid"].(string),
		UUIDTUIC:         firstUser(tuic)["uuid"].(string),
		UUIDVmessReality: firstUser(vmessReal)["uuid"].(string),
		UUIDVmessWSTLS:   firstUser(vmessWS)["uuid"].(string),
		UUIDVlessWS:      firstUser(vlessWS)["uuid"].(string),

		PasswordHysteria2: firstUser(hy2)["password"].(string),
		PasswordTUIC:      firstUser(tuic)["password"].(string),
		PasswordTrojan:    firstUser(trojan)["password"].(string),
		PasswordAnyTLS:    firstUser(anytls)["password"].(string),

		HY2ObfsType:     hy2["obfs"].(map[string]any)["type"].(string),
		HY2ObfsPassword: hy2["obfs"].(map[string]any)["password"].(string),

		PaddingScheme: strSlice(anytls["padding_scheme"]),

		PathVmessWSTLS: vmessWS["transport"].(map[string]any)["path"].(string),
		PathVLESSWS:    vlessWS["transport"].(map[string]any)["path"].(string),

		CertLines: strSlice(tlsOf(hy2)["certificate"]),
		KeyLines:  strSlice(tlsOf(hy2)["key"]),
	}

	cfg := sbconfig.BuildServerConfig(params)
	out := must(json.MarshalIndent(cfg, "", "  "))
	if err := os.WriteFile("generated_config.json", out, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("生成完毕: generated_config.json")
}
