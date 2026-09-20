package main

import (
	"encoding/json"
	"strings"

	"singboxprovision/internal/clientconfig"
	"singboxprovision/internal/links"
	"singboxprovision/internal/portcheck"
	"singboxprovision/internal/randgen"
	"singboxprovision/internal/report"
	"singboxprovision/internal/sysconfig"
)

// randomValues 把 randgen 生成的一大堆值集中放一处，main() 里不用满屏
// 都是零散的局部变量。
type randomValues struct {
	uuidVLESS, uuidTUIC, uuidVmessReality, uuidVmessWSTLS, uuidVlessWS string

	passwordHysteria2, passwordTUIC, passwordTrojan, passwordAnyTLS string
	hy2ObfsPassword                                                 string

	shortIDsVLESS, shortIDsTrojan, shortIDsAnyTLS, shortIDsVmessReality []string

	realityPrivateKey, realityPublicKey string

	paddingScheme []string

	pathVmessWSTLS, pathVlessWS string
}

func generateRandomValues() randomValues {
	priv, pub, err := randgen.RealityKeyPair()
	must(err)

	return randomValues{
		uuidVLESS: randgen.NewUUID(), uuidTUIC: randgen.NewUUID(),
		uuidVmessReality: randgen.NewUUID(), uuidVmessWSTLS: randgen.NewUUID(), uuidVlessWS: randgen.NewUUID(),

		passwordHysteria2: randgen.HexPassword(), passwordTUIC: randgen.HexPassword(),
		passwordTrojan: randgen.HexPassword(), passwordAnyTLS: randgen.HexPassword(),
		hy2ObfsPassword: randgen.HexPassword(),

		shortIDsVLESS: randgen.ManyShortIDs(), shortIDsTrojan: randgen.ManyShortIDs(),
		shortIDsAnyTLS: randgen.ManyShortIDs(), shortIDsVmessReality: randgen.ManyShortIDs(),

		realityPrivateKey: priv, realityPublicKey: pub,

		paddingScheme: randgen.PaddingScheme(),

		pathVmessWSTLS: randgen.ShortID(), pathVlessWS: randgen.ShortID(),
	}
}

func stripDashes(s string) string {
	return strings.ReplaceAll(s, "-", "")
}

// buildAllLinks 按 SUBSCRIPTION_CONTENT 的固定顺序（VLESS,Trojan,AnyTLS,
// Hysteria2,TUIC,VmessReality,VmessWSTLS,VlessWS，然后是 CF 节点）拼出
// 全部分享链接。CF 节点链接不重新查一遍 CF 节点表——直接从已经生成好的
// client.json 的 outbounds 里回收 server/port/tls 这些字段，保证链接
// 内容和 JSON 配置里的 CF 出站是同一个数据来源，不会出现两边各自维护
// 一份、哪天改了一边忘了改另一边导致的不一致。
func buildAllLinks(p clientconfig.Params, cfOutbounds []clientconfig.Outbound) (allLinks []string, cfEntries []report.CFEntry) {
	const insecureReality = "0"

	vless := links.VLESS(links.RealityLink{
		Credential: p.UUIDVLESS, ServerIP: p.ServerIP, Port: p.PortVLESS,
		SNI: p.BestDomain, Insecure: insecureReality, Fingerprint: p.FingerprintType,
		PublicKey: p.PublicKey, ShortID: p.ShortIDVLESS, Tag: p.Tags.VLESS,
	})
	trojan := links.Trojan(links.RealityLink{
		Credential: p.PasswordTrojan, ServerIP: p.ServerIP, Port: p.PortTrojan,
		SNI: p.BestDomain, Insecure: insecureReality, Fingerprint: p.FingerprintType,
		PublicKey: p.PublicKey, ShortID: p.ShortIDTrojan, Tag: p.Tags.Trojan,
	})
	anytls := links.AnyTLS(links.RealityLink{
		Credential: p.PasswordAnyTLS, ServerIP: p.ServerIP, Port: p.PortAnyTLS,
		SNI: p.BestDomain, Insecure: insecureReality, Fingerprint: p.FingerprintType,
		PublicKey: p.PublicKey, ShortID: p.ShortIDAnyTLS, Tag: p.Tags.AnyTLS,
	})
	hy2 := links.Hysteria2(links.Hysteria2Params{
		Password: p.PasswordHysteria2, ServerIP: p.ServerIP, Port: p.PortHysteria2,
		ObfsType: p.HY2ObfsType, ObfsPassword: p.HY2ObfsPassword,
		ALPN: "h3", SNI: p.BestDomain, Insecure: "1", Tag: p.Tags.Hysteria2,
	})
	tuic := links.TUIC(links.TUICParams{
		UUID: p.UUIDTUIC, Password: p.PasswordTUIC, ServerIP: p.ServerIP, Port: p.PortTUIC,
		ALPN: "h3", SNI: p.BestDomain, Insecure: "1", Tag: p.Tags.TUIC,
	})
	vmessReal := links.VmessReality(links.VmessRealityParams{
		Tag: p.Tags.VmessReality, ServerIP: p.ServerIP, Port: p.PortVmessReality,
		UUID: p.UUIDVmessReality, SNI: p.BestDomain, PublicKey: p.PublicKey,
		ShortID: p.ShortIDVmessReality, Fingerprint: p.FingerprintType, AllowInsecure: "0",
	})
	vmessWS := links.VmessWSTLS(links.VmessWSTLSParams{
		Tag: p.Tags.VmessWSTLS, ServerIP: p.ServerIP, Port: p.PortVmessWSTLS,
		UUID: p.UUIDVmessWSTLS, Host: p.BestDomain, Path: p.PathVmessWSTLS,
		SNI: p.BestDomain, AllowInsecure: "1", ALPN: "http/1.1",
	})
	vlessWS := links.VlessWS(links.VlessWSParams{
		Tag: p.Tags.VlessWS, UUID: p.UUIDVlessWS, ServerIP: p.ServerIP, Port: p.PortVlessWS,
		Host: p.BestDomain, Path: p.PathVLESSWS, TLS: false,
	})

	allLinks = []string{vless, trojan, anytls, hy2, tuic, vmessReal, vmessWS, vlessWS}

	for _, ob := range cfOutbounds {
		vp := links.VlessWSParams{
			Tag: ob.Tag, UUID: p.UUIDVlessWS, ServerIP: ob.Server, Port: ob.ServerPort,
			Path: p.PathVLESSWS,
		}
		if ob.TLS != nil {
			vp.TLS = true
			vp.Host = ob.TLS.ServerName
			vp.SNI = ob.TLS.ServerName
			vp.AllowInsecure = "0"
			vp.ALPN = "http/1.1"
			vp.Fingerprint = p.FingerprintType
		} else if ob.Transport != nil {
			vp.Host = ob.Transport.Headers["Host"]
		}
		link := links.VlessWS(vp)
		allLinks = append(allLinks, link)
		cfEntries = append(cfEntries, report.CFEntry{Tag: ob.Tag, Link: link})
	}

	return allLinks, cfEntries
}

// cfOutboundsOf 从一份已经生成好的客户端配置里挑出 tag 含 "cf-ob-" 的
// 出站——顺序就是它们在 Outbounds 里出现的顺序，跟 subscription.txt 里
// 的顺序一致。
func cfOutboundsOf(cfg *clientconfig.Config) []clientconfig.Outbound {
	var out []clientconfig.Outbound
	for _, ob := range cfg.Outbounds {
		if strings.Contains(ob.Tag, "cf-ob-") {
			out = append(out, ob)
		}
	}
	return out
}

func firewallRules(p *portcheck.Ports) []sysconfig.PortRule {
	return []sysconfig.PortRule{
		{Port: p.VLESS, Proto: "tcp", Comment: "sing-box:vless-reality"},
		{Port: p.Trojan, Proto: "tcp", Comment: "sing-box:trojan-reality"},
		{Port: p.AnyTLS, Proto: "tcp", Comment: "sing-box:anytls"},
		{Port: p.VmessReality, Proto: "tcp", Comment: "sing-box:vmess-reality"},
		{Port: p.VmessWSTLS, Proto: "tcp", Comment: "sing-box:vmess-ws-tls"},
		{Port: p.VlessWS, Proto: "tcp", Comment: "sing-box:vless-ws"},
		{Port: p.Hysteria2, Proto: "udp", Comment: "sing-box:hysteria2"},
		{Port: p.TUIC, Proto: "udp", Comment: "sing-box:tuic"},
	}
}

func jsonMarshalIndent(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
