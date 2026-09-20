package clientconfig

import "singboxprovision/internal/sbconfig"

// sharedProtocolOutbounds 对应原脚本 get_shared_outbounds()：TUIC / Hysteria2
// / VLESS / Trojan / VmessReality / VmessWSTLS / VlessWS 这 7 个协议出站，
// 三个客户端变体完全共用。字段跟你上传的真实 client.json 逐条核对过。
func sharedProtocolOutbounds(p Params) []Outbound {
	utls := &UTLS{Enabled: true, Fingerprint: p.FingerprintType}

	return []Outbound{
		{
			Type: "tuic", Tag: p.Tags.TUIC, Server: p.ServerIP, ServerPort: p.PortTUIC,
			UUID: p.UUIDTUIC, Password: p.PasswordTUIC, CongestionControl: "bbr",
			TLS: &ClientTLS{Enabled: true, ServerName: p.BestDomain, Insecure: false,
				Certificate: p.CertLines, ALPN: []string{"h3"}},
		},
		{
			Type: "hysteria2", Tag: p.Tags.Hysteria2, Server: p.ServerIP, ServerPort: p.PortHysteria2,
			Password: p.PasswordHysteria2,
			Obfs:     &sbconfig.Obfs{Type: p.HY2ObfsType, Password: p.HY2ObfsPassword},
			TLS: &ClientTLS{Enabled: true, ServerName: p.BestDomain, Insecure: false,
				Certificate: p.CertLines, ALPN: []string{"h3"}},
		},
		{
			Type: "vless", Tag: p.Tags.VLESS, Server: p.ServerIP, ServerPort: p.PortVLESS,
			UUID: p.UUIDVLESS, Flow: "xtls-rprx-vision", PacketEncoding: "xudp",
			TLS: &ClientTLS{Enabled: true, ServerName: p.BestDomain, Insecure: false, UTLS: utls,
				Reality: &ClientReality{Enabled: true, PublicKey: p.PublicKey, ShortID: p.ShortIDVLESS}},
		},
		{
			Type: "trojan", Tag: p.Tags.Trojan, Server: p.ServerIP, ServerPort: p.PortTrojan,
			Password: p.PasswordTrojan,
			TLS: &ClientTLS{Enabled: true, ServerName: p.BestDomain, Insecure: false, UTLS: utls,
				Reality: &ClientReality{Enabled: true, PublicKey: p.PublicKey, ShortID: p.ShortIDTrojan}},
		},
		{
			Type: "vmess", Tag: p.Tags.VmessReality, Server: p.ServerIP, ServerPort: p.PortVmessReality,
			UUID: p.UUIDVmessReality, Security: "auto", PacketEncoding: "xudp",
			TLS: &ClientTLS{Enabled: true, ServerName: p.BestDomain, Insecure: false, UTLS: utls,
				Reality: &ClientReality{Enabled: true, PublicKey: p.PublicKey, ShortID: p.ShortIDVmessReality}},
		},
		{
			Type: "vmess", Tag: p.Tags.VmessWSTLS, Server: p.ServerIP, ServerPort: p.PortVmessWSTLS,
			UUID: p.UUIDVmessWSTLS, Security: "auto", PacketEncoding: "xudp",
			// Insecure 改成 false 并锁定证书，跟 Hysteria2/TUIC 保持一致——
			// 三者用的是同一份自签证书，没理由单独放宽这一个协议的校验。
			TLS: &ClientTLS{Enabled: true, ServerName: p.BestDomain, Insecure: false,
				Certificate: p.CertLines, ALPN: []string{"http/1.1"}},
			Transport: &sbconfig.Transport{Type: "ws", Path: p.PathVmessWSTLS,
				Headers: map[string]string{"Host": p.BestDomain}, EarlyDataHeaderName: "Sec-WebSocket-Protocol"},
		},
		{
			Type: "vless", Tag: p.Tags.VlessWS, Server: p.ServerIP, ServerPort: p.PortVlessWS,
			UUID: p.UUIDVlessWS, PacketEncoding: "xudp",
			Transport: &sbconfig.Transport{Type: "ws", Path: p.PathVLESSWS,
				Headers: map[string]string{"Host": p.BestDomain}},
		},
	}
}

// anytlsOutbound 对应 get_shared_outbounds_anytls()。client_1.11.4.json
// 不含这一个（1.11.4 不支持 AnyTLS），由调用方决定要不要拼进去。
func anytlsOutbound(p Params) Outbound {
	return Outbound{
		Type: "anytls", Tag: p.Tags.AnyTLS, Server: p.ServerIP, ServerPort: p.PortAnyTLS,
		Password: p.PasswordAnyTLS,
		TLS: &ClientTLS{Enabled: true, ServerName: p.BestDomain, Insecure: false,
			UTLS:    &UTLS{Enabled: true, Fingerprint: p.FingerprintType},
			Reality: &ClientReality{Enabled: true, PublicKey: p.PublicKey, ShortID: p.ShortIDAnyTLS}},
	}
}

// cfOutbounds 对应 build_cf_data()：把 CF_NODES 静态表转成 vless-ws 出站 +
// 对应的 tag 列表（后者用来拼进"自动"/"手动"urltest/selector 的引用数组）。
// p.CF.Domain 和 p.CF.ProxyIP 留空时，对应几个节点自动不生成——不需要专门
// 判断"要不要走 CF 隧道这条功能"，数据表本身的留白就表达了这件事。
func cfOutbounds(p Params, randHex func() string) (outbounds []Outbound, tags []string) {
	for _, spec := range cfNodeTable(p.CF) {
		tag := p.RegionTag + "cf-ob-" + spec.name + "-" + randHex()
		ob := Outbound{
			Type: "vless", Tag: tag, Server: spec.host, ServerPort: spec.port,
			UUID: p.UUIDVlessWS, PacketEncoding: "xudp",
			// 注意 Host 是 CF 隧道的域名（p.CF.Domain），不是 Reality 用的
			// p.BestDomain——这两个域名服务于完全不同的目的，抄错一个字段名
			// 就会导致 CF 节点全部连不上，是这一步验证抓出来的一处真实 bug。
			Transport: &sbconfig.Transport{Type: "ws", Path: p.PathVLESSWS,
				Headers: map[string]string{"Host": p.CF.Domain}},
		}
		if spec.tls {
			ob.TLS = &ClientTLS{
				Enabled: true, ServerName: p.CF.Domain, Insecure: false,
				ALPN: []string{"http/1.1"},
				UTLS: &UTLS{Enabled: true, Fingerprint: p.FingerprintType},
			}
		}
		outbounds = append(outbounds, ob)
		tags = append(tags, tag)
	}
	return outbounds, tags
}
