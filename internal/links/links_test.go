package links

import (
	"encoding/base64"
	"testing"
)

func TestVLESS_MatchesKnownGoodLink(t *testing.T) {
	got := VLESS(RealityLink{
		Credential: "0c3d89de-16e6-441a-ae98-a5bb2519054f", ServerIP: "107.172.224.251", Port: 28676,
		SNI: "fpinit.itunes.apple.com", Insecure: "0", Fingerprint: "firefox",
		PublicKey: "N2sWNmPZ4m89pNeu_iJo-0t2E9ZhkX2DS9xyvutGaXA", ShortID: "3dee80b8",
		Tag: "美国vless-out-70e40d1652f14dd3900d7fcc7dff2681",
	})
	want := "vless://0c3d89de-16e6-441a-ae98-a5bb2519054f@107.172.224.251:28676?encryption=none&flow=xtls-rprx-vision&security=reality&sni=fpinit.itunes.apple.com&insecure=0&fp=firefox&pbk=N2sWNmPZ4m89pNeu_iJo-0t2E9ZhkX2DS9xyvutGaXA&sid=3dee80b8&type=tcp#美国vless-out-70e40d1652f14dd3900d7fcc7dff2681"
	if got != want {
		t.Fatalf("VLESS 链接跟已知正确值不一致:\n got: %s\nwant: %s", got, want)
	}
}

func TestHysteria2_MatchesKnownGoodLink(t *testing.T) {
	got := Hysteria2(Hysteria2Params{
		Password: "d586fe9f28bc0df3cd2bf41d", ServerIP: "107.172.224.251", Port: 28676,
		ObfsType: "salamander", ObfsPassword: "b9968ab186c5eba68d36efe6",
		ALPN: "h3", SNI: "fpinit.itunes.apple.com", Insecure: "1",
		Tag: "美国hysteria2-out-e6f7f413b8044269a680bff7a1c8860c",
	})
	want := "hysteria2://d586fe9f28bc0df3cd2bf41d@107.172.224.251:28676?obfs=salamander&obfs-password=b9968ab186c5eba68d36efe6&alpn=h3&sni=fpinit.itunes.apple.com&insecure=1#美国hysteria2-out-e6f7f413b8044269a680bff7a1c8860c"
	if got != want {
		t.Fatalf("Hysteria2 链接跟已知正确值不一致:\n got: %s\nwant: %s", got, want)
	}
}

func TestVmessReality_DecodesToKnownGoodJSON(t *testing.T) {
	got := VmessReality(VmessRealityParams{
		Tag: "美国vmess-reality-out-459e0952630f496193e8b35e6650a827", ServerIP: "107.172.224.251", Port: 44661,
		UUID: "df1eb635-ae3f-4d54-90a7-9e13d2cadb8e", SNI: "fpinit.itunes.apple.com",
		PublicKey: "N2sWNmPZ4m89pNeu_iJo-0t2E9ZhkX2DS9xyvutGaXA", ShortID: "3404",
		Fingerprint: "firefox", AllowInsecure: "0",
	})
	want := "vmess://eyJ2IjoiMiIsInBzIjoi576O5Zu9dm1lc3MtcmVhbGl0eS1vdXQtNDU5ZTA5NTI2MzBmNDk2MTkzZThiMzVlNjY1MGE4MjciLCJhZGQiOiIxMDcuMTcyLjIyNC4yNTEiLCJwb3J0IjoiNDQ2NjEiLCJpZCI6ImRmMWViNjM1LWFlM2YtNGQ1NC05MGE3LTllMTNkMmNhZGI4ZSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0IjoidGNwIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6InJlYWxpdHkiLCJzbmkiOiJmcGluaXQuaXR1bmVzLmFwcGxlLmNvbSIsInBiayI6Ik4yc1dObVBaNG04OXBOZXVfaUpvLTB0MkU5WmhrWDJEUzl4eXZ1dEdhWEEiLCJzaWQiOiIzNDA0IiwiZnAiOiJmaXJlZm94IiwiYWxsb3dJbnNlY3VyZSI6IjAifQ=="
	if got != want {
		t.Fatalf("VmessReality 链接跟已知正确值不一致:\n got: %s\nwant: %s", got, want)
	}
}

func TestSubscription_NewlineHandling(t *testing.T) {
	// 对应原脚本三处换行细节：base64 编码的是"两条链接+末尾一个换行"，
	// 写进 subscription.txt 的内容比这个还要再多一个换行。
	content, b64 := Subscription([]string{"A", "B"})
	if content != "A\nB\n\n" {
		t.Fatalf("subscription.txt 内容应为 %q，实际 %q", "A\nB\n\n", content)
	}
	// base64 应该是对 "A\nB\n" 编码，不是对 "A\nB\n\n" 编码。
	wantDecoded := "A\nB\n"
	gotDecoded := mustBase64Decode(t, b64[:len(b64)-1]) // 去掉 Subscription 加的最后一个 \n 再解码
	if gotDecoded != wantDecoded {
		t.Fatalf("base64 应该编码 %q，实际解码出 %q", wantDecoded, gotDecoded)
	}
}

func mustBase64Decode(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
