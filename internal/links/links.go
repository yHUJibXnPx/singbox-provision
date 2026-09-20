// Package links 生成节点分享链接（vless:// trojan:// anytls:// hysteria2://
// tuic:// vmess:// 这几种 URI），对应原脚本的 5 个 LINK_* 直接拼接 +
// make_vmess() + make_vless_ws() 两个辅助函数。
package links

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// RealityLink 是 VLESS/Trojan/AnyTLS 这三个 Reality 协议共用的参数集——
// 三条链接的 query string 几乎一模一样，只有协议名、"用户部分"（uuid 还是
// password）、以及 VLESS 独有的 flow 字段不同。
type RealityLink struct {
	Credential  string // VLESS 是 UUID，Trojan/AnyTLS 是密码
	ServerIP    string
	Port        int
	SNI         string
	Insecure    string // "0" 或 "1"（原脚本 INSECURE_REALITY_LINK 固定 "0"）
	Fingerprint string
	PublicKey   string
	ShortID     string
	Tag         string
}

func VLESS(p RealityLink) string {
	return fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&insecure=%s&fp=%s&pbk=%s&sid=%s&type=tcp#%s",
		p.Credential, p.ServerIP, p.Port, p.SNI, p.Insecure, p.Fingerprint, p.PublicKey, p.ShortID, p.Tag)
}

func Trojan(p RealityLink) string {
	return fmt.Sprintf("trojan://%s@%s:%d?security=reality&sni=%s&insecure=%s&fp=%s&pbk=%s&sid=%s&type=tcp#%s",
		p.Credential, p.ServerIP, p.Port, p.SNI, p.Insecure, p.Fingerprint, p.PublicKey, p.ShortID, p.Tag)
}

func AnyTLS(p RealityLink) string {
	return fmt.Sprintf("anytls://%s@%s:%d?security=reality&sni=%s&insecure=%s&fp=%s&pbk=%s&sid=%s&type=tcp#%s",
		p.Credential, p.ServerIP, p.Port, p.SNI, p.Insecure, p.Fingerprint, p.PublicKey, p.ShortID, p.Tag)
}

// Hysteria2Link / TUICLink 对应 LINK_HYSTERIA2 / LINK_TUIC。
type Hysteria2Params struct {
	Password, ServerIP       string
	Port                     int
	ObfsType, ObfsPassword   string
	ALPN, SNI, Insecure, Tag string
}

func Hysteria2(p Hysteria2Params) string {
	return fmt.Sprintf("hysteria2://%s@%s:%d?obfs=%s&obfs-password=%s&alpn=%s&sni=%s&insecure=%s#%s",
		p.Password, p.ServerIP, p.Port, p.ObfsType, p.ObfsPassword, p.ALPN, p.SNI, p.Insecure, p.Tag)
}

type TUICParams struct {
	UUID, Password, ServerIP string
	Port                     int
	ALPN, SNI, Insecure, Tag string
}

func TUIC(p TUICParams) string {
	return fmt.Sprintf("tuic://%s:%s@%s:%d?congestion_control=bbr&alpn=%s&sni=%s&insecure=%s&version=5&udp_relay_mode=native#%s",
		p.UUID, p.Password, p.ServerIP, p.Port, p.ALPN, p.SNI, p.Insecure, p.Tag)
}

// VlessWSParams 对应 make_vless_ws()。TLS=false 时是"直连 WS"（vless-ws-out
// 本体走的这条），TLS=true 时是"WS+TLS"（CF 隧道节点走的这条）。
type VlessWSParams struct {
	Tag, UUID, ServerIP                   string
	Port                                  int
	Host, Path                            string
	TLS                                   bool
	SNI, AllowInsecure, ALPN, Fingerprint string
}

func VlessWS(p VlessWSParams) string {
	if p.TLS {
		return fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&allowInsecure=%s&sni=%s&alpn=%s&fp=%s&type=ws&host=%s&path=%s#%s",
			p.UUID, p.ServerIP, p.Port, p.AllowInsecure, p.SNI, p.ALPN, p.Fingerprint, p.Host, p.Path, p.Tag)
	}
	return fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=none&type=ws&host=%s&path=%s#%s",
		p.UUID, p.ServerIP, p.Port, p.Host, p.Path, p.Tag)
}

// vmess 链接是 "vmess://" + base64(紧凑 JSON)。字段顺序会影响 base64 结果，
// 所以这里没有用一个大结构体 + omitempty 去覆盖所有情况——那样字段顺序
// 会跟着 Go struct 声明走，一旦某个可选字段该出现却被 omitempty 吞掉，
// 或者顺序跟原脚本对不上，生成的 base64 就会跟原版不一致，而这个问题只有
// 拿真实数据解码比对才容易发现。改成按"实际会被调用到的两种形态"各自
// 定义一个字段完全固定的小结构体，更不容易出这种错。
type vmessRealityJSON struct {
	V             string `json:"v"`
	PS            string `json:"ps"`
	Add           string `json:"add"`
	Port          string `json:"port"`
	ID            string `json:"id"`
	Aid           string `json:"aid"`
	Scy           string `json:"scy"`
	Net           string `json:"net"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	TLS           string `json:"tls"`
	SNI           string `json:"sni"`
	PBK           string `json:"pbk"`
	SID           string `json:"sid"`
	FP            string `json:"fp"`
	AllowInsecure string `json:"allowInsecure"`
}

type vmessTLSAlpnJSON struct {
	V             string `json:"v"`
	PS            string `json:"ps"`
	Add           string `json:"add"`
	Port          string `json:"port"`
	ID            string `json:"id"`
	Aid           string `json:"aid"`
	Scy           string `json:"scy"`
	Net           string `json:"net"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	TLS           string `json:"tls"`
	SNI           string `json:"sni"`
	AllowInsecure string `json:"allowInsecure"`
	ALPN          string `json:"alpn"`
}

func vmessLink(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // 这几个结构体全是纯字符串字段，不可能序列化失败
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

// VmessRealityParams 对应 LINK_VMESS_REALITY 那次 make_vmess 调用
// （tls="reality" 分支：net=tcp、host/path 留空、带 pbk/sid/fp，没有 alpn）。
type VmessRealityParams struct {
	Tag, ServerIP                                             string
	Port                                                      int
	UUID, SNI, PublicKey, ShortID, Fingerprint, AllowInsecure string
}

func VmessReality(p VmessRealityParams) string {
	return vmessLink(vmessRealityJSON{
		V: "2", PS: p.Tag, Add: p.ServerIP, Port: fmt.Sprint(p.Port), ID: p.UUID,
		Aid: "0", Scy: "auto", Net: "tcp", Type: "none", Host: "", Path: "",
		TLS: "reality", SNI: p.SNI, PBK: p.PublicKey, SID: p.ShortID,
		FP: p.Fingerprint, AllowInsecure: p.AllowInsecure,
	})
}

// VmessWSTLSParams 对应 LINK_VMESS_WS_TLS 那次 make_vmess 调用
// （tls 非空且非 reality、alpn 非空分支：net=ws、带 host/path/alpn，
// 没有 pbk/sid/fp）。
type VmessWSTLSParams struct {
	Tag, ServerIP                              string
	Port                                       int
	UUID, Host, Path, SNI, AllowInsecure, ALPN string
}

func VmessWSTLS(p VmessWSTLSParams) string {
	return vmessLink(vmessTLSAlpnJSON{
		V: "2", PS: p.Tag, Add: p.ServerIP, Port: fmt.Sprint(p.Port), ID: p.UUID,
		Aid: "0", Scy: "auto", Net: "ws", Type: "none", Host: p.Host, Path: p.Path,
		TLS: "tls", SNI: p.SNI, AllowInsecure: p.AllowInsecure, ALPN: p.ALPN,
	})
}

// Subscription 对应 SUBSCRIPTION_CONTENT/SUBSCRIPTION_BASE64 的拼合，
// 包括原脚本里两处容易漏掉的换行细节：
//   - base64 是对"29 条链接用换行拼起来、末尾再加一个换行"编码的，不是
//     对写进 subscription.txt 的最终文件内容编码的；
//   - subscription.txt 实际内容比 base64 编码的那份多一个换行——
//     因为写文件时 `printf "%s\n"` 又追加了一次。
//
// 两个返回值分别就是"该写进 subscription.txt 的内容"和
// "该写进 subscription_base64.txt 的内容"，调用方直接落盘即可，不需要
// 自己再补换行。
func Subscription(allLinks []string) (fileContent string, base64FileContent string) {
	joined := strings.Join(allLinks, "\n") + "\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(joined))
	return joined + "\n", b64 + "\n"
}
