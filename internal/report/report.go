// Package report 生成 result.txt——纯人类可读的汇总报告，跟 sing-box
// 或客户端实际解析什么都没关系，对应原脚本最后两段 `cat >> result.txt
// <<EOF` heredoc。
package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CFEntry 对应 CF_RESULT_LINES 里的一行："节点 tag" + "对应链接"。
type CFEntry struct {
	Tag  string
	Link string
}

// Params 是拼 result.txt 需要的全部值。故意没有直接复用
// sbconfig.ServerParams/clientconfig.Params——那两个结构体里一大半字段
// （TLS 配置细节、DNS、路由规则）report 根本用不上，硬凑一个大结构体只会
// 让这里的字段列表看不出"报告到底要展示什么"。
type Params struct {
	ServerIP                                                           string
	SingBoxVersion                                                     string
	PublicKey                                                          string
	PrivateKey                                                         string
	UUIDVLESS, UUIDTUIC, UUIDVmessReality, UUIDVmessWSTLS, UUIDVlessWS string
	PasswordHysteria2, PasswordTUIC, PasswordTrojan, PasswordAnyTLS    string
	HY2ObfsType, HY2ObfsPassword                                       string
	BestDomain                                                         string
	CloudflaredDomain                                                  string
	CloudflaredProxyIP                                                 string
	CloudflaredProxyIPPort                                             int
	ServerCFNAT                                                        string
	PortCFNAT                                                          int

	PortVLESS, PortTrojan, PortAnyTLS, PortHysteria2, PortTUIC, PortVmessReality, PortVmessWSTLS, PortVlessWS int

	ShortIDsVLESS, ShortIDsTrojan, ShortIDsAnyTLS, ShortIDsVmessReality []string

	// 8 条直连协议链接，顺序固定：VLESS/Trojan/VmessReality/VmessWSTLS/
	// VlessWS/Hysteria2/TUIC/AnyTLS——对应原脚本 [1]~[8]。
	LinkVLESS, LinkTrojan, LinkVmessReality, LinkVmessWSTLS, LinkVlessWS, LinkHysteria2, LinkTUIC, LinkAnyTLS string

	CFEntries          []CFEntry
	SubscriptionBase64 string // 不带原脚本写文件时追加的那个最后换行

	WorkDir string // 用来拼"后台运行所用命令"那几行提示文本
}

// Build 生成完整的 result.txt 内容。
func Build(p Params) string {
	var b strings.Builder

	totalNodes := 8 + len(p.CFEntries)

	fmt.Fprintf(&b, `====================================
       Reality Sing-box 生成报告
====================================

服务器 IP: %s

sing-box 版本: %s

Public Key: %s
Private Key: %s

UUID (独立)：
  VLESS → %s
  TUIC  → %s
  VMESS_REALITY → %s
  VMESS_WS_TLS → %s
  VLESS_WS → %s

Password (hysteria2 用): %s
Password (tuic 用): %s
Password (trojan 用): %s
Password (anytls 用): %s
Hysteria2 obfs: %s
Hysteria2 obfs-password: %s

Fake SNI / server_name: %s

Handshake Domain: %s

Cloudflare Domain: %s
Cloudflare Proxy Domain: %s:%d
CFNAT PROXYIP: %s:%d

端口：
  VLESS          : %d
  Trojan         : %d
  AnyTLS         : %d
  Hysteria2      : %d
  TUIC           : %d
  VMESS_REALITY  : %d
  VMESS_WS_TLS   : %d
  VLESS_WS       : %d

Short IDs（多组）：
  VLESS  : %s
  Trojan : %s
  AnyTLS : %s
  VMESS : %s
====================================
  节点分享链接（全部 %d 条）
====================================

--- 直连协议（推荐优先使用）---
[1]  VLESS Reality:        %s
[2]  Trojan Reality:       %s
[3]  VMess Reality:        %s
[4]  VMess WS TLS:         %s
[5]  VLess WS:             %s
[6]  Hysteria2 (UDP):      %s
[7]  TUIC (UDP):           %s
[8]  AnyTLS (仅sing-box):  %s

--- Cloudflare CDN 中转（抗封锁备用）---
%s

====================================
  Base64 订阅码（全部 %d 条）
  Shadowrocket / V2RayN / NekoBox 直接粘贴导入
====================================

%s

后台运行所用命令：
  nohup %s/sing-boxs/sing-box -D %s/config -c %s/config.json run > %s/sing-box.log 2>&1 & disown
  nohup %s/cloudflared tunnel --url http://127.0.0.1:%d --no-autoupdate --edge-ip-version auto --protocol http2 > %s/cloudflared_%d.log 2>&1 & disown

证书已内嵌，无需额外文件。
====================================
`,
		p.ServerIP, p.SingBoxVersion, p.PublicKey, p.PrivateKey,
		p.UUIDVLESS, p.UUIDTUIC, p.UUIDVmessReality, p.UUIDVmessWSTLS, p.UUIDVlessWS,
		p.PasswordHysteria2, p.PasswordTUIC, p.PasswordTrojan, p.PasswordAnyTLS,
		p.HY2ObfsType, p.HY2ObfsPassword,
		p.BestDomain, p.BestDomain,
		p.CloudflaredDomain, p.CloudflaredProxyIP, p.CloudflaredProxyIPPort, p.ServerCFNAT, p.PortCFNAT,
		p.PortVLESS, p.PortTrojan, p.PortAnyTLS, p.PortHysteria2, p.PortTUIC, p.PortVmessReality, p.PortVmessWSTLS, p.PortVlessWS,
		mustJSONArray(p.ShortIDsVLESS), mustJSONArray(p.ShortIDsTrojan), mustJSONArray(p.ShortIDsAnyTLS), mustJSONArray(p.ShortIDsVmessReality),
		totalNodes,
		p.LinkVLESS, p.LinkTrojan, p.LinkVmessReality, p.LinkVmessWSTLS, p.LinkVlessWS, p.LinkHysteria2, p.LinkTUIC, p.LinkAnyTLS,
		buildCFResultLines(p.CFEntries),
		totalNodes,
		p.SubscriptionBase64,
		p.WorkDir, p.WorkDir, p.WorkDir, p.WorkDir,
		p.WorkDir, p.PortVlessWS, p.WorkDir, p.PortVlessWS,
	)

	return b.String()
}

// buildCFResultLines 对应原脚本 build_cf_data() 里拼 CF_RESULT_LINES 那段：
// 序号从 9 开始（前面 [1]~[8] 是 8 个直连协议），"tag:" 左对齐补齐到
// **65 字节**（不是 65 个字符——这一处如果按 Unicode 码点或者"字符数"去
// 补齐，中文 tag 对出来的空格数量会跟原脚本的真实输出对不上；bash 的
// printf "%-65s" 在这里是按字节数计算宽度的，用你的真实 result.txt 反推
// 验证过好几组不同长度的 tag，byte_len + 补的空格数 = 65 完全对得上）。
//
// 返回值末尾带一个换行——这不是随手加的：CF_RESULT_LINES 在原脚本里每
// 追加一条就带一个 \n（包括最后一条），而它在 heredoc 里又是单独占一行
// 被引用的，heredoc 本身还会再给这一"行"补一个换行，两个换行叠在一起，
// 紧接着 heredoc 模板里还有一行空行——三个换行加在一起，是 Base64 那个
// 标题前实际有两个空行、不是一个，拿真实 result.txt 数过换行数才确认的。
func buildCFResultLines(entries []CFEntry) string {
	var lines []string
	for i, e := range entries {
		idx := 9 + i
		tagWithColon := e.Tag + ":"
		formatted := tagWithColon
		if len(formatted) < 65 { // len() 在 Go 里是字节数，正好是这里需要的
			formatted += strings.Repeat(" ", 65-len(formatted))
		}
		lines = append(lines, fmt.Sprintf("[%d] %s %s", idx, formatted, e.Link))
	}
	return strings.Join(lines, "\n") + "\n"
}

func mustJSONArray(items []string) string {
	b, err := json.Marshal(items)
	if err != nil {
		panic(err) // 纯字符串切片，不可能序列化失败
	}
	return string(b)
}
