// cmd/provision 是整个重构的落脚点：把 internal/ 下面十二个已经各自验证
// 过的包，按原脚本 make_sing-box_server_ubuntu.sh 的执行顺序串起来。
//
// 跟原脚本的一处从头到尾的差别：几个原脚本里硬编码的个人基础设施
// （SERVER_CFNAT=127.0.0.1、PORT_CFNAT=1234、
// CLOUDFLARED_PROXYIP=cloudflare.182682.xyz）在这里全部改成了命令行参数、
// 默认留空——那几个值明显是原作者自己的 NAT 转发和代理域名，没有理由
// 原样抄进一个要给别人用的工具里当默认值。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"singboxprovision/internal/certgen"
	"singboxprovision/internal/clientconfig"
	"singboxprovision/internal/fetch"
	"singboxprovision/internal/links"
	"singboxprovision/internal/netprobe"
	"singboxprovision/internal/portcheck"
	"singboxprovision/internal/procmgr"
	"singboxprovision/internal/randgen"
	"singboxprovision/internal/report"
	"singboxprovision/internal/sbconfig"
	"singboxprovision/internal/sysconfig"
)

type options struct {
	workDir         string
	regionTag       string
	singBoxChannel  string
	singBoxVersion  string
	fingerprintType string

	serverCFNAT          string
	portCFNAT            int
	cloudflaredProxyIP   string
	cloudflaredProxyPort int

	skipCloudflared bool
	skipFirewall    bool
}

func parseFlags() options {
	o := options{}
	flag.StringVar(&o.workDir, "workdir", envOr("WORKDIR", "/root"), "工作目录（对应原脚本 WORKDIR）")
	flag.StringVar(&o.regionTag, "region-tag", os.Getenv("NODE_REGION_TAG"), "节点 tag 前缀，比如 美国（对应 NODE_REGION_TAG）")
	flag.StringVar(&o.singBoxChannel, "singbox-channel", envOr("SING_BOX_CHANNEL", "testing"), "stable 或 testing")
	flag.StringVar(&o.singBoxVersion, "singbox-version", os.Getenv("SING_BOX_VERSION"), "显式指定版本，跳过自动探测")
	flag.StringVar(&o.fingerprintType, "fingerprint", envOr("FINGERPRINT_TYPE", "firefox"), "uTLS 指纹类型")
	flag.StringVar(&o.serverCFNAT, "cfnat-server", "", "可选：CF 节点 NAT 转发目标地址，留空则不生成 *-NAT 节点")
	flag.IntVar(&o.portCFNAT, "cfnat-port", 0, "可选：CF 节点 NAT 转发目标端口")
	flag.StringVar(&o.cloudflaredProxyIP, "cf-proxyip", "", "可选：额外的 Cloudflare ProxyIP 域名")
	flag.IntVar(&o.cloudflaredProxyPort, "cf-proxyip-port", 443, "上面那个 ProxyIP 的端口")
	flag.BoolVar(&o.skipCloudflared, "skip-cloudflared", false, "不启动 cloudflared 隧道（CF 节点仍会生成那 8 个不依赖隧道的字面 IP 节点）")
	flag.BoolVar(&o.skipFirewall, "skip-firewall", false, "跳过 ufw 防火墙放行")
	flag.Parse()
	return o
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	log.SetFlags(0)
	o := parseFlags()
	ctx := context.Background()

	if err := os.MkdirAll(filepath.Join(o.workDir, "config"), 0o755); err != nil {
		log.Fatalf("创建工作目录失败: %v", err)
	}

	step("1/12", "开启 BBR")
	if bbr, err := sysconfig.EnsureBBR("/etc/sysctl.conf"); err != nil {
		log.Printf("  警告：BBR 检查失败（不中断安装）: %v", err)
	} else if bbr.Skipped {
		log.Printf("  跳过：内核版本 %s 低于 4.9", bbr.KernelVersion)
	} else if !bbr.Enabled {
		log.Printf("  警告：BBR 启用后验证未通过，当前拥塞控制算法为 %q", bbr.CurrentCongestionControl)
	} else {
		log.Printf("  BBR 已启用（内核 %s）", bbr.KernelVersion)
	}

	step("2/12", "同步服务器时间")
	if method, err := sysconfig.SyncTime(); err != nil {
		log.Printf("  警告：时间同步失败（不中断安装）: %v", err)
	} else if method == "" {
		log.Printf("  警告：没有找到 timedatectl 或 ntpdate，无法同步时间，仅显示，请手动检查")
	} else {
		log.Printf("  已通过 %s 触发时间同步，当前时间: %s", method, time.Now().Format(time.RFC3339))
	}

	step("3/12", "下载 sing-box / cloudflared")
	sb, err := fetch.FetchSingBox(ctx, o.workDir, fetch.SingBoxParams{Channel: o.singBoxChannel, Version: o.singBoxVersion})
	if err != nil {
		log.Fatalf("下载 sing-box 失败: %v", err)
	}
	log.Printf("  sing-box %s -> %s", sb.Version, sb.BinaryPath)
	cloudflaredPath, err := fetch.FetchCloudflared(ctx, o.workDir)
	if err != nil {
		log.Fatalf("下载 cloudflared 失败: %v", err)
	}
	log.Printf("  cloudflared -> %s", cloudflaredPath)

	step("4/12", "探测服务器公网身份 + Reality 伪装域名")
	serverIP := fetch.ServerIdentity(ctx)
	log.Printf("  服务器身份: %s", serverIP)
	bestDomain, latency, usedFallback := netprobe.PickHandshakeDomain(ctx)
	if usedFallback {
		log.Printf("  警告：未找到支持 TLS1.3 的候选域名，使用兜底域名 %s", bestDomain)
	} else {
		log.Printf("  伪装域名: %s（延迟 %v）", bestDomain, latency)
	}

	step("5/12", "生成随机值（UUID / 密码 / short-id / Reality 密钥对）")
	rv := generateRandomValues()
	log.Printf("  完成")

	step("6/12", "生成自签名证书")
	certLines, keyLines, err := certgen.SelfSigned(bestDomain)
	if err != nil {
		log.Fatalf("生成自签名证书失败: %v", err)
	}

	step("7/12", "分配端口")
	ports, err := portcheck.Allocate()
	if err != nil {
		log.Fatalf("分配端口失败: %v", err)
	}
	log.Printf("  VLESS=%d Trojan=%d AnyTLS=%d VmessReality=%d VlessWS=%d Hysteria2=%d(UDP) VmessWSTLS=%d TUIC=%d(UDP)",
		ports.VLESS, ports.Trojan, ports.AnyTLS, ports.VmessReality, ports.VlessWS, ports.Hysteria2, ports.VmessWSTLS, ports.TUIC)

	step("8/12", "构建服务端 config.json")
	serverParams := sbconfig.ServerParams{
		BestDomain: bestDomain, RealityPrivateKey: rv.realityPrivateKey,
		ShortIDsVLESS: rv.shortIDsVLESS, ShortIDsTrojan: rv.shortIDsTrojan,
		ShortIDsAnyTLS: rv.shortIDsAnyTLS, ShortIDsVmessReal: rv.shortIDsVmessReality,
		PortHysteria2: ports.Hysteria2, PortTUIC: ports.TUIC, PortVLESS: ports.VLESS,
		PortTrojan: ports.Trojan, PortAnyTLS: ports.AnyTLS, PortVmessReality: ports.VmessReality,
		PortVmessWSTLS: ports.VmessWSTLS, PortVlessWS: ports.VlessWS,
		UUIDVLESS: rv.uuidVLESS, UUIDTUIC: rv.uuidTUIC, UUIDVmessReality: rv.uuidVmessReality,
		UUIDVmessWSTLS: rv.uuidVmessWSTLS, UUIDVlessWS: rv.uuidVlessWS,
		PasswordHysteria2: rv.passwordHysteria2, PasswordTUIC: rv.passwordTUIC,
		PasswordTrojan: rv.passwordTrojan, PasswordAnyTLS: rv.passwordAnyTLS,
		HY2ObfsType: "salamander", HY2ObfsPassword: rv.hy2ObfsPassword,
		PaddingScheme:  rv.paddingScheme,
		PathVmessWSTLS: "/" + rv.pathVmessWSTLS, PathVLESSWS: "/" + rv.pathVlessWS,
		CertLines: certLines, KeyLines: keyLines,
	}
	serverCfg := sbconfig.BuildServerConfig(serverParams)
	if err := writeJSON(filepath.Join(o.workDir, "config.json"), serverCfg); err != nil {
		log.Fatalf("写入 config.json 失败: %v", err)
	}

	step("9/12", "启动 sing-box")
	sbStarted, err := procmgr.StartSingBox(procmgr.SingBoxParams{
		BinaryPath: sb.BinaryPath, ConfigDir: filepath.Join(o.workDir, "config"),
		ConfigPath: filepath.Join(o.workDir, "config.json"), LogPath: filepath.Join(o.workDir, "sing-box.log"),
	})
	if err != nil {
		log.Fatalf("启动 sing-box 失败: %v", err)
	}
	log.Printf("  PID=%d", sbStarted.PID)

	step("10/12", "启动 cloudflared 隧道")
	cf := clientconfig.CFParams{
		NATServer: o.serverCFNAT, NATPort: o.portCFNAT,
		ProxyIP: o.cloudflaredProxyIP, ProxyIPPort: o.cloudflaredProxyPort,
	}
	if o.skipCloudflared {
		log.Printf("  已跳过（--skip-cloudflared）")
	} else {
		cfStarted, err := procmgr.StartCloudflared(procmgr.CloudflaredParams{
			BinaryPath: cloudflaredPath, TargetPort: ports.VlessWS,
			LogPath: filepath.Join(o.workDir, fmt.Sprintf("cloudflared_%d.log", ports.VlessWS)),
		})
		if err != nil {
			log.Printf("  警告：cloudflared 启动失败（不中断安装，CF 节点会缺少隧道域名相关的那几个）: %v", err)
		} else if domain, err := procmgr.ExtractTrycloudflareDomain(cfStarted.LogPath); err != nil {
			log.Printf("  警告：没能从日志里解析出隧道域名（不中断安装）: %v", err)
		} else {
			cf.Domain = domain
			log.Printf("  隧道域名: %s", domain)
		}
	}

	step("11/12", "生成客户端配置 / 分享链接 / 订阅")
	tags := clientconfig.NewTags(o.regionTag, func() string { return stripDashes(randgen.NewUUID()) })
	clientParams := clientconfig.Params{
		ServerIP: serverIP, BestDomain: bestDomain, PublicKey: rv.realityPublicKey,
		FingerprintType: o.fingerprintType,
		UUIDVLESS:       rv.uuidVLESS, UUIDTUIC: rv.uuidTUIC, UUIDVmessReality: rv.uuidVmessReality,
		UUIDVmessWSTLS: rv.uuidVmessWSTLS, UUIDVlessWS: rv.uuidVlessWS,
		PasswordHysteria2: rv.passwordHysteria2, PasswordTUIC: rv.passwordTUIC,
		PasswordTrojan: rv.passwordTrojan, PasswordAnyTLS: rv.passwordAnyTLS,
		ShortIDVLESS: randgen.PickRandom(rv.shortIDsVLESS), ShortIDTrojan: randgen.PickRandom(rv.shortIDsTrojan),
		ShortIDAnyTLS: randgen.PickRandom(rv.shortIDsAnyTLS), ShortIDVmessReality: randgen.PickRandom(rv.shortIDsVmessReality),
		PortVLESS: ports.VLESS, PortTrojan: ports.Trojan, PortAnyTLS: ports.AnyTLS,
		PortVmessReality: ports.VmessReality, PortVmessWSTLS: ports.VmessWSTLS, PortVlessWS: ports.VlessWS,
		PortHysteria2: ports.Hysteria2, PortTUIC: ports.TUIC,
		HY2ObfsType: "salamander", HY2ObfsPassword: rv.hy2ObfsPassword, CertLines: certLines,
		PathVmessWSTLS: "/" + rv.pathVmessWSTLS, PathVLESSWS: "/" + rv.pathVlessWS,
		RegionTag: o.regionTag, Tags: tags, CF: cf,
	}

	randHex := func() string { return stripDashes(randgen.NewUUID()) }
	latestCfg := clientconfig.BuildLatest(clientParams, clientconfig.LatestOptions{
		IncludeCF: true, IncludePrivateRule: true, IncludeAnyTLS: true, MixedListen: "0.0.0.0",
	}, randHex)
	clientconfig.ApplyClassification(latestCfg)
	must(writeJSON(filepath.Join(o.workDir, "client.json"), latestCfg))

	openwrtCfg := clientconfig.BuildLatest(clientParams, clientconfig.LatestOptions{
		TUNInterfaceName: "tun0", IncludeAnyTLS: true,
	}, randHex)
	clientconfig.ApplyClassification(openwrtCfg)
	must(writeJSON(filepath.Join(o.workDir, "client_openwrt_sing-box.json"), openwrtCfg))

	legacyCfg := clientconfig.Build1114(clientParams, randHex)
	clientconfig.ApplyClassification(legacyCfg)
	must(writeJSON(filepath.Join(o.workDir, "client_1.11.4.json"), legacyCfg))

	allLinks, cfEntries := buildAllLinks(clientParams, cfOutboundsOf(latestCfg))
	subContent, subBase64 := links.Subscription(allLinks)
	must(os.WriteFile(filepath.Join(o.workDir, "subscription.txt"), []byte(subContent), 0o644))
	must(os.WriteFile(filepath.Join(o.workDir, "subscription_base64.txt"), []byte(subBase64), 0o644))
	log.Printf("  生成了 %d 条节点链接（8 个直连协议 + %d 个 CF 节点）", len(allLinks), len(cfEntries))

	step("12/12", "生成 result.txt / 放行防火墙端口")
	resultTxt := report.Build(report.Params{
		ServerIP: serverIP, SingBoxVersion: sb.Version,
		PublicKey: rv.realityPublicKey, PrivateKey: rv.realityPrivateKey,
		UUIDVLESS: rv.uuidVLESS, UUIDTUIC: rv.uuidTUIC, UUIDVmessReality: rv.uuidVmessReality,
		UUIDVmessWSTLS: rv.uuidVmessWSTLS, UUIDVlessWS: rv.uuidVlessWS,
		PasswordHysteria2: rv.passwordHysteria2, PasswordTUIC: rv.passwordTUIC,
		PasswordTrojan: rv.passwordTrojan, PasswordAnyTLS: rv.passwordAnyTLS,
		HY2ObfsType: "salamander", HY2ObfsPassword: rv.hy2ObfsPassword,
		BestDomain: bestDomain, CloudflaredDomain: cf.Domain,
		CloudflaredProxyIP: o.cloudflaredProxyIP, CloudflaredProxyIPPort: o.cloudflaredProxyPort,
		ServerCFNAT: o.serverCFNAT, PortCFNAT: o.portCFNAT,
		PortVLESS: ports.VLESS, PortTrojan: ports.Trojan, PortAnyTLS: ports.AnyTLS,
		PortHysteria2: ports.Hysteria2, PortTUIC: ports.TUIC, PortVmessReality: ports.VmessReality,
		PortVmessWSTLS: ports.VmessWSTLS, PortVlessWS: ports.VlessWS,
		ShortIDsVLESS: rv.shortIDsVLESS, ShortIDsTrojan: rv.shortIDsTrojan,
		ShortIDsAnyTLS: rv.shortIDsAnyTLS, ShortIDsVmessReality: rv.shortIDsVmessReality,
		LinkVLESS: allLinks[0], LinkTrojan: allLinks[1], LinkAnyTLS: allLinks[2],
		LinkHysteria2: allLinks[3], LinkTUIC: allLinks[4],
		LinkVmessReality: allLinks[5], LinkVmessWSTLS: allLinks[6], LinkVlessWS: allLinks[7],
		CFEntries: cfEntries, SubscriptionBase64: subBase64[:len(subBase64)-1],
		WorkDir: o.workDir,
	})
	must(os.WriteFile(filepath.Join(o.workDir, "result.txt"), []byte(resultTxt), 0o644))

	if o.skipFirewall {
		log.Printf("  已跳过防火墙放行（--skip-firewall）")
	} else {
		fw, err := sysconfig.OpenFirewallPorts(firewallRules(ports))
		if err != nil {
			log.Printf("  警告：防火墙操作失败（不中断安装）: %v", err)
		} else if fw.UFWNotInstalled {
			log.Printf("  未安装 ufw，请自行放行以下端口：")
			for _, ins := range fw.ManualInstructions {
				log.Printf("    %s", ins)
			}
		} else if fw.UFWInactive {
			log.Printf("  ufw 已安装但未激活，跳过")
		} else {
			log.Printf("  已放行端口（清理了 %d 条旧规则）", len(fw.RemovedRuleNums))
		}
	}

	fmt.Println()
	fmt.Printf("完成。详细信息见 %s/result.txt\n", o.workDir)
}

func step(n, title string) {
	log.Printf("== [%s] %s ==", n, title)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func writeJSON(path string, v any) error {
	data, err := jsonMarshalIndent(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
