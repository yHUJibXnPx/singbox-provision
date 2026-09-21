package procmgr

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

type CloudflaredParams struct {
	BinaryPath string
	TargetPort int // tunnel --url http://127.0.0.1:{TargetPort}
	LogPath    string
}

// StartCloudflared 对应原脚本第 1378~1394 行：先短暂启动一次看日志、杀掉，
// 再正式启动一次、等 10 秒让隧道真正建立起来。跟 sing-box 那边一样，
// "启动两次"是原脚本自己的流程，原样保留。
func StartCloudflared(p CloudflaredParams) (*Started, error) {
	args := []string{
		"tunnel", "--url", fmt.Sprintf("http://127.0.0.1:%d", p.TargetPort),
		"--no-autoupdate", "--edge-ip-version", "auto", "--protocol", "http2",
	}

	first, err := startDetached(p.BinaryPath, args, p.LogPath)
	if err != nil {
		return nil, err
	}
	time.Sleep(1 * time.Second)
	_ = Stop(first.PID, 2*time.Second)
	time.Sleep(1 * time.Second)

	started, err := startDetached(p.BinaryPath, args, p.LogPath)
	if err != nil {
		return nil, err
	}
	time.Sleep(10 * time.Second) // 给隧道足够时间跟 Cloudflare 边缘节点建立连接

	return started, nil
}

var trycloudflareRe = regexp.MustCompile(`https://[a-zA-Z0-9.-]+\.trycloudflare\.com`)

// ExtractTrycloudflareDomain 对应原脚本这两行（已经去掉了原版用 eval 的
// 危险写法，原脚本注释自己也说明了原因：日志里如果混进 shell 元字符，
// eval 会把它们当命令执行）：
//
//	grep -oE "https://[a-zA-Z0-9.-]+\.trycloudflare\.com" "$LOG" | head -n 1 | sed 's|https://||'
func ExtractTrycloudflareDomain(logPath string) (string, error) {
	content, err := os.ReadFile(logPath)
	if err != nil {
		return "", fmt.Errorf("读取 %s 失败: %w", logPath, err)
	}
	match := trycloudflareRe.FindString(string(content))
	if match == "" {
		return "", fmt.Errorf("在 %s 里没有找到 trycloudflare.com 域名", logPath)
	}
	return strings.TrimPrefix(match, "https://"), nil
}
