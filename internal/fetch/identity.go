package fetch

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ServerIdentity 对应原脚本 get_vps_identity()：优先尝试云厂商的
// EC2 风格元数据接口拿公网主机名，拿不到就退化到几个公网 IP 探测服务 +
// 反向 DNS 查询，最后兜底直接返回裸 IP。
//
// 反向 DNS 这一步原脚本是 shell out 到 `host` 命令解析输出文本，这里用
// 标准库 `net.LookupAddr` 原生做 PTR 查询，不依赖系统装没装 `host` 这个
// 工具、也不用解析它的输出格式。
func ServerIdentity(ctx context.Context) string {
	client := &http.Client{Timeout: 6 * time.Second}

	if hostname := fetchMetadata(ctx, client, "http://169.254.169.254/latest/meta-data/public-hostname"); hostname != "" {
		return hostname
	}
	if hostname := fetchMetadata(ctx, client, "http://169.254.169.254/2009-04-04/meta-data/hostname"); hostname != "" {
		return hostname
	}
	if hostname := fetchMetadata(ctx, client, "http://169.254.169.254/latest/meta-data/hostname"); hostname != "" {
		return hostname
	}

	ip := firstPublicIP(ctx, client)
	if ip == "" {
		return "无法获取公网IP"
	}

	if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		domain := strings.TrimSuffix(names[0], ".")
		if domain != "" {
			return domain
		}
	}
	return ip
}

func fetchMetadata(ctx context.Context, client *http.Client, url string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(body))
	if s == "" || s == "404" || strings.Contains(s, "Not Found") {
		return ""
	}
	return s
}

var publicIPServices = []string{
	"https://ifconfig.me",
	"https://icanhazip.com",
	"https://ip.sb",
}

func firstPublicIP(ctx context.Context, client *http.Client) string {
	for _, url := range publicIPServices {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		if err != nil {
			continue
		}
		// 校验返回内容真的是个 IP，不能假设 2xx/看似正常的响应体就一定是
		// 期待的那种格式——这是实测才发现的坑：这类探测服务被网络策略
		// 拦截时，有的网关不是直接拒绝连接，而是照常完成 TLS 握手、返回
		// 一个 200/403 状态码 + 一段人类可读的错误文字当作响应体，如果不
		// 校验就直接把这段文字当成 IP 用，等于把一句错误提示误当成了
		// 服务器的公网地址。
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) == nil {
			continue
		}
		return ip
	}
	return ""
}
