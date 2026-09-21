package netprobe

import (
	"context"
	"crypto/tls"
	"net"
	"sort"
	"time"
)

// LatencyProber 对应原脚本第一阶段：curl（不强制 TLS 版本，走系统信任链）
// 测到某个域名的连接耗时；探测失败（超时/连接被拒/证书不受信）时 ok=false，
// 对应原脚本里 lat=999999 被跳过的情况。
type LatencyProber func(ctx context.Context, domain string) (latency time.Duration, ok bool)

// TLS13Prober 对应原脚本第二阶段：openssl s_client -tls1_3，强制 TLS1.3
// 握手、不校验证书链是否受信（这一步只关心协议版本和叶证书体积，跟
// s_client 默认行为一致，故意比 LatencyProber 宽松）。
type TLS13Prober func(ctx context.Context, domain string) (ok bool, certDERLen int)

// DefaultLatencyProber 用标准 TLS 握手（走 Go 默认的系统信任链）测量耗时，
// 对应 curl 不加 -k 时的默认证书校验行为。
func DefaultLatencyProber(ctx context.Context, domain string) (time.Duration, bool) {
	d := &net.Dialer{Timeout: 2 * time.Second}
	start := time.Now()
	conn, err := tls.DialWithDialer(d, "tcp", domain+":443", &tls.Config{ServerName: domain})
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	return time.Since(start), true
}

// DefaultTLS13Prober 强制走 TLS1.3、跳过证书链校验，对应
// `openssl s_client -tls1_3`：它不会因为证书不受信就中断握手，
// 只要协议协商成功就算通过。
func DefaultTLS13Prober(ctx context.Context, domain string) (bool, int) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", domain+":443", &tls.Config{
		ServerName:         domain,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec // 有意如此，见上方注释
	})
	if err != nil {
		return false, 0
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return true, 0
	}
	return true, len(certs[0].Raw)
}

type probeResult struct {
	domain  string
	latency time.Duration
	ok      bool
}

// Select 对应原脚本 667~787 行的完整选择逻辑：
//
//  1. 并发测出每个候选域名的连接延迟（原脚本是串行 curl 循环，这里是这次
//     重构里性能收益最直接的一处：119 个域名从"最坏几分钟"降到几秒内出结果）。
//  2. 把测到延迟的域名按从低到高排序。
//  3. 依次验证 TLS1.3 支持 + 证书大小，第一个都通过的就是答案，立刻返回
//     （不必也不会去测比它延迟更高的候选——即使那些候选还没测过 TLS1.3，
//     它们也不可能给出更好的结果）。
//
// 这个"排序后再顺序短路"的写法不是随便选的：它保留了原脚本"只有当延迟
// 有可能刷新最优解时才做一次较贵的 TLS1.3 验证"这个剪枝优化的语义，
// 同时把开销最大的第 1 步做成并发。候选域名列表本身的顺序对结果没有
// 任何影响——不管 Candidates 怎么排，Select 返回的都是全体候选里延迟最低
// 且通过验证的那一个。
func Select(ctx context.Context, candidates []string, latencyProbe LatencyProber, tlsProbe TLS13Prober, concurrency int) (domain string, latency time.Duration, found bool) {
	if concurrency <= 0 {
		concurrency = 20
	}

	results := make([]probeResult, len(candidates))
	sem := make(chan struct{}, concurrency)
	done := make(chan struct{})

	for i, d := range candidates {
		i, d := i, d
		sem <- struct{}{}
		go func() {
			defer func() {
				<-sem
				done <- struct{}{}
			}()
			lat, ok := latencyProbe(ctx, d)
			results[i] = probeResult{domain: d, latency: lat, ok: ok}
		}()
	}
	for range candidates {
		<-done
	}

	order := make([]int, 0, len(candidates))
	for i, r := range results {
		if r.ok {
			order = append(order, i)
		}
	}
	sort.Slice(order, func(a, b int) bool {
		return results[order[a]].latency < results[order[b]].latency
	})

	for _, idx := range order {
		r := results[idx]
		ok, certLen := tlsProbe(ctx, r.domain)
		if !ok || certLen > maxCertDER {
			continue
		}
		return r.domain, r.latency, true
	}
	return "", 0, false
}

// PickHandshakeDomain 是生产环境用的入口：用真实网络探测在 Candidates 里
// 选一个，找不到就用 FallbackDomain 兜底——对应原脚本"未找到支持TLS1.3的
// 域名时使用 gateway.icloud.com"那一段，脚本里这个分支永远不会真正失败。
func PickHandshakeDomain(ctx context.Context) (domain string, latency time.Duration, usedFallback bool) {
	d, lat, found := Select(ctx, Candidates, DefaultLatencyProber, DefaultTLS13Prober, 20)
	if !found {
		return FallbackDomain, 0, true
	}
	return d, lat, false
}
