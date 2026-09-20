package netprobe

import (
	"context"
	"testing"
	"time"
)

// fakeSite 描述一个虚构候选域名在测试里的表现。
type fakeSite struct {
	latency    time.Duration
	reachable  bool // 对应 LatencyProber 阶段是否算"能连上"
	tls13      bool
	certDERLen int
}

func fakeProbers(sites map[string]fakeSite) (LatencyProber, TLS13Prober) {
	lat := func(ctx context.Context, domain string) (time.Duration, bool) {
		s, ok := sites[domain]
		if !ok || !s.reachable {
			return 0, false
		}
		return s.latency, true
	}
	tls13 := func(ctx context.Context, domain string) (bool, int) {
		s := sites[domain]
		return s.tls13, s.certDERLen
	}
	return lat, tls13
}

func TestSelect_PicksLowestLatencyAmongPassing(t *testing.T) {
	// C 延迟最低但不支持 TLS1.3；B 延迟其次且合格；A 最慢但也合格。
	// 期望结果是 B：延迟最低的"合格"域名，不是延迟最低的域名本身。
	sites := map[string]fakeSite{
		"a.example": {latency: 300 * time.Millisecond, reachable: true, tls13: true, certDERLen: 1000},
		"b.example": {latency: 100 * time.Millisecond, reachable: true, tls13: true, certDERLen: 1000},
		"c.example": {latency: 50 * time.Millisecond, reachable: true, tls13: false},
	}
	latP, tlsP := fakeProbers(sites)

	domain, latency, found := Select(context.Background(), []string{"a.example", "b.example", "c.example"}, latP, tlsP, 10)
	if !found {
		t.Fatal("应该能找到合格域名")
	}
	if domain != "b.example" {
		t.Fatalf("应该选中 b.example，实际选中 %q", domain)
	}
	if latency != 100*time.Millisecond {
		t.Fatalf("延迟应为 100ms，实际 %v", latency)
	}
}

func TestSelect_SkipsOversizedCertificate(t *testing.T) {
	// D 延迟最低但证书太大；E 延迟其次、证书合规。
	sites := map[string]fakeSite{
		"d.example": {latency: 10 * time.Millisecond, reachable: true, tls13: true, certDERLen: 9000},
		"e.example": {latency: 20 * time.Millisecond, reachable: true, tls13: true, certDERLen: 1200},
	}
	latP, tlsP := fakeProbers(sites)

	domain, _, found := Select(context.Background(), []string{"d.example", "e.example"}, latP, tlsP, 10)
	if !found || domain != "e.example" {
		t.Fatalf("应该跳过证书过大的 d.example，选中 e.example；实际 domain=%q found=%v", domain, found)
	}
}

func TestSelect_UnreachableCandidatesAreSkipped(t *testing.T) {
	sites := map[string]fakeSite{
		"f.example": {reachable: false},
		"g.example": {latency: 40 * time.Millisecond, reachable: true, tls13: true, certDERLen: 500},
	}
	latP, tlsP := fakeProbers(sites)

	domain, _, found := Select(context.Background(), []string{"f.example", "g.example"}, latP, tlsP, 10)
	if !found || domain != "g.example" {
		t.Fatalf("应该跳过连不上的 f.example，选中 g.example；实际 domain=%q found=%v", domain, found)
	}
}

func TestSelect_NoneQualify(t *testing.T) {
	sites := map[string]fakeSite{
		"h.example": {latency: 10 * time.Millisecond, reachable: true, tls13: false},
	}
	latP, tlsP := fakeProbers(sites)

	_, _, found := Select(context.Background(), []string{"h.example"}, latP, tlsP, 10)
	if found {
		t.Fatal("全部候选都不合格时，应该返回 found=false，交给调用方去用 FallbackDomain")
	}
}

func TestSelect_OrderOfCandidateListDoesNotMatterToResult(t *testing.T) {
	sites := map[string]fakeSite{
		"a.example": {latency: 300 * time.Millisecond, reachable: true, tls13: true, certDERLen: 1000},
		"b.example": {latency: 100 * time.Millisecond, reachable: true, tls13: true, certDERLen: 1000},
		"c.example": {latency: 50 * time.Millisecond, reachable: true, tls13: false},
	}
	latP, tlsP := fakeProbers(sites)

	d1, _, _ := Select(context.Background(), []string{"a.example", "b.example", "c.example"}, latP, tlsP, 10)
	d2, _, _ := Select(context.Background(), []string{"c.example", "a.example", "b.example"}, latP, tlsP, 10)
	if d1 != d2 {
		t.Fatalf("候选列表顺序不应影响结果: %q vs %q", d1, d2)
	}
}
