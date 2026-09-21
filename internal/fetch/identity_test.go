package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFirstPublicIP_RejectsNonIPResponseBody 对应实测跑 cmd/provision 时
// 发现的真实 bug：探测服务被网络策略拦截时，有的网关不是直接拒绝连接，
// 而是照常完成握手、返回一段人类可读的错误文字当响应体（这个沙盒实测
// 返回的是 "Host not in allowlist: ...", 状态码还是 200/403 都可能）。
// 不校验就直接拿来当 IP 用，等于把一句错误提示当成了服务器的公网地址。
func TestFirstPublicIP_RejectsNonIPResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Host not in allowlist: example.com. Add this host to your network egress settings to allow access."))
	}))
	defer srv.Close()

	orig := publicIPServices
	publicIPServices = []string{srv.URL}
	defer func() { publicIPServices = orig }()

	got := firstPublicIP(context.Background(), &http.Client{})
	if got != "" {
		t.Fatalf("响应体不是合法 IP 时应该返回空字符串（表示这个服务没探测出结果），实际返回了 %q", got)
	}
}

func TestFirstPublicIP_AcceptsRealIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.42\n"))
	}))
	defer srv.Close()

	orig := publicIPServices
	publicIPServices = []string{srv.URL}
	defer func() { publicIPServices = orig }()

	got := firstPublicIP(context.Background(), &http.Client{})
	if got != "203.0.113.42" {
		t.Fatalf("应该解析出 203.0.113.42，实际 %q", got)
	}
}

func TestFirstPublicIP_FallsThroughToNextServiceOnBadResponse(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not an ip"))
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("198.51.100.7"))
	}))
	defer good.Close()

	orig := publicIPServices
	publicIPServices = []string{bad.URL, good.URL}
	defer func() { publicIPServices = orig }()

	got := firstPublicIP(context.Background(), &http.Client{})
	if got != "198.51.100.7" {
		t.Fatalf("第一个服务返回垃圾数据时应该继续试下一个，实际返回 %q", got)
	}
}
