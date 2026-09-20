package sysconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestParseMajorMinor(t *testing.T) {
	cases := []struct {
		in           string
		major, minor int
	}{
		{"6.18.44-fc-v33", 6, 18},
		{"4.9.0", 4, 9},
		{"5.15.0-105-generic", 5, 15},
		{"4.8.13", 4, 8},
	}
	for _, c := range cases {
		major, minor, err := parseMajorMinor(c.in)
		if err != nil {
			t.Fatalf("parseMajorMinor(%q) 失败: %v", c.in, err)
		}
		if major != c.major || minor != c.minor {
			t.Fatalf("parseMajorMinor(%q) = %d.%d, want %d.%d", c.in, major, minor, c.major, c.minor)
		}
	}
}

// TestKernelVersion_RealFile 是真实调用（不是 mock），这个沙盒实际
// 跑在 6.18 内核上，早就远高于 BBR 要求的 4.9。
func TestKernelVersion_RealFile(t *testing.T) {
	major, minor, err := KernelVersion()
	if err != nil {
		t.Fatal(err)
	}
	if major < 4 {
		t.Fatalf("这个沙盒的内核不应该低于 4.x，实际读到 %d.%d", major, minor)
	}
	t.Logf("真实内核版本: %d.%d", major, minor)
}

func TestEnsureLineInFile_AppendsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sysctl.conf")

	if err := ensureLineInFile(path, "net.core.default_qdisc=fq"); err != nil {
		t.Fatal(err)
	}
	if err := ensureLineInFile(path, "net.core.default_qdisc=fq"); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(content); got != "net.core.default_qdisc=fq\n" {
		t.Fatalf("重复调用两次应该只写一行，实际内容: %q", got)
	}
}

// TestEnsureBBR_RealRun 是真实调用：这个沙盒里有真实的 sysctl 命令、
// 内核也确实支持 BBR（当前拥塞控制算法本来就是 bbr），用临时文件当
// sysctl.conf，不去碰真的 /etc/sysctl.conf。
func TestEnsureBBR_RealRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sysctl.conf")
	result, err := EnsureBBR(path)
	if err != nil {
		t.Fatal(err)
	}
	if result.Skipped {
		t.Fatal("这个沙盒的内核版本不该触发跳过")
	}
	t.Logf("BBR 结果: %+v", result)

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"net.core.default_qdisc=fq", "net.ipv4.tcp_congestion_control=bbr"} {
		if !contains(string(content), want) {
			t.Fatalf("sysctl 配置文件里应该包含 %q，实际内容:\n%s", want, content)
		}
	}
}

// TestSyncTime_RealRun 是真实调用，不 mock exec.Command——但不能像其它
// "真实调用"测试一样写死"这个环境应该有 timedatectl"：这条假设只在我
// 当初写测试那个沙盒里成立，换一个没装 timedatectl/ntpdate 的最小容器
// （真实出现过：Docker 里的精简 Ubuntu 镜像，没有 systemd 在跑，
// timedatectl 根本没装）就会误报失败，而 SyncTime() 本身"两个工具都没有
// 就老实返回空字符串、不算错误"这个行为设计上是对的。这里改成先用
// exec.LookPath 探测当前环境实际有什么，再验证 SyncTime() 的返回值跟
// 探测结果一致——这样在任何环境跑都有意义，不会因为换一台机器就假失败。
func TestSyncTime_RealRun(t *testing.T) {
	method, err := SyncTime()
	if err != nil {
		t.Fatal(err)
	}

	var want string
	if _, lookErr := exec.LookPath("timedatectl"); lookErr == nil {
		want = "timedatectl"
	} else if _, lookErr := exec.LookPath("ntpdate"); lookErr == nil {
		want = "ntpdate"
	} else {
		want = ""
	}

	if method != want {
		t.Fatalf("当前环境探测到应该走 %q，SyncTime() 实际返回 %q", want, method)
	}
}

func TestParseUFWRuleNumbers(t *testing.T) {
	const sample = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # sing-box:trojan
[ 2] 8443/tcp                   ALLOW IN    Anywhere                   # unrelated rule
[ 3] 9000/udp                   ALLOW IN    Anywhere                   # sing-box:hysteria2
`
	got := parseUFWRuleNumbers(sample, "sing-box")
	want := []int{3, 1} // 从大到小
	if len(got) != len(want) {
		t.Fatalf("应该解析出 %v，实际 %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("应该解析出 %v，实际 %v", want, got)
		}
	}
}

func TestParseUFWRuleNumbers_NoMatch(t *testing.T) {
	const sample = `[ 1] 22/tcp ALLOW IN Anywhere # ssh`
	got := parseUFWRuleNumbers(sample, "sing-box")
	if len(got) != 0 {
		t.Fatalf("没有匹配的规则时应该返回空，实际 %v", got)
	}
}

// TestOpenFirewallPorts_UFWNotInstalled_RealRun 是真实调用：这个沙盒里
// 确实没装 ufw，走的是真实的"未安装"分支，不是构造出来的假场景。
func TestOpenFirewallPorts_UFWNotInstalled_RealRun(t *testing.T) {
	result, err := OpenFirewallPorts([]PortRule{
		{Port: 12345, Proto: "tcp", Comment: "sing-box:test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.UFWNotInstalled {
		t.Fatal("这个沙盒没装 ufw，应该走未安装分支")
	}
	if len(result.ManualInstructions) != 1 {
		t.Fatalf("应该给出 1 条手动指令，实际 %d 条", len(result.ManualInstructions))
	}
	want := `ufw allow 12345/tcp comment "sing-box:test"`
	if result.ManualInstructions[0] != want {
		t.Fatalf("手动指令应为 %q，实际 %q", want, result.ManualInstructions[0])
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
