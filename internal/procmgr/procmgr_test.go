package procmgr

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempLog(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.log")
}

func TestIsAlive_TrueThenFalseAfterExit(t *testing.T) {
	started, err := startDetached("sleep", []string{"2"}, tempLog(t))
	if err != nil {
		t.Fatalf("测试环境跑不起来 sleep: %v", err)
	}

	if !IsAlive(started.PID) {
		t.Fatal("进程刚启动，应该判定为存活")
	}

	// 等它自然退出（sleep 2 秒），确认 startDetached 内部的后台 reap
	// 生效之后，IsAlive 能正确反映"已经死了"，而不是因为僵尸进程残留
	// 在进程表里、对信号 0 依然有响应，被误判成"还活着"。
	time.Sleep(2500 * time.Millisecond)
	if IsAlive(started.PID) {
		t.Fatal("进程已经退出，不该再判定为存活（可能是僵尸进程没被正确 reap）")
	}
}

func TestStop_PlainSIGTERMIsEnoughForWellBehavedProcess(t *testing.T) {
	started, err := startDetached("sleep", []string{"30"}, tempLog(t))
	if err != nil {
		t.Fatalf("测试环境跑不起来 sleep: %v", err)
	}

	start := time.Now()
	if err := Stop(started.PID, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if IsAlive(started.PID) {
		t.Fatal("Stop 之后进程不应该还活着")
	}
	// sleep 收到 SIGTERM 会立刻退出，不需要等到宽限期用完、更不需要 SIGKILL。
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("正常响应 SIGTERM 的进程不该等这么久才停下: %v", elapsed)
	}
}

func TestStop_EscalatesToSIGKILLWhenTermIsIgnored(t *testing.T) {
	// trap 掉 TERM，逼 Stop() 走到 SIGKILL 那条路径。
	started, err := startDetached("sh", []string{"-c", "trap '' TERM; sleep 30"}, tempLog(t))
	if err != nil {
		t.Fatalf("测试环境跑不起来 sh: %v", err)
	}

	if err := Stop(started.PID, 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	// 给 SIGKILL 一点点生效 + 被 reap 的时间再判活。
	time.Sleep(300 * time.Millisecond)
	if IsAlive(started.PID) {
		t.Fatal("忽略 SIGTERM 的进程应该被 SIGKILL 兜底杀掉")
	}
}

func TestWaitUntilAlive_FalseForNonExistentPID(t *testing.T) {
	// 用一个几乎不可能真实存在的 PID。
	if WaitUntilAlive(999999, 2, 10*time.Millisecond) {
		t.Fatal("不存在的 PID 不应该被判定为存活")
	}
}

func TestWaitUntilAlive_TrueForRealProcess(t *testing.T) {
	started, err := startDetached("sleep", []string{"2"}, tempLog(t))
	if err != nil {
		t.Fatalf("测试环境跑不起来 sleep: %v", err)
	}
	defer Stop(started.PID, time.Second)

	if !WaitUntilAlive(started.PID, 3, 50*time.Millisecond) {
		t.Fatal("真实存在的进程应该被判定为存活")
	}
}

func TestExtractTrycloudflareDomain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cloudflared.log")
	content := `2026-09-14T10:00:00Z INF Requesting new quick Tunnel on trycloudflare.com...
2026-09-14T10:00:01Z INF +--------------------------------------------------------------------------------------------+
2026-09-14T10:00:01Z INF |  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):    |
2026-09-14T10:00:01Z INF |  https://eddie-adding-preferences-accessibility.trycloudflare.com                            |
2026-09-14T10:00:01Z INF +--------------------------------------------------------------------------------------------+
`
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ExtractTrycloudflareDomain(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "eddie-adding-preferences-accessibility.trycloudflare.com"
	if got != want {
		t.Fatalf("提取出的域名应为 %q，实际 %q", want, got)
	}
}

func TestExtractTrycloudflareDomain_NotFound(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "cloudflared.log")
	if err := os.WriteFile(logPath, []byte("没有域名的日志\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractTrycloudflareDomain(logPath); err == nil {
		t.Fatal("日志里没有域名时应该报错，不该返回空字符串装作成功")
	}
}
