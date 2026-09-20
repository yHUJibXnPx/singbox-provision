package procmgr

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type SingBoxParams struct {
	BinaryPath string
	ConfigDir  string // -D
	ConfigPath string // -c
	LogPath    string
}

// CheckConfig 对应 `sing-box check -D ... -c ...`，失败就不该往下启动。
func CheckConfig(p SingBoxParams) error {
	cmd := exec.Command(p.BinaryPath, "check", "-D", p.ConfigDir, "-c", p.ConfigPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box check 失败: %w\n%s", err, out)
	}
	return nil
}

// StartSingBox 对应原脚本第 1357~1376 行那一整套流程：check → 先短暂启动
// 一次看看有没有立刻炸掉 → 杀掉 → 正式启动 → 用 WaitUntilAlive 验证。
// 这个"启动两次"的模式是原脚本自己的设计，不是我加的；保留它是因为不
// 确定这背后是不是在规避某个真实部署环境下才会出现的启动竞态，贸然砍掉
// 可能引入原脚本从来没暴露过的问题——真要简化，等确认了原因再改不迟。
func StartSingBox(p SingBoxParams) (*Started, error) {
	if err := CheckConfig(p); err != nil {
		return nil, err
	}
	args := []string{"-D", p.ConfigDir, "-c", p.ConfigPath, "run"}

	first, err := startDetached(p.BinaryPath, args, p.LogPath)
	if err != nil {
		return nil, err
	}
	time.Sleep(1 * time.Second)
	_ = Stop(first.PID, 2*time.Second)

	started, err := startDetached(p.BinaryPath, args, p.LogPath)
	if err != nil {
		return nil, err
	}
	if !WaitUntilAlive(started.PID, 5, 1*time.Second) {
		content, _ := os.ReadFile(p.LogPath)
		return nil, fmt.Errorf("sing-box 启动失败，最近日志:\n%s", tailLines(string(content), 30))
	}
	return started, nil
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}
