package sysconfig

import (
	"os"
	"os/exec"
	"strings"
)

// BBRResult 记录 EnsureBBR 的最终状态——原脚本这一步从来不会让整个安装
// 失败（内核太旧、或者启用后验证不通过，都只是打印警告然后继续），所以
// Go 版也不用一个 error 把"跳过""失败""成功"这几种情况混在一起，用结构体
// 把状态说清楚，让调用方自己决定要不要打印警告，err 只留给"读内核版本
// 这种基本操作都失败了"这类真正意外的情况。
type BBRResult struct {
	Skipped                  bool // 内核版本低于 4.9，直接跳过
	Enabled                  bool // 验证后确认拥塞控制算法确实是 bbr
	CurrentCongestionControl string
	KernelVersion            string
}

// EnsureBBR 对应 enable_bbr()：检查内核版本 → 幂等写入 sysctl.conf →
// `sysctl -p` → 用 `sysctl -n net.ipv4.tcp_congestion_control` 验证。
// sysctlConfPath 参数化是为了测试时可以指向临时文件，不需要真的改
// /etc/sysctl.conf。
func EnsureBBR(sysctlConfPath string) (BBRResult, error) {
	major, minor, err := KernelVersion()
	if err != nil {
		return BBRResult{}, err
	}
	kernelStr := itoa(major) + "." + itoa(minor)

	if major < 4 || (major == 4 && minor < 9) {
		return BBRResult{Skipped: true, KernelVersion: kernelStr}, nil
	}

	if err := ensureLineInFile(sysctlConfPath, "net.core.default_qdisc=fq"); err != nil {
		return BBRResult{}, err
	}
	if err := ensureLineInFile(sysctlConfPath, "net.ipv4.tcp_congestion_control=bbr"); err != nil {
		return BBRResult{}, err
	}

	_ = exec.Command("sysctl", "-p").Run() // 跟原脚本一致：允许失败，不中断流程

	out, _ := exec.Command("sysctl", "-n", "net.ipv4.tcp_congestion_control").Output()
	current := strings.TrimSpace(string(out))

	return BBRResult{
		Enabled:                  current == "bbr",
		CurrentCongestionControl: current,
		KernelVersion:            kernelStr,
	}, nil
}

// ensureLineInFile 对应原脚本 `grep -q "..." file || echo "..." >> file`
// 这个幂等追加模式：跟原脚本一样是子串匹配（只要文件里任意一行包含这个
// 子串就算已存在），不是要求整行完全相等——这跟原脚本的判断标准保持一致，
// 不是我随手改成了更严格的比较。
func ensureLineInFile(path, line string) error {
	content, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if strings.Contains(string(content), line) {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line + "\n")
	return err
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
