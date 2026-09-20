package sysconfig

import "os/exec"

// SyncTime 对应原脚本：优先 `timedatectl set-ntp true`，没有 timedatectl
// 就退化到 `ntpdate pool.ntp.org`，两者失败都不算错——原脚本原话是
// "无法同步时间或容器环境无法同步，仅显示，请手动检查 date"，本来就是
// 容器环境里的已知限制，不是需要中断安装的错误。
func SyncTime() (method string, err error) {
	if _, lookErr := exec.LookPath("timedatectl"); lookErr == nil {
		_ = exec.Command("timedatectl", "set-ntp", "true").Run()
		return "timedatectl", nil
	}
	if _, lookErr := exec.LookPath("ntpdate"); lookErr == nil {
		_ = exec.Command("ntpdate", "pool.ntp.org").Run()
		return "ntpdate", nil
	}
	return "", nil // 两个工具都没有，原样跳过，调用方决定要不要提示
}
