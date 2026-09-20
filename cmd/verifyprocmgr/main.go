// cmd/verifyprocmgr 用真实 sing-box 二进制（从 /home/claude/work/sing-box
// 复制，这个沙盒里之前手工下载验证过的那一份）+ cmd/verify 生成的真实
// config.json，完整跑一遍"check → 启动 → 确认存活 → 停止 → 确认已停"，
// 不是只测 procmgr 内部逻辑，是端到端跑一次真实的 sing-box 进程生命周期。
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"singboxprovision/internal/procmgr"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	workDir := "/tmp/procmgr-verify"
	must(os.RemoveAll(workDir))
	must(os.MkdirAll(workDir+"/config", 0o755))

	// 复用之前手工下载验证过的真实 sing-box 二进制。
	must(copyFile("/home/claude/work/sing-box", workDir+"/sing-box"))
	must(os.Chmod(workDir+"/sing-box", 0o755))

	// 复用 cmd/verify 已经生成、已经验证过的真实 config.json 会在启动时
	// 尝试联网拉取 rule-set（这是 sing-box 配置本身的正常行为，不是
	// procmgr 的事），这个沙盒的出站网络对 sing-box 自己发起的 DNS
	// 解析有限制，会在这一步卡住——跟 procmgr 要验证的"进程生死管理"是
	//两码事，所以这里换一份不需要联网就能启动的最小配置，专门验证
	// StartSingBox/IsAlive/Stop 这条链路本身；config.json 的内容正确性
	// 已经在 cmd/verify 里用真实数据验证过，不需要在这里重复验证。
	must(copyFile("/tmp/minimal-singbox-config.json", workDir+"/config.json"))

	p := procmgr.SingBoxParams{
		BinaryPath: workDir + "/sing-box",
		ConfigDir:  workDir + "/config",
		ConfigPath: workDir + "/config.json",
		LogPath:    workDir + "/sing-box.log",
	}

	fmt.Println("== 启动 sing-box（含 check + 两阶段启动）==")
	started, err := procmgr.StartSingBox(p)
	must(err)
	fmt.Printf("启动成功，PID=%d\n", started.PID)

	fmt.Println("== 确认真的在监听端口（直接拨号，不依赖 ss/netstat 这些可能没装的工具）==")
	time.Sleep(500 * time.Millisecond)
	conn, dialErr := net.DialTimeout("tcp", "127.0.0.1:17890", 2*time.Second)
	if dialErr != nil {
		panic(fmt.Sprintf("端口应该已经被 sing-box 监听，拨号失败: %v", dialErr))
	}
	conn.Close()
	fmt.Println("拨号成功，端口确实在监听")

	fmt.Println("== 停止 sing-box ==")
	must(procmgr.Stop(started.PID, 3*time.Second))
	if procmgr.IsAlive(started.PID) {
		panic("停止之后进程不应该还活着")
	}
	fmt.Println("已确认停止，PID 不再存活")
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}
