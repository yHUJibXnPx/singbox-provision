// Package procmgr 对应原脚本"启动 sing-box"/"启动 cloudflared" 那两段
// nohup+disown+pkill -f 的进程管理逻辑。
//
// 核心差异：原脚本启动进程之后就跟它失去了直接联系，只能靠
// `pkill -f "关键词"` 按命令行文本模糊匹配去找到它、杀它——这意味着如果
// 服务器上凑巧有别的进程命令行也包含 "sing-box" 这几个字符（哪怕只是
// 谁在执行一条包含这个词的 grep/ps 命令，短暂地出现在进程列表里），
// 就有被一起误杀的风险。Go 版启动进程时能拿到内核分配的真实 PID
// （`cmd.Process.Pid`），后续全部操作都是"对这一个精确 PID 发信号"，
// 不存在"关键词恰好还匹配到别的进程"这类问题。
package procmgr

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Started 是一次成功启动后拿到的句柄。
type Started struct {
	Cmd     *exec.Cmd
	PID     int
	LogPath string
}

// startDetached 是 sing-box/cloudflared 共用的启动逻辑：把 stdout/stderr
// 重定向到日志文件，用 Setsid 让子进程脱离当前会话（对应 nohup+disown——
// 我们的 Go 程序退出之后，子进程不会收到 SIGHUP 被连带杀掉）。
func startDetached(name string, args []string, logPath string) (*Started, error) {
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("创建日志文件 %s 失败: %w", logPath, err)
	}

	cmd := exec.Command(name, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("启动 %s 失败: %w", name, err)
	}

	// 子进程会继承这个 fd 去写日志，父进程这边的 *os.File 用完就可以关，
	// 不影响子进程继续写——这跟 bash 里 `> file` 重定向后父 shell 退出、
	// 子进程仍持有同一个文件描述符是同一回事。
	logFile.Close()

	// 后台 reap：Go 的子进程退出后，如果没人调用过 Wait()，会一直以
	// "僵尸进程"的状态留在进程表里——而僵尸进程发信号 0（IsAlive 用来
	// 判活的手段）依然会成功，等于"明明死了却一直显示活着"。只要我们
	// 这个 Go 程序还在运行，就该有人负责 reap 掉自己启动的子进程；
	// 如果这个 Go 程序很快退出（一次性的 provision 工具，这正是本项目
	// 的预期用法），子进程会被系统重新挂到 init 下面，交给 init 兜底
	// reap，不受这里影响。这个 goroutine 只是为了在 Go 程序活得比较久
	// （比如常驻管理模式）的场景下，不留下僵尸进程、也不产生"假活着"的
	// 判断结果。
	go func() { _ = cmd.Wait() }()

	return &Started{Cmd: cmd, PID: cmd.Process.Pid, LogPath: logPath}, nil
}

// IsAlive 检查指定 PID 是否还活着，用信号 0（不会真的杀死目标，只是探测
// 该 PID 是否存在、当前进程是否有权限往它发信号）。这是 Unix 系统上判断
// "进程还在不在"的标准写法。
func IsAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

// Stop 对应原脚本"先 SIGTERM，等一段时间，再 SIGKILL"那套优雅停止逻辑，
// 但作用目标是一个精确 PID，不是命令行关键词匹配出来的一批进程。
func Stop(pid int, gracePeriod time.Duration) error {
	if !IsAlive(pid) {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	_ = process.Signal(syscall.SIGTERM)

	deadline := time.Now().Add(gracePeriod)
	for time.Now().Before(deadline) {
		if !IsAlive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	if IsAlive(pid) {
		_ = process.Signal(syscall.SIGKILL)
	}
	return nil
}

// WaitUntilAlive 对应原脚本 verify_singbox_running()：每隔一秒探测一次，
// 最多重试 retries 次。用真实 PID 判活，不是 `pgrep -f "sing-box.*run"`
// 那种可能匹配到无关进程的文本模式。
func WaitUntilAlive(pid int, retries int, interval time.Duration) bool {
	for i := 0; i < retries; i++ {
		time.Sleep(interval)
		if IsAlive(pid) {
			return true
		}
	}
	return false
}
