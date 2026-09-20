// Package sysconfig 对应原脚本的系统层操作：enable_bbr()、时间同步、
// open_firewall_ports()。这几块本质上还是在调同一批系统命令
// （sysctl/ufw/timedatectl），Go 版在这里的收益主要是结构化的错误处理和
// 可测试的纯逻辑部分，不是"把这些系统命令也用 Go 原生实现掉"——沙盒/防
// 火墙/时间同步这些事本来就该交给系统自己的工具做，没必要重新发明。
package sysconfig

import (
	"fmt"
	"os"
	"strings"
)

// KernelVersion 对应原脚本 `uname -r | cut -d. -f1/2`，但读取
// /proc/sys/kernel/osrelease（跟 `uname -r` 的输出内容完全一致）而不是
// shell out 到 uname 命令再解析文本。
//
// 这里特意没有用 syscall.Uname——那是 Linux 独有的系统调用，Utsname
// 结构体里 Release 字段的元素类型在不同架构下还不一样（amd64 是
// [65]int8，某些架构是 [65]uint8），跨架构会有额外的类型分支要处理；
// 更麻烦的是 syscall.Uname/Utsname 在 darwin 上根本不存在，用了它整个
// 二进制在 macOS 上会连编译都过不去——这是真实踩过的坑：这个包本该只在
// Linux 服务器上跑真正有意义的操作，但调用方（cmd/provision）需要能在
// macOS 上至少编译通过，才能先本地跑 `-h` 看看参数、或者交叉编译。
// 读 /proc/sys/kernel/osrelease 这个纯文本文件，在任何架构下都是同一种
// 格式，在非 Linux 系统上就是单纯地"文件不存在"运行时错误（EnsureBBR
// 已经把这类错误当非致命警告处理），不会在编译期就把整个程序挡在门外。
func KernelVersion() (major, minor int, err error) {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return 0, 0, fmt.Errorf("读取内核版本失败（/proc/sys/kernel/osrelease，非 Linux 系统上这个文件本来就不存在）: %w", err)
	}
	return parseMajorMinor(strings.TrimSpace(string(data)))
}

// parseMajorMinor 从 "6.18.44-fc-v33" 这种字符串里取出主/次版本号，
// 单独拆出来是为了不需要真的读文件就能测试解析逻辑本身。
func parseMajorMinor(release string) (major, minor int, err error) {
	dot1 := indexByte(release, '.')
	if dot1 < 0 {
		return 0, 0, fmt.Errorf("无法解析内核版本: %q", release)
	}
	rest := release[dot1+1:]
	dot2 := indexByte(rest, '.')
	minorStr := rest
	if dot2 >= 0 {
		minorStr = rest[:dot2]
	} else {
		// 次版本号后面可能直接跟着 "-xxx" 后缀而不是另一个点。
		if dash := indexByte(rest, '-'); dash >= 0 {
			minorStr = rest[:dash]
		}
	}

	major, err = atoi(release[:dot1])
	if err != nil {
		return 0, 0, fmt.Errorf("无法解析主版本号: %q", release)
	}
	minor, err = atoi(minorStr)
	if err != nil {
		return 0, 0, fmt.Errorf("无法解析次版本号: %q", release)
	}
	return major, minor, nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func atoi(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("空字符串")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("非数字: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
