package sysconfig

import (
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

type PortRule struct {
	Port    int
	Proto   string // "tcp" 或 "udp"
	Comment string
}

// FirewallResult 描述 OpenFirewallPorts 实际做了什么，供调用方决定怎么
// 展示给用户——原脚本这一步无论发生什么都不会中断安装（ufw 没装、没
// 激活、清理旧规则失败，都只是打印信息然后继续）。
type FirewallResult struct {
	UFWNotInstalled    bool  // ufw 没装，ManualInstructions 里是给用户看的命令
	UFWInactive        bool  // ufw 装了但没激活
	RemovedRuleNums    []int // 清理掉的旧 "sing-box" 规则编号（从大到小）
	ManualInstructions []string
}

// OpenFirewallPorts 对应 open_firewall_ports()：
//   - 没装 ufw → 打印出用户可以自己手动执行的 ufw 命令，不报错。
//   - 装了但未激活 → 跳过，不去动它。
//   - 已激活 → 清理带 "sing-box" 标记的旧规则（按编号从大到小删，避免
//     删除过程中编号错位），然后放行新端口。
func OpenFirewallPorts(rules []PortRule) (FirewallResult, error) {
	if _, err := exec.LookPath("ufw"); err != nil {
		instructions := make([]string, 0, len(rules))
		for _, r := range rules {
			instructions = append(instructions, fmt.Sprintf(
				`ufw allow %d/%s comment "%s"`, r.Port, r.Proto, r.Comment))
		}
		return FirewallResult{UFWNotInstalled: true, ManualInstructions: instructions}, nil
	}

	statusOut, err := exec.Command("ufw", "status").CombinedOutput()
	if err != nil {
		return FirewallResult{}, fmt.Errorf("执行 ufw status 失败: %w", err)
	}
	if strings.Contains(strings.ToLower(string(statusOut)), "inactive") {
		return FirewallResult{UFWInactive: true}, nil
	}

	numberedOut, err := exec.Command("ufw", "status", "numbered").CombinedOutput()
	if err != nil {
		return FirewallResult{}, fmt.Errorf("执行 ufw status numbered 失败: %w", err)
	}
	oldNums := parseUFWRuleNumbers(string(numberedOut), "sing-box")
	for _, n := range oldNums {
		// 对应原脚本 `yes | ufw delete "$NUM"`：ufw delete 需要一次
		// y/n 确认，用 --force 跳过交互，效果一样，不用真的管一个假的
		// stdin 输入流。
		_ = exec.Command("ufw", "--force", "delete", strconv.Itoa(n)).Run()
	}

	for _, r := range rules {
		_ = exec.Command("ufw", "allow", fmt.Sprintf("%d/%s", r.Port, r.Proto),
			"comment", r.Comment).Run()
	}

	return FirewallResult{RemovedRuleNums: oldNums}, nil
}

// parseUFWRuleNumbers 对应原脚本这一行纯文本处理逻辑：
//
//	ufw status numbered | grep -i "关键词" | awk -F"[][]" '{print $2}' | sort -rn
//
// 单独拆出来是为了能用固定文本做单元测试，不需要真的装 ufw。
func parseUFWRuleNumbers(statusNumbered, keyword string) []int {
	var nums []int
	keyword = strings.ToLower(keyword)
	for _, line := range strings.Split(statusNumbered, "\n") {
		if !strings.Contains(strings.ToLower(line), keyword) {
			continue
		}
		open := strings.IndexByte(line, '[')
		close := strings.IndexByte(line, ']')
		if open < 0 || close < 0 || close <= open {
			continue
		}
		numStr := strings.TrimSpace(line[open+1 : close])
		n, err := strconv.Atoi(numStr)
		if err != nil {
			continue
		}
		nums = append(nums, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(nums)))
	return nums
}
