// Package portcheck 对应原脚本 is_port_in_use() 和 gen_free_random_ports()。
//
// 原脚本要靠 ss → netstat → lsof → 手工解析 /proc/net/{tcp,udp}[6] 四级降级链
// 才能在"什么工具都可能没装"的裸机上判断一个端口是否被占用。Go 标准库
// 里判断端口能不能用的做法反而更直接、更可靠：直接尝试绑定，绑得上就是真
// 的空闲，绑不上就是真的被占用——不需要猜测宿主机装了哪个网络工具，也不用
// 解析任何命令的文本输出。
package portcheck

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
)

const (
	minRandomPort = 20000
	maxRandomPort = 60000 // 原脚本 int(rand()*40000)+20000，区间 [20000, 60000)
)

// IsTCPPortFree 尝试绑定 TCP 端口，能绑上说明空闲。
func IsTCPPortFree(port int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// IsUDPPortFree 尝试绑定 UDP 端口，能绑上说明空闲。
func IsUDPPortFree(port int) bool {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// IsPortFree 对应原脚本 proto=both：TCP 和 UDP 必须同时空闲才算空闲。
// 之所以两者都要查，是因为 Hysteria2/TUIC 这些 UDP 协议会跟 TCP 协议共用
// 同一个端口号（同一个数字、不同协议栈，操作系统层面互不冲突），分配新
// 端口时必须保证两边都没人用，后面才能放心地"一个数字端口两种协议各用一次"。
func IsPortFree(port int) bool {
	return IsTCPPortFree(port) && IsUDPPortFree(port)
}

func randomPort() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxRandomPort-minRandomPort)))
	if err != nil {
		return 0, err
	}
	return minRandomPort + int(n.Int64()), nil
}

// FreeRandomPorts 对应原脚本 gen_free_random_ports()：一次性生成 count 个
// 互不相同、且同时确认 TCP/UDP 都空闲的随机端口，最多重试 100 轮
// （跟原脚本的 max_tries=100 一致）。
func FreeRandomPorts(count int) ([]int, error) {
	const maxTries = 100

	for try := 0; try < maxTries; try++ {
		seen := make(map[int]bool, count)
		candidates := make([]int, 0, count)
		for len(candidates) < count {
			p, err := randomPort()
			if err != nil {
				return nil, fmt.Errorf("生成随机端口失败: %w", err)
			}
			if seen[p] {
				continue
			}
			seen[p] = true
			candidates = append(candidates, p)
		}

		conflict := false
		for _, p := range candidates {
			if !IsPortFree(p) {
				conflict = true
				break
			}
		}
		if !conflict {
			return candidates, nil
		}
	}

	return nil, fmt.Errorf("连续 %d 次都无法找到 %d 个互不冲突的空闲随机端口", maxTries, count)
}
