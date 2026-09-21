package portcheck

import "fmt"

// Ports 是 8 个入站最终拿到的端口号。
//
// 注意几处"数字相同、协议不同"的共用关系（这是原脚本有意为之的设计，不是
// bug）：Hysteria2(UDP) 复用 VLESS(TCP) 的端口数字；TUIC(UDP) 复用
// VmessWSTLS(TCP) 的端口数字。TCP 和 UDP 是操作系统里两个独立的 socket
// 命名空间，同一个数字端口可以分别被一个 TCP 服务和一个 UDP 服务占用，
// 互不冲突。
type Ports struct {
	VLESS        int // TCP，随机
	Trojan       int // TCP，随机
	AnyTLS       int // TCP，随机
	VmessReality int // TCP，随机
	VlessWS      int // TCP，随机
	Hysteria2    int // UDP，与 VLESS 共用端口数字
	VmessWSTLS   int // TCP，优先 443（Cloudflare CDN 回源要求），被占用则随机
	TUIC         int // UDP，与 VmessWSTLS 共用端口数字
}

// Allocate 对应原脚本 861~910 行的完整端口分配策略。
func Allocate() (*Ports, error) {
	rp, err := FreeRandomPorts(6)
	if err != nil {
		return nil, err
	}

	p := &Ports{
		VLESS:        rp[0],
		Trojan:       rp[1],
		AnyTLS:       rp[2],
		VmessReality: rp[3],
		VlessWS:      rp[4],
	}
	p.Hysteria2 = p.VLESS // UDP，跟 VLESS 的 TCP 端口共用数字，互不冲突

	if IsTCPPortFree(443) {
		p.VmessWSTLS = 443
	} else {
		p.VmessWSTLS = rp[5]
	}

	p.TUIC = p.VmessWSTLS // 先假设能跟 VmessWSTLS 共用数字端口
	if !IsUDPPortFree(p.TUIC) {
		p.TUIC = rp[5]
		if !IsUDPPortFree(p.TUIC) {
			// 原脚本这里是硬失败退出（"终止"），不是继续找第三个候选——
			// 保留这个行为：failure 就是 failure，不要在这一步偷偷放宽标准。
			return nil, fmt.Errorf("TUIC 候选 UDP 端口 %d 仍被占用，无法分配", p.TUIC)
		}
	}

	return p, nil
}
