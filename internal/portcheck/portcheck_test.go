package portcheck

import (
	"net"
	"testing"
)

func TestIsTCPPortFree_DetectsRealOccupation(t *testing.T) {
	l, err := net.Listen("tcp", ":0") // :0 让操作系统分配一个当前空闲端口
	if err != nil {
		t.Fatalf("测试环境本身无法监听端口: %v", err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	if IsTCPPortFree(port) {
		t.Fatalf("端口 %d 明明被占用着，却被判断为空闲", port)
	}
}

func TestIsTCPPortFree_DetectsReallyFreePort(t *testing.T) {
	// 先占用一个端口拿到端口号，再释放，紧接着测试应该判断为空闲。
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("测试环境本身无法监听端口: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	if !IsTCPPortFree(port) {
		t.Fatalf("端口 %d 已经释放，却被判断为占用", port)
	}
}

func TestIsUDPPortFree_DetectsRealOccupation(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("测试环境本身无法监听 UDP 端口: %v", err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	if IsUDPPortFree(port) {
		t.Fatalf("UDP 端口 %d 明明被占用着，却被判断为空闲", port)
	}
}

func TestFreeRandomPorts_ReturnsDistinctFreePorts(t *testing.T) {
	ports, err := FreeRandomPorts(6)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 6 {
		t.Fatalf("应该返回 6 个端口，实际 %d", len(ports))
	}
	seen := map[int]bool{}
	for _, p := range ports {
		if p < minRandomPort || p >= maxRandomPort {
			t.Fatalf("端口 %d 超出预期区间 [%d,%d)", p, minRandomPort, maxRandomPort)
		}
		if seen[p] {
			t.Fatalf("端口 %d 重复出现", p)
		}
		seen[p] = true
		if !IsPortFree(p) {
			t.Fatalf("FreeRandomPorts 返回的端口 %d 实际却不空闲", p)
		}
	}
}

func TestAllocate_SharesPortNumberAcrossUDPAndTCPAsDesigned(t *testing.T) {
	p, err := Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if p.Hysteria2 != p.VLESS {
		t.Fatalf("Hysteria2(UDP) 应该跟 VLESS(TCP) 共用端口数字: %d vs %d", p.Hysteria2, p.VLESS)
	}
	if p.TUIC != p.VmessWSTLS {
		t.Fatalf("TUIC(UDP) 应该跟 VmessWSTLS(TCP) 共用端口数字: %d vs %d", p.TUIC, p.VmessWSTLS)
	}

	all := []int{p.VLESS, p.Trojan, p.AnyTLS, p.VmessReality, p.VlessWS, p.VmessWSTLS}
	seen := map[int]bool{}
	for _, v := range all {
		if seen[v] {
			t.Fatalf("这几个应该各不相同的 TCP 端口出现了重复: %v", all)
		}
		seen[v] = true
	}
}

func TestAllocate_FallsBackWhen443Occupied(t *testing.T) {
	l, err := net.Listen("tcp", ":443")
	if err != nil {
		t.Skip("测试环境没有权限监听 443（需要 root），跳过这个场景")
	}
	defer l.Close()

	p, err := Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if p.VmessWSTLS == 443 {
		t.Fatal("443 已被占用，VmessWSTLS 不应该还选中 443")
	}
}
