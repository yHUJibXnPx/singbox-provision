package classify

import "testing"

func TestClassify_BasicMatch(t *testing.T) {
	nodes := []Node{{Tag: "美国vless-out-abc123"}, {Tag: "日本trojan-out-def456"}}
	got := Classify(nodes)
	if len(got["美国_469138946ba5fa"]) != 1 || got["美国_469138946ba5fa"][0] != "美国vless-out-abc123" {
		t.Fatalf("美国节点分类不对: %v", got["美国_469138946ba5fa"])
	}
	if len(got["日本_469138946ba5fa"]) != 1 || got["日本_469138946ba5fa"][0] != "日本trojan-out-def456" {
		t.Fatalf("日本节点分类不对: %v", got["日本_469138946ba5fa"])
	}
}

func TestClassify_GroupsWithNoMatchAreAbsent(t *testing.T) {
	nodes := []Node{{Tag: "美国vless-out-abc123"}}
	got := Classify(nodes)
	if _, ok := got["法国_469138946ba5fa"]; ok {
		t.Fatal("没有任何节点匹配法国，法国不该出现在结果里")
	}
}

// TestClassify_HexSubstringFalsePositive 对应原脚本注释里记录的坑 1：
// 32 位随机 UUID 里偶然带出 "de" 或 "ca" 子串，如果不加 \b 词边界就会被
// 误判进德国/加拿大。这里构造一个刻意包含 "de" 和 "ca" 子串、但跟德国/
// 加拿大毫无关系的随机十六进制 tag，验证不会被误分类。
func TestClassify_HexSubstringFalsePositive(t *testing.T) {
	// "abcdef0123456789" 这类随机 hex 串很容易天然包含 "de"、"ca" 子串。
	nodes := []Node{{Tag: "vless-out-fadecafe1234567890abcdef"}}
	got := Classify(nodes)
	for tag, hits := range got {
		if tag == "德国_469138946ba5fa" || tag == "加拿大_469138946ba5fa" {
			t.Fatalf("不该被误判进 %s（词边界没生效）: %v", tag, hits)
		}
	}
}

// TestClassify_AnyTLSDoesNotFalsePositiveIntoUS 对应原脚本注释里记录的坑 2
// （"必现 bug，不是概率性的"）：AnyTLS 协议固定 tag 前缀 "anytls-out-" 本身
// 就包含 "ny" 子串，如果美国分组的正则没有给 "NY" 加词边界，每一个 AnyTLS
// 节点都会被误判进美国组——不管这个节点实际部署在哪。这里故意不给这个
// tag 任何跟美国相关的标记，验证它不会被 "NY" 误伤。
func TestClassify_AnyTLSDoesNotFalsePositiveIntoUS(t *testing.T) {
	nodes := []Node{{Tag: "anytls-out-e6f7f413b8044269a680bff7a1c8860c"}}
	got := Classify(nodes)
	if hits, ok := got["美国_469138946ba5fa"]; ok {
		t.Fatalf("anytls-out- 里的 \"ny\" 子串不该把节点误判进美国组: %v", hits)
	}
}

func TestClassify_USStillMatchesRealNYMention(t *testing.T) {
	// 确认上面那条防呆没有矫枉过正：一个真正带 "NY"（作为独立单词）的
	// 节点，还是应该被分类进美国组。
	nodes := []Node{{Tag: "美国NY-vless-out-abc"}}
	got := Classify(nodes)
	if len(got["美国_469138946ba5fa"]) != 1 {
		t.Fatalf("真正的 NY 标记应该正常命中美国组: %v", got["美国_469138946ba5fa"])
	}
}

func TestClassify_MutualExclusivityFollowsGroupOrder(t *testing.T) {
	// "港" 和 "美" 都可能出现在同一个 tag 里时，按 Groups 里的处理顺序，
	// 排在前面的分组（香港排在美国前面）应该先抢到这个节点。
	nodes := []Node{{Tag: "香港美国中转-vless-out-abc"}}
	got := Classify(nodes)
	if len(got["香港_469138946ba5fa"]) != 1 {
		t.Fatalf("应该被排序更靠前的香港组抢到: %v", got)
	}
	if _, ok := got["美国_469138946ba5fa"]; ok {
		t.Fatal("已经被香港组匹配走的节点，不该再出现在美国组里")
	}
}
