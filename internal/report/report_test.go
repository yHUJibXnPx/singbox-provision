package report

import (
	"strings"
	"testing"
)

func TestBuildCFResultLines_PadsToSixtyFiveBytesNotRunes(t *testing.T) {
	// "美国" 是 2 个 Unicode 字符，但 UTF-8 编码下是 6 个字节——如果按
	// "字符数"补齐会跟原脚本 bash printf 的"字节数"补齐结果对不上。
	entries := []CFEntry{
		{Tag: "美国cf-ob-CF-104.16-443-8528c76702004e08841acafa89d2ac25", Link: "vless://x"},
	}
	got := buildCFResultLines(entries)

	tagWithColon := entries[0].Tag + ":"
	byteLen := len(tagWithColon) // Go 的 len() 对 string 就是字节数
	wantPadding := 65 - byteLen
	wantLine := "[9] " + tagWithColon + strings.Repeat(" ", wantPadding) + " vless://x"

	if !strings.HasPrefix(got, wantLine) {
		t.Fatalf("补齐结果不对:\n got: %q\nwant prefix: %q", got, wantLine)
	}
}

func TestBuildCFResultLines_IndexStartsAtNine(t *testing.T) {
	entries := []CFEntry{
		{Tag: "a", Link: "link-a"},
		{Tag: "b", Link: "link-b"},
	}
	got := buildCFResultLines(entries)
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("应该有 2 行，实际 %d", len(lines))
	}
	if !strings.HasPrefix(lines[0], "[9] ") {
		t.Fatalf("第一条应该从 [9] 开始（前面 [1]~[8] 是 8 个直连协议），实际: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "[10] ") {
		t.Fatalf("第二条应该是 [10]，实际: %q", lines[1])
	}
}

func TestBuildCFResultLines_LongTagIsNotTruncated(t *testing.T) {
	// tag 本身如果已经 >= 65 字节，不应该被截断或者不补空格导致贴着链接。
	longTag := strings.Repeat("x", 70)
	entries := []CFEntry{{Tag: longTag, Link: "vless://y"}}
	got := buildCFResultLines(entries)
	want := "[9] " + longTag + ": vless://y"
	if strings.TrimRight(got, "\n") != want {
		t.Fatalf("长 tag 处理不对:\n got: %q\nwant: %q", got, want)
	}
}

func TestBuild_TotalNodesCountsCoreAndCFTogether(t *testing.T) {
	p := Params{
		CFEntries: []CFEntry{{Tag: "a", Link: "l1"}, {Tag: "b", Link: "l2"}, {Tag: "c", Link: "l3"}},
	}
	out := Build(p)
	if !strings.Contains(out, "节点分享链接（全部 11 条）") {
		t.Fatal("总节点数应该是 8 个直连协议 + 3 个 CF 节点 = 11")
	}
	if !strings.Contains(out, "Base64 订阅码（全部 11 条）") {
		t.Fatal("Base64 那一段标题里的总数也应该是 11")
	}
}
