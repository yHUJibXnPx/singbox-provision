package randgen

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewUUID(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewUUID()
		if !uuidRe.MatchString(id) {
			t.Fatalf("UUID 格式不对: %q", id)
		}
		if seen[id] {
			t.Fatalf("1000 次里出现重复 UUID: %q", id)
		}
		seen[id] = true
	}
}

func TestHexPassword(t *testing.T) {
	// gen_password() { openssl rand -hex 12; } -> 24 个十六进制字符
	p := HexPassword()
	if len(p) != 24 {
		t.Fatalf("密码长度应为 24，实际 %d: %q", len(p), p)
	}
	if _, err := regexp.Compile(`^[0-9a-f]{24}$`); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{24}$`).MatchString(p) {
		t.Fatalf("密码不是纯小写十六进制: %q", p)
	}
}

func TestShortID(t *testing.T) {
	// 原脚本 bytes = rand%7+2，即 2~8 字节 -> 十六进制 4~16 个字符
	for i := 0; i < 500; i++ {
		id := ShortID()
		if len(id) < 4 || len(id) > 16 || len(id)%2 != 0 {
			t.Fatalf("short-id 长度超出预期范围 [4,16] 偶数: %q (len=%d)", id, len(id))
		}
	}
}

func TestManyShortIDs(t *testing.T) {
	for i := 0; i < 200; i++ {
		ids := ManyShortIDs()
		if len(ids) < 4 || len(ids) > 8 {
			t.Fatalf("short-id 组数量超出预期范围 [4,8]: %d", len(ids))
		}
	}
}

func TestRealityKeyPair(t *testing.T) {
	priv, pub, err := RealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"private": priv, "public": pub} {
		if len(v) != 43 {
			t.Fatalf("%s key 长度应为 43（32 字节 base64 无 padding），实际 %d: %q", name, len(v), v)
		}
		if strings.Contains(v, "=") {
			t.Fatalf("%s key 不应包含 padding: %q", name, v)
		}
		raw, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("%s key 不是合法的 base64 URL 编码: %v", name, err)
		}
		if len(raw) != 32 {
			t.Fatalf("%s key 解码后应为 32 字节，实际 %d", name, len(raw))
		}
	}
	if priv == pub {
		t.Fatal("私钥和公钥不应相同")
	}
}

func TestPaddingScheme(t *testing.T) {
	for i := 0; i < 200; i++ {
		p := PaddingScheme()
		if len(p) != 12 {
			t.Fatalf("padding scheme 应该正好 12 条，实际 %d", len(p))
		}
		if !strings.HasPrefix(p[0], "stop=") {
			t.Fatalf("第一条应以 stop= 开头: %q", p[0])
		}
		for idx, entry := range p[1:] {
			prefix := regexp.MustCompile(`^\d+=`)
			if !prefix.MatchString(entry) {
				t.Fatalf("第 %d 条格式不对: %q", idx+1, entry)
			}
		}
		// 每个 "min-max" 区间里 min 必须 <= max（ensureMinMax 的职责）
		rangeRe := regexp.MustCompile(`(\d+)-(\d+)`)
		for _, entry := range p {
			for _, m := range rangeRe.FindAllStringSubmatch(entry, -1) {
				var lo, hi int
				_, _ = fmtSscanRange(m[1], m[2], &lo, &hi)
				if lo > hi {
					t.Fatalf("区间 min>max: %q in %q", m[0], entry)
				}
			}
		}
	}
}

func fmtSscanRange(a, b string, lo, hi *int) (int, error) {
	var err error
	*lo, err = atoi(a)
	if err != nil {
		return 0, err
	}
	*hi, err = atoi(b)
	return 0, err
}

func atoi(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, &strErr{"非数字: " + s}
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

type strErr struct{ s string }

func (e *strErr) Error() string { return e.s }
