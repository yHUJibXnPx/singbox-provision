// Package randgen 对应原 bash 脚本里所有"生成随机值"的函数：
// gen_uuid / gen_password / gen_short_id / gen_many_short_ids / 以及 anytls 的
// padding_scheme 那一大段。全部用 crypto/rand，标准库自带，不需要额外依赖。
package randgen

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
)

// randIntn 返回 [0, n) 内的随机整数，等价于 bash 里 get_true_random() % n 的效果，
// 但用 crypto/rand 而不是 /dev/urandom+awk 拼凑，且没有 shell 那种"两次调用结果
// 不一致导致 min>max"的隐患（原脚本第一次随机 padding 计算完全是死代码，见下方说明）。
func randIntn(n int64) int64 {
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		// crypto/rand 在正常操作系统上不应该失败；失败了说明系统熵源有问题，
		// 直接 panic 比静默退化成弱随机数更安全。
		panic(fmt.Sprintf("randgen: 读取随机数失败: %v", err))
	}
	return v.Int64()
}

// NewUUID 生成一个 RFC 4122 v4 UUID，格式与 `sing-box generate uuid` 完全一致
// （小写、连字符分隔），不依赖任何第三方库。
func NewUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("randgen: 生成 UUID 失败: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// HexPassword 对应 gen_password() { openssl rand -hex 12; }：12 字节随机数，
// 编码成 24 位十六进制字符串。
func HexPassword() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("randgen: 生成密码失败: %v", err))
	}
	return hex.EncodeToString(b)
}

// ShortID 对应 gen_short_id()：字节数在 [2,8] 之间随机（原脚本 rand%7+2），
// 编码成小写十六进制（4~16 个字符）。
func ShortID() string {
	nBytes := 2 + randIntn(7) // 2..8
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("randgen: 生成 short-id 失败: %v", err))
	}
	return hex.EncodeToString(b)
}

// ManyShortIDs 对应 gen_many_short_ids()：数量在 [4,8] 之间随机（原脚本 rand%5+4）。
func ManyShortIDs() []string {
	count := 4 + randIntn(5) // 4..8
	ids := make([]string, count)
	for i := range ids {
		ids[i] = ShortID()
	}
	return ids
}

// PickRandom 对应 pick_random_short_id()：从一组 short-id 里随机挑一个，
// 用于把「一组 short_id」和「链接里单独要用的那一个 short_id」关联起来。
func PickRandom(ids []string) string {
	return ids[randIntn(int64(len(ids)))]
}

// ensureMinMax 对应原脚本的 ensure_min_max()：保证输出总是 "小-大"，
// 而不是万一算出 min>max 时生成一个不合法的区间字符串。
func ensureMinMax(min, max int64) string {
	if min > max {
		min, max = max, min
	}
	return fmt.Sprintf("%d-%d", min, max)
}

// PaddingScheme 生成 anytls 用的随机流量填充方案（12 条规则）。
//
// 关于跟原脚本的一处差异：原脚本在真正生效的那组随机数（STOP_VAL/R0_FIXED.../
// R_HIGH_...）之前，还有一段几乎一模一样、专门算 R0_MIN/R0_MAX/R1_MIN/R1_MAX/
// R2_BASE/R2_MAX/R_HIGH 的代码——但这些变量算出来之后，从头到尾没有被下面任何一
// 个 PAD_* 用到，全部会被同名变量的第二次赋值覆盖掉。这是纯粹的死代码，我在这里
// 直接删掉了，不影响任何最终生成的值。
//
// 另外原脚本还多算了一个 PAD_12（"11=50-150,c,...,700-1100""），但拼最终 JSON
// 数组时只取了 PAD_0..PAD_11 共 12 个元素，PAD_12 从未被用上——同样是死代码，
// 这里也没有保留。用你上传的 config.json 核对过：真实生效的 padding_scheme 正好
// 是 12 条、到 "10=..." 为止，跟这里的实现一致。
func PaddingScheme() []string {
	stopVal := randIntn(7) + 6

	r0Fixed := randIntn(11) + 20
	r0Fixed2 := randIntn(21) + 40
	r0Fixed3 := randIntn(11) + 50
	r0Fixed4 := randIntn(16) + 25

	r1Min := randIntn(101) + 80
	r1Max := r1Min + randIntn(201) + 100

	r2Base := randIntn(201) + 250
	r2Gap1 := r2Base + randIntn(151) + 100
	r2Gap2 := r2Gap1 + randIntn(201) + 150

	rHighBase := randIntn(201) + 400
	rHighMid := rHighBase + randIntn(301) + 150
	rHighMax := rHighBase + randIntn(401) + 300

	return []string{
		fmt.Sprintf("stop=%d", stopVal),
		fmt.Sprintf("0=%d-%d", r0Fixed, r0Fixed),
		fmt.Sprintf("1=%d-%d", r0Fixed2, r0Fixed2),
		fmt.Sprintf("2=%d-%d", r0Fixed3, r0Fixed3),
		fmt.Sprintf("3=%d-%d", r0Fixed4, r0Fixed4),
		fmt.Sprintf("4=%d-%d", r1Min, r1Max),
		fmt.Sprintf("5=%s,c,%s,c,%s",
			ensureMinMax(r2Base, r2Base+120),
			ensureMinMax(r2Gap1, r2Gap1+180),
			ensureMinMax(r2Gap2, r2Gap2+220)),
		fmt.Sprintf("6=9-9,%s", ensureMinMax(rHighBase, rHighBase+250)),
		fmt.Sprintf("7=%s", ensureMinMax(rHighBase+100, rHighBase+400)),
		fmt.Sprintf("8=%s,c,%s",
			ensureMinMax(rHighBase+200, rHighBase+500),
			ensureMinMax(rHighMid, rHighMid+300)),
		fmt.Sprintf("9=%s,c,%s",
			ensureMinMax(rHighBase+300, rHighBase+600),
			ensureMinMax(rHighMid+200, rHighMax)),
		fmt.Sprintf("10=12-12,%s", ensureMinMax(rHighBase+400, rHighBase+800)),
	}
}
