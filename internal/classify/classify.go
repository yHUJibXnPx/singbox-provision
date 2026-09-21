// Package classify 对应原脚本末尾那段"锦上添花"的自动分类
// （GROUPS_PATTERNS）：按 tag 里出现的地区名字/城市名/emoji，把真实协议
// 节点自动分进 12 个地区分组之一。
//
// 原脚本注释原话："这段只是锦上添花的自动分类，即便中途出错也只让对应
// 分组保持占位指向 直连_（不影响前面已经装好、已经在跑的 sing-box 服务）"。
// 这个定位很重要：这一步失败不该影响其它任何东西，Classify 本身也确实
// 设计成"匹配不到就不返回"，调用方据此决定"不碰"而不是"清空"对应分组。
package classify

import "regexp"

// Group 是一条"分组 tag + 匹配规则"。Pattern 是原始正则文本（不含 (?i)
// 前缀，匹配时统一加大小写不敏感）。
type Group struct {
	Tag     string
	Pattern string
}

// Groups 的顺序就是原脚本 GROUPS_PATTERNS 里从上到下的顺序：德国排最前，
// 美国压轴。这个顺序会实际影响结果——一个节点一旦被排在前面的分组"抢走"，
// 后面的分组就不会再匹配到它，所以不能随便调整。
//
// 关于 \b 词边界，这里跟原脚本的实际文本有一处刻意的出入，需要说清楚：
//
// 原脚本紧跟着这段数据的注释原话是——"所有 ≤3 字母的短代码（DE/JP/US/USA/
// SG/HK/TW/KR/UK/GB/CA/AU/FR/NL/LA/SF/NY）统一加了 \b 词边界"，并且解释了
// 两个实测踩过的坑：32 位随机 UUID 偶然带出 "de"/"ca" 子串误判进德国/
// 加拿大；AnyTLS 固定 tag 前缀 "anytls-out-" 自带 "ny"，会 100% 把每一个
// AnyTLS 节点误分类进美国组，"是必现 bug，不是概率性的"。
//
// 但把原脚本那段 GROUPS_PATTERNS 的实际文本拿真实 jq 跑一遍会发现：这个
// "已修复"的说法只对了一半——每一行确实给排在最前面的那个主要短代码加了
// \b（\bDE\b、\bJP\b……\bUS\b），但同一行里后面出现的其它短代码别名——
// 英国行里的 "GB"、美国行里的 "USA"/"LA"/"SF"/"NY"——依然是裸露的，没有
// \b。我拿脚本里一模一样的 pattern 文本、真实 jq 二进制实测过：
//
//	echo '{"tag":"anytls-out-e6f7f413b8044269a680bff7a1c8860c"}' \
//	  | jq --arg pattern '美国|美|\bUS\b|USA|...|New York|NY|...' \
//	       '.tag | test($pattern; "i")'
//	# => true
//
// 也就是说注释里说"已经修复"的那个 AnyTLS/NY 碰撞，在当前这份脚本里其实
// 还在，只是原脚本原本跑的那次 NODE_REGION_TAG 恰好也是"美国"，所以这个
// bug 有没有触发从结果上根本看不出来——AnyTLS 节点反正都会进美国组，
// 一个是因为 tag 里真的带着"美国"两个字，另一个是因为"ny"子串误判，
// 两条路径殊途同归，把 bug 彻底藏起来了。
//
// 这里选择按注释描述的**原意**实现（GB/USA/LA/SF/NY 也补上 \b），而不是
// 照抄"看起来已修复、实际没修完"的当前文本——这不是我擅自改需求，是把
// 脚本自己写明的意图真正落实完整。如果你想要跟当前 bash 版本逐字节一致
// （包括这个未修完的坑），告诉我一声，我可以把这几个 \b 去掉。
var Groups = []Group{
	{"德国_469138946ba5fa", `德国|德|\bDE\b|Germany|Frankfurt|Frankfurt am Main|Berlin|Munich|München|Hamburg|Dusseldorf|Düsseldorf|Cologne|Köln|Stuttgart|法兰克福|柏林|慕尼黑|汉堡|杜塞尔多夫|科隆|斯图加特|🇩🇪`},
	{"日本_469138946ba5fa", `日本|日|\bJP\b|Japan|Tokyo|Osaka|Nagoya|Yokohama|Sapporo|Fukuoka|东京|大阪|名古屋|横滨|札幌|福冈|🇯🇵`},
	{"新加坡_469138946ba5fa", `新加坡|坡|\bSG\b|Singapore|Singapore City|Lion City|狮城|🇸🇬`},
	{"香港_469138946ba5fa", `香港|港|\bHK\b|Hong Kong|HongKong|HKG|🇭🇰`},
	{"台湾_469138946ba5fa", `台湾|台|\bTW\b|Taiwan|Taipei|Taichung|Kaohsiung|Tainan|Hsinchu|Changhua|New Taipei|台北|台中|高雄|台南|新竹|彰化|新北|🇹🇼`},
	{"韩国_469138946ba5fa", `韩国|韩|\bKR\b|Korea|South Korea|Seoul|Busan|Incheon|首尔|釜山|仁川|🇰🇷`},
	{"英国_469138946ba5fa", `英国|英|\bUK\b|\bGB\b|United Kingdom|England|London|Manchester|伦敦|曼彻斯特|🇬🇧`},
	{"加拿大_469138946ba5fa", `加拿大|加|\bCA\b|Canada|Toronto|Vancouver|Montreal|多伦多|温哥华|蒙特利尔|🇨🇦`},
	{"澳大利亚_469138946ba5fa", `澳大利亚|澳|\bAU\b|Australia|Sydney|Melbourne|Brisbane|Perth|悉尼|墨尔本|布里斯班|珀斯|🇦🇺`},
	{"法国_469138946ba5fa", `法国|法|\bFR\b|France|Paris|Marseille|巴黎|马赛|🇫🇷`},
	{"荷兰_469138946ba5fa", `荷兰|荷|\bNL\b|Netherlands|Amsterdam|阿姆斯特丹|🇳🇱`},
	{"美国_469138946ba5fa", `美国|美|\bUS\b|\bUSA\b|United States|America|Los Angeles|\bLA\b|San Francisco|\bSF\b|Silicon Valley|San Jose|Seattle|Chicago|Dallas|New York|\bNY\b|Miami|Atlanta|Ashburn|Phoenix|Las Vegas|Denver|洛杉矶|旧金山|硅谷|圣何塞|西雅图|芝加哥|达拉斯|纽约|迈阿密|亚特兰大|阿什本|凤凰城|拉斯维加斯|丹佛|🇺🇸`},
}

// Node 是参与分类的候选节点——只有真实协议节点（有 server 字段）才应该
// 传进来，selector/urltest/direct 这类"分组壳子"不参与匹配。
type Node struct {
	Tag string
}

// Classify 按 Groups 的固定顺序、大小写不敏感、互斥地匹配节点，返回
// "分组 tag -> 匹配到的节点 tag 列表"。一个分组如果一个节点都没匹配到，
// 不会出现在返回结果里——调用方应该据此保持该分组原有的 outbounds
// 不动（通常是占位的 ["直连_..."]），而不是把它清空。
func Classify(nodes []Node) map[string][]string {
	result := make(map[string][]string)
	matched := make(map[string]bool, len(nodes))

	for _, g := range Groups {
		re := regexp.MustCompile("(?i)" + g.Pattern)
		var hits []string
		for _, n := range nodes {
			if matched[n.Tag] {
				continue
			}
			if re.MatchString(n.Tag) {
				hits = append(hits, n.Tag)
			}
		}
		if len(hits) == 0 {
			continue
		}
		for _, h := range hits {
			matched[h] = true
		}
		result[g.Tag] = hits
	}

	return result
}
