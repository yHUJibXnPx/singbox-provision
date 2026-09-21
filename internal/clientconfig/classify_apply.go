package clientconfig

import "singboxprovision/internal/classify"

// ApplyClassification 对应原脚本 2146~2226 行：从已经生成好的配置里挑出
// 真实协议节点（Server 字段非空的），按地区分类，然后把匹配结果写回对应
// 分组的 outbounds 字段——分组已存在就更新，不存在就新建一个 selector
// （原脚本对应"分组不存在，创建新 selector" / "分组已存在，更新节点列表"
// 两个分支）。一个分组如果没匹配到任何节点，保持原样不动。
//
// 传入哪份 *Config 就地修改哪份，用于 gen_client() 生成完三份文件之后
// 各跑一次（跟原脚本对三份文件各跑一次这段后处理是同一个顺序）。
func ApplyClassification(cfg *Config) {
	var nodes []classify.Node
	for _, ob := range cfg.Outbounds {
		if ob.Server != "" {
			nodes = append(nodes, classify.Node{Tag: ob.Tag})
		}
	}

	groups := classify.Classify(nodes)

	// 按 classify.Groups 的固定顺序处理（而不是遍历 map，map 的遍历顺序是
	// 随机的）——这样如果真的走到"分组不存在、要新建"这个分支，新建出来的
	// 顺序也是确定的，不会每次生成都不一样。
	for _, g := range classify.Groups {
		matched, ok := groups[g.Tag]
		if !ok {
			continue
		}
		idx := -1
		for i, ob := range cfg.Outbounds {
			if ob.Tag == g.Tag {
				idx = i
				break
			}
		}
		if idx == -1 {
			cfg.Outbounds = append(cfg.Outbounds, Outbound{Type: "selector", Tag: g.Tag, Outbounds: matched})
			continue
		}
		if cfg.Outbounds[idx].Type == "selector" || cfg.Outbounds[idx].Type == "urltest" {
			cfg.Outbounds[idx].Outbounds = matched
		}
	}
}
