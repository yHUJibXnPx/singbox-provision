package fetch

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"
)

// LatestReleaseTag 对应原脚本这一行：
//
//	curl -sIL -o /dev/null -w "%{url_effective}" \
//	  "https://github.com/${URI}/releases/latest" | awk -F'/' '{print $NF}'
//
// 用一个会跟着 302 走的 HTTP 客户端请求 /releases/latest，GitHub 会重定向
// 到 /releases/tag/vX.Y.Z，取重定向落地后的 URL 最后一段就是版本号。
// GitHub 对 "latest" 的官方定义就是"排除 prerelease 和 draft 的最新版"，
// 不需要额外过滤逻辑，也不占用 GitHub REST API 那 60次/小时的未认证额度
// ——这是 cloudflared 版本探测、以及下面 sing-box "stable" 频道共用的
// 同一个函数。
func LatestReleaseTag(ctx context.Context, owner, repo string) (string, error) {
	url := fmt.Sprintf("https://github.com/%s/%s/releases/latest", owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求 %s 失败: %w", url, err)
	}
	defer resp.Body.Close()

	final := resp.Request.URL.Path // 例如 /SagerNet/sing-box/releases/tag/v1.14.0
	tag := lastPathSegment(final)
	if tag == "" || tag == "latest" {
		return "", fmt.Errorf("无法从 %s 解析出版本号（最终落地 %s）", url, final)
	}
	return tag, nil
}

func lastPathSegment(p string) string {
	i := len(p) - 1
	for i >= 0 && p[i] == '/' {
		i--
	}
	end := i + 1
	for i >= 0 && p[i] != '/' {
		i--
	}
	return p[i+1 : end]
}

// atomFeed / atomEntry 只解析用得到的两个字段，Atom 里其余内容
// （发布说明正文、作者头像等）原样忽略。
type atomFeed struct {
	Entries []atomEntry `xml:"entry"`
}

type atomEntry struct {
	ID string `xml:"id"` // 形如 "tag:github.com,2008:Repository/509091576/v1.15.0-alpha.3"
}

// AtomLatestTag 对应"想要拿到包含预发布版本在内的最新一个 release"这个
// 需求，但不通过会被限流的 GitHub REST API，而是读取 GitHub 给每个仓库
// 自动提供的 releases.atom 订阅源——这是结构化 XML，不是要拿正则去啃
// 会随时因为页面改版而碎掉的原始 HTML；GitHub 维护这个订阅源接口已经
// 十几年了，比页面 DOM 结构稳定得多。订阅源只收录**已发布**的
// release/prerelease，draft 从定义上就不会出现在里面，所以第一条天然
// 就是"最新的已发布版本，不管是不是预发布"。
func AtomLatestTag(ctx context.Context, owner, repo string) (string, error) {
	url := fmt.Sprintf("https://github.com/%s/%s/releases.atom", owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求 %s 失败: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("请求 %s 返回状态码 %d", url, resp.StatusCode)
	}

	var feed atomFeed
	if err := xml.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return "", fmt.Errorf("解析 %s 的 Atom 内容失败: %w", url, err)
	}
	if len(feed.Entries) == 0 {
		return "", fmt.Errorf("%s 里没有任何 release 条目", url)
	}
	return parseAtomEntryTag(feed.Entries[0].ID)
}

// parseAtomEntryTag 从 "tag:github.com,2008:Repository/509091576/v1.15.0-alpha.3"
// 这种 Atom entry id 里取出最后一段（真正的 git tag 名）。单独拆出来是
// 为了能用固定字符串做单元测试，不需要每次都真的请求 GitHub。
func parseAtomEntryTag(entryID string) (string, error) {
	tag := lastPathSegment(entryID)
	if tag == "" {
		return "", fmt.Errorf("无法从 entry id 解析出 tag: %q", entryID)
	}
	return tag, nil
}

// SingBoxVersion 对应原脚本 downloadAndBuild() 给 sing-box 挑版本号那段：
//
//	channel=stable  → 排除 draft 和 prerelease，取最新一个（= LatestReleaseTag）
//	channel=testing（默认） → 只排除 draft，prerelease 也算数（= AtomLatestTag）
//
// 跟原脚本的差别是原脚本这里走的是 GitHub REST API + jq 过滤，这里换成了
// 两个都不碰 REST API 限额的路径——这是这一轮改的地方，具体原因看
// README。explicitVersion 非空时直接原样返回（对应 SING_BOX_VERSION
// 环境变量），不发任何请求。
func SingBoxVersion(ctx context.Context, channel, explicitVersion string) (string, error) {
	if explicitVersion != "" {
		return explicitVersion, nil
	}
	if channel == "stable" {
		return LatestReleaseTag(ctx, "SagerNet", "sing-box")
	}
	return AtomLatestTag(ctx, "SagerNet", "sing-box")
}
