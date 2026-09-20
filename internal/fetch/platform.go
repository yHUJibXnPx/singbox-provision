// Package fetch 对应原脚本的 downloadAndBuild() / downloadFile() /
// fetchPageContent()：从 GitHub Releases 拉 sing-box / cloudflared 二进制。
//
// 不下载 jq 了——原脚本下载 jq 纯粹是为了后面能用它解析 GitHub API 返回的
// JSON、以及给三份客户端配置做节点分类，这两件事在 Go 版里分别是标准库
// encoding/json 和 internal/classify 包原生做的，jq 这个外部依赖直接消失，
// 连"先有鸡还是先有蛋"那个问题（要下载 jq，但下载稳定版 jq 又不能依赖
// jq 去解析 GitHub API）也一并不存在了。
package fetch

import (
	"fmt"
	"runtime"
)

// Platform 对应原脚本 downloadAndBuild() 里 uname -s / uname -m 那段解析。
// Go 标准库的 runtime.GOOS / runtime.GOARCH 就是这两个值的原生等价物，
// 不需要再 shell out 到 uname 命令、也不需要处理它的输出格式。
type Platform struct {
	OS   string // "linux" / "darwin"
	Arch string // "amd64" / "arm64"
}

// DetectPlatform 对应原脚本对 ARCH_NAME 的 case 分支
// （aarch64/arm64 → arm64，x86_64/amd64 → amd64，其它架构直接报错退出）。
// Go 的 runtime.GOARCH 已经是 "amd64"/"arm64" 这种规范名字，不会出现
// "aarch64" 这种需要归一化的别名，所以这里的判断比原脚本简单。
func DetectPlatform() (Platform, error) {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		// ok
	default:
		return Platform{}, fmt.Errorf("没有可以支持的架构: %s", runtime.GOARCH)
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return Platform{}, fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
	return Platform{OS: runtime.GOOS, Arch: runtime.GOARCH}, nil
}
