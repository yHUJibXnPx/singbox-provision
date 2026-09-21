package fetch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// FetchCloudflared 对应原脚本 downloadAndBuild("cloudflare/cloudflared")
// 里 case cloudflared 那一段：linux 下直接是个裸二进制，darwin 下是个
// .tgz 压缩包需要解压。版本号走 LatestReleaseTag（页面 302 重定向技巧），
// 不走 GitHub API——这跟原脚本的选择一致，注释里写的原因是"继续使用
// release 页面提取稳定 tag，避免安装 jq 时形成循环依赖"；Go 版虽然已经
// 不需要 jq 了，但这里保留同一条路径没有改成走 API，是因为 cloudflared
// 的 release 里没有 sing-box 那种 stable/testing 两条 channel 的区分
// 需求，重定向技巧已经够用，没必要多发一次 API 请求。
func FetchCloudflared(ctx context.Context, workDir string) (binaryPath string, err error) {
	platform, err := DetectPlatform()
	if err != nil {
		return "", err
	}

	version, err := LatestReleaseTag(ctx, "cloudflare", "cloudflared")
	if err != nil {
		return "", err
	}

	dest := filepath.Join(workDir, "cloudflared")

	switch platform.OS {
	case "linux":
		url := fmt.Sprintf("https://github.com/cloudflare/cloudflared/releases/download/%s/cloudflared-%s-%s",
			version, platform.OS, platform.Arch)
		if err := DownloadFile(ctx, url, dest); err != nil {
			return "", err
		}
	case "darwin":
		url := fmt.Sprintf("https://github.com/cloudflare/cloudflared/releases/download/%s/cloudflared-%s-%s.tgz",
			version, platform.OS, platform.Arch)
		tgzPath := dest + ".tgz"
		if err := DownloadFile(ctx, url, tgzPath); err != nil {
			return "", err
		}
		defer os.Remove(tgzPath)
		f, err := os.Open(tgzPath)
		if err != nil {
			return "", err
		}
		defer f.Close()
		if err := ExtractTarGz(f, workDir); err != nil {
			return "", fmt.Errorf("解压 %s 失败: %w", tgzPath, err)
		}
	default:
		return "", fmt.Errorf("不支持的平台: %s", platform.OS)
	}

	if err := os.Chmod(dest, 0o755); err != nil {
		return "", err
	}
	return dest, nil
}
