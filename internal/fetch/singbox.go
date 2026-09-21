package fetch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SingBoxParams 对应原脚本控制 sing-box 下载行为的两个环境变量。
type SingBoxParams struct {
	Channel string // "stable" 或 "testing"（默认），对应 SING_BOX_CHANNEL
	Version string // 非空时跳过版本探测，直接用这个（对应 SING_BOX_VERSION）
}

// SingBoxResult 是下载完成后的产物信息。
type SingBoxResult struct {
	Version    string // 例如 "v1.14.0"
	BinaryPath string // {WorkDir}/sing-boxs/sing-box
}

// FetchSingBox 对应原脚本 downloadAndBuild("SagerNet/sing-box") 那一整段：
// 探测版本 → 按平台拼下载 URL → 下载 tar.gz → 解压 → 把解压出来的目录
// 改名成 "sing-boxs"（原脚本的命名，复数形式，目的是跟二进制文件本身的
// 名字 "sing-box" 区分开，避免目录和可执行文件同名导致的各种路径歧义）
// → chmod +x → 把版本号写进 sing-box.version。
func FetchSingBox(ctx context.Context, workDir string, params SingBoxParams) (*SingBoxResult, error) {
	platform, err := DetectPlatform()
	if err != nil {
		return nil, err
	}

	version, err := SingBoxVersion(ctx, params.Channel, params.Version)
	if err != nil {
		return nil, err
	}

	vNum := strings.TrimPrefix(version, "v")
	url := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/%s/sing-box-%s-%s-%s.tar.gz",
		version, vNum, platform.OS, platform.Arch)

	tarPath := filepath.Join(workDir, "sing-box.tar.gz")
	if err := DownloadFile(ctx, url, tarPath); err != nil {
		return nil, err
	}
	defer os.Remove(tarPath)

	f, err := os.Open(tarPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := ExtractTarGz(f, workDir); err != nil {
		return nil, fmt.Errorf("解压 %s 失败: %w", tarPath, err)
	}

	extractedDir := filepath.Join(workDir, fmt.Sprintf("sing-box-%s-%s-%s", vNum, platform.OS, platform.Arch))
	finalDir := filepath.Join(workDir, "sing-boxs")
	if err := os.RemoveAll(finalDir); err != nil {
		return nil, err
	}
	if err := os.Rename(extractedDir, finalDir); err != nil {
		return nil, fmt.Errorf("重命名 %s -> %s 失败: %w", extractedDir, finalDir, err)
	}

	binaryPath := filepath.Join(finalDir, "sing-box")
	if err := os.Chmod(binaryPath, 0o755); err != nil {
		return nil, err
	}

	if err := os.WriteFile(filepath.Join(workDir, "sing-box.version"), []byte(version+"\n"), 0o644); err != nil {
		return nil, err
	}

	return &SingBoxResult{Version: version, BinaryPath: binaryPath}, nil
}
