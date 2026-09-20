package fetch

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DownloadFile 对应原脚本反复出现的
// `curl -L -C - --retry 3 --retry-delay 5 --progress-bar -o dest url`。
// 失败自动重试 3 次，每次间隔 5 秒，跟原脚本参数一致；没有实现
// `-C -`（断点续传）——这个留到真正需要断点续传的场景（比如大文件在
// 不稳定网络下反复失败）再加，目前 sing-box/cloudflared 单个二进制体积
// 不大，重试三次通常比"续传逻辑写错导致文件损坏"更划算。
func DownloadFile(ctx context.Context, url, destPath string) error {
	const maxRetries = 3
	const retryDelay = 5 * time.Second

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryDelay):
			}
		}
		if err := downloadOnce(ctx, url, destPath); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("下载 %s 失败（重试 %d 次后放弃）: %w", url, maxRetries, lastErr)
}

func downloadOnce(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	tmp := destPath + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, destPath)
}

// ExtractTarGz 对应原脚本的 `tar zxvf`，用标准库原生实现，不依赖系统
// tar 命令（在极简的容器/裸机镜像上，tar 不一定预装；Go 标准库这两个包
// 随二进制一起编译进去，运行时不需要任何外部程序）。
func ExtractTarGz(src io.Reader, destDir string) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("打开 gzip 流失败: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("读取 tar 条目失败: %w", err)
		}

		// 防御 tar 里的路径穿越（"zip slip" 的 tar 版本）：解压目标必须
		// 落在 destDir 内部，不能靠 ../ 跳出去。
		target := filepath.Join(destDir, hdr.Name)
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) && target != filepath.Clean(destDir) {
			return fmt.Errorf("tar 条目路径不安全: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		}
	}
}
