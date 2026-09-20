package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"singboxprovision/internal/fetch"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	platform, err := fetch.DetectPlatform()
	must(err)
	fmt.Printf("平台: %+v\n", platform)

	tag, err := fetch.LatestReleaseTag(ctx, "cloudflare", "cloudflared")
	must(err)
	fmt.Println("cloudflared 最新 tag:", tag)

	stableVersion, err := fetch.SingBoxVersion(ctx, "stable", "")
	must(err)
	fmt.Println("sing-box stable 版本（走 /releases/latest 跳转）:", stableVersion)

	testingVersion, err := fetch.SingBoxVersion(ctx, "testing", "")
	must(err)
	fmt.Println("sing-box testing 版本（走 releases.atom，可能是预发布）:", testingVersion)

	version := stableVersion

	workDir := "/tmp/fetch-verify"
	os.RemoveAll(workDir)
	must(os.MkdirAll(workDir, 0o755))

	sb, err := fetch.FetchSingBox(ctx, workDir, fetch.SingBoxParams{Version: version})
	must(err)
	fmt.Printf("下载完成: version=%s path=%s\n", sb.Version, sb.BinaryPath)

	out, err := exec.CommandContext(ctx, sb.BinaryPath, "version").CombinedOutput()
	must(err)
	fmt.Println("--- sing-box version 输出 ---")
	fmt.Println(string(out))

	cfPath, err := fetch.FetchCloudflared(ctx, workDir)
	must(err)
	fmt.Println("cloudflared 下载完成:", cfPath)
	out2, err := exec.CommandContext(ctx, cfPath, "--version").CombinedOutput()
	must(err)
	fmt.Println("--- cloudflared --version 输出 ---")
	fmt.Println(string(out2))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
