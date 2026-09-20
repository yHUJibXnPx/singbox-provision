package fetch

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLastPathSegment(t *testing.T) {
	cases := map[string]string{
		"/SagerNet/sing-box/releases/tag/v1.14.0":       "v1.14.0",
		"/cloudflare/cloudflared/releases/tag/2026.9.1": "2026.9.1",
		"/a/b/c/": "c",
		"":        "",
	}
	for in, want := range cases {
		if got := lastPathSegment(in); got != want {
			t.Fatalf("lastPathSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseAtomEntryTag(t *testing.T) {
	got, err := parseAtomEntryTag("tag:github.com,2008:Repository/509091576/v1.15.0-alpha.3")
	if err != nil {
		t.Fatal(err)
	}
	if got != "v1.15.0-alpha.3" {
		t.Fatalf("应该解析出 v1.15.0-alpha.3，实际 %q", got)
	}
}

func TestParseAtomEntryTag_Empty(t *testing.T) {
	if _, err := parseAtomEntryTag(""); err == nil {
		t.Fatal("空 entry id 应该报错，不该返回空版本号")
	}
}

// TestLatestReleaseTag_FollowsRedirect 不打真实的 GitHub，用本地 httptest
// 服务器模拟"/releases/latest 302 到 /releases/tag/vX.Y.Z"这个跳转，验证
// 跟随重定向 + 从最终 URL 解析版本号这个行为本身。真正对 GitHub 的
// 端到端验证见 cmd/verifyfetch（会发真实网络请求，不适合放进 go test）。
func TestLatestReleaseTag_FollowsRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/owner/repo/releases/latest" {
			http.Redirect(w, r, "/owner/repo/releases/tag/v9.9.9", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodHead, srv.URL+"/owner/repo/releases/latest", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got := lastPathSegment(resp.Request.URL.Path)
	if got != "v9.9.9" {
		t.Fatalf("跟随重定向后应该解析出 v9.9.9，实际 %q", got)
	}
}

// TestAtomLatestTag_ParsesFeedXML 用本地 httptest 服务器返回一份跟真实
// releases.atom 结构一致的固定 XML，验证 AtomLatestTag 从第一条 entry
// 里正确取出 tag，且不需要真的请求 github.com。
func TestAtomLatestTag_ParsesFeedXML(t *testing.T) {
	const sampleAtom = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>tag:github.com,2008:Repository/509091576/v1.15.0-alpha.3</id>
    <title>1.15.0-alpha.3</title>
  </entry>
  <entry>
    <id>tag:github.com,2008:Repository/509091576/v1.14.0</id>
    <title>1.14.0</title>
  </entry>
</feed>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/atom+xml")
		_, _ = w.Write([]byte(sampleAtom))
	}))
	defer srv.Close()

	// AtomLatestTag 内部拼的是 https://github.com/... 固定域名，测试直接
	// 复用它的 HTTP 解析逻辑（请求 + xml.Decode）而不是重新拼一遍 URL。
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var feed atomFeed
	if err := xml.NewDecoder(resp.Body).Decode(&feed); err != nil {
		t.Fatal(err)
	}
	if len(feed.Entries) != 2 {
		t.Fatalf("应该解析出 2 条 entry，实际 %d", len(feed.Entries))
	}
	got, err := parseAtomEntryTag(feed.Entries[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != "v1.15.0-alpha.3" {
		t.Fatalf("第一条 entry 应该是 v1.15.0-alpha.3（预发布也算数），实际 %q", got)
	}
}
