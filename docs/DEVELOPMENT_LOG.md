# singbox-provision（Go 重构，进行中）

对应原来的 `make_sing-box_server_ubuntu.sh`（~2250 行 bash）。这是第一阶段的
成果，只覆盖了"服务端 config.json 生成"这一块——也是原脚本里最脆弱、最该
优先解决的部分（heredoc 字符串拼接 JSON）。**不是完整替代品，还不能拿去直接
部署**，往下看"目前覆盖了什么 / 还没做什么"。

## 已经验证过什么，怎么验证的

不是"看起来对"，是实际跑出来核对过：

1. `go test ./...` — `randgen` 包的单元测试，覆盖 UUID / 密码 / short-id /
   Reality 密钥对 / padding scheme 的格式和边界条件。
2. **拿你上传的真实 `config.json`** 作为 golden 文件，把里面的参数（域名、
   端口、UUID、密钥、padding_scheme 等）抠出来喂给 Go 版的
   `BuildServerConfig`，生成的 JSON 跟你那份原始文件做了**逐字段结构化 diff**
   （不是文本 diff，是解析成对象后递归比较每一个 key/value）：结果是
   **0 处差异**。
3. 下载了官方 `sing-box v1.14.0` 二进制，对原版和 Go 生成版**各自跑了一次
   `sing-box check`**，两个都 PASS——不只是"合法 JSON"，是 sing-box 自己的
   schema 校验器认可的合法配置。
4. Reality 密钥对格式（32 字节、base64 URL 无 padding）是用真实
   `sing-box generate reality-keypair` 的输出核对过字符长度和字符集之后
   确认的，不是凭印象猜的。

## 顺手发现的一处死代码

`internal/randgen/randgen.go` 的注释里写了：原脚本在算 anytls 的
padding_scheme 时，有一段完整的 `R0_MIN/R0_MAX/R1_MIN/R1_MAX/R2_BASE/R2_MAX/
R_HIGH` 计算，算完之后从未被用到，全部被后面同名变量的第二次赋值覆盖；另外
还多算了一个 `PAD_12`，但拼最终数组时只取了前 12 个（`PAD_0..PAD_11`），
`PAD_12` 也是从未用上。用你的真实 `config.json` 核对过：生效的 padding_scheme
确实正好是 12 条、到 `"10=..."` 为止。这两处死代码在 Go 版里直接删掉了。

## 目前覆盖了什么

- `internal/randgen`：UUID、十六进制密码、short-id（单个/成组）、Reality
  X25519 密钥对、anytls padding_scheme。全部标准库实现，不需要 openssl 或
  sing-box 二进制。
- `internal/certgen`：自签名证书（RSA 2048，10 年有效期，SAN=DNS:域名），
  同样原生实现，替代原脚本里的 `openssl req -x509 ...`。
- `internal/sbconfig`：8 种入站协议的服务端 `config.json` 结构体定义 + 构建
  函数（`BuildServerConfig`），用真正的 Go struct + `json.Marshal` 替代原脚本
  的 heredoc 字符串拼接。
- `internal/netprobe`：119 个候选域名的并发延迟探测 + 按延迟顺序做 TLS1.3/
  证书大小验证、短路返回第一个合格域名。用注入 `LatencyProber`/`TLS13Prober`
  的假实现做了单元测试（覆盖"该选谁""证书过大要跳过""连不上要跳过""全部
  不合格""候选顺序不影响结果"这几种场景），这部分不受下面这条影响，仍然
  可信。

  **需要更正一处我之前的表述**：早前我说"真实探测器拿 github.com 单独
  跑通过了"，暗示这证明了探测代码能正确区分"域名真的可达"和"不可达"。
  跑通整个 `cmd/provision` 之后发现这个说法不够准确——这个沙盒的出站
  网络有一层透明的 TLS 终结网关：**任何**域名的 TLS 握手本身都会被这层
  网关接住并正常完成（证书签发者是网关自己的 CA，被系统信任），域名白
  名单实际上是握手完成之后、发出 HTTP 请求那一刻才生效的。`DefaultLatencyProber`/
  `DefaultTLS13Prober` 都只做 TLS 握手、握手完就关连接，根本没走到发
  HTTP 请求那一步——这意味着在这个沙盒里，探测器对**任何**能解析出 DNS
  的域名都会报告"成功"，不只是 github.com。实测让 `cmd/provision` 真的跑
  一遍，探测器确实"选中"了候选名单里的 `www.google-analytics.com`，
  但这不能说明探测逻辑验证过了"选出的域名在真实网络条件下确实可达"——
  这个沙盒的网络环境本身就不具备验证这件事的条件。选择逻辑（该选哪个、
  怎么排序、怎么短路）是真的测过的，没问题；"某个具体域名在真实互联网上
  是否可达"这件事，只有在你的真实 VPS 上跑才能验证，这个之前就说过，
  现在只是把"为什么连 github.com 都不能说明什么"这一层解释补全。
- `internal/portcheck`：端口占用检测（真实 bind 测试）+ 空闲随机端口分配 +
  完整的"混合固定/随机"端口分配策略（对应原脚本 861~910 行，包括
  Hysteria2/VLESS、TUIC/VmessWSTLS 两组 TCP/UDP 共用端口数字的设计）。这几个
  在沙盒里就是真实网络操作，不是 mock，单元测试是真的绑定/释放端口来验证的，
  包括"443 被占用时是否正确 fallback"这一条——沙盒里跑测试的用户正好是
  root，能真的绑 443，这条分支也被真实跑到了，不是靠 skip 蒙混过去的。

- `internal/clientconfig`：三份客户端配置（`client.json` / OpenWrt /
  `client_1.11.4.json`）的完整生成逻辑，包括 7 个共享协议出站、AnyTLS
  出站、CF（cloudflared 隧道）系列出站节点、12 个地区占位 urltest 分组、
  三个变体各自专属的 DNS/Inbounds/路由尾/Experimental schema。跟你上传的
  三份真实文件做了同样的逐字段递归 diff：**client.json 和 OpenWrt 版结构
  完全一致（0 处不可解释的差异）**；`client_1.11.4.json` 用新版 sing-box
  校验器（v1.14.0）会报错，但**用同一个校验器去校验你上传的原始
  client_1.11.4.json 也是一样的报错**——这是 1.11.4 时代的旧版 DNS schema
  在新版 sing-box 里被移除了，跟这次移植没有关系，不是我引入的问题。

  验证过程中这一步顺手抓出了 3 个真 bug（不是原脚本的锅，是我第一版
  Go 代码写错的地方，被结构化 diff 揪出来了）：
  1. 12 个地区分组在"定义时的顺序"和"被"代理"/"智能"两个 selector 引用时
     的顺序"其实不一样（德国在两处的位置不同）——这是**原脚本自己就有**的
     不一致（两处硬编码列表分开维护，没同步过），照抄一份会产生错误结果，
     两份顺序都原样保留、分别用了两个常量。
  2. CF 隧道节点的 tag 忘了加地区标记前缀。
  3. CF 节点的 WebSocket Host 头错填成了 Reality 用的域名，而不是 CF 隧道
     自己的域名——这一个如果没抓出来，会导致所有 CF 节点实际连不上。

  另外还发现一处**目前只记录、暂不处理**的原脚本行为：CF_NODES 表里 8 个
  "字面 Cloudflare IP" 的条目不依赖任何变量，就算从没配置过 cloudflared
  隧道也会生成（只是没有隧道域名时这些节点的 TLS server_name 是空的，实际
  连不通）。要不要在 `cmd/provision` 里加一层"完全没配置隧道就不生成这些
  节点"的判断，等做进程管理那部分、真正搞清楚隧道到底有没有配置时再决定。

  **还没做的**：脚本末尾那段"自动分类"后处理（`GROUPS_PATTERNS`，按 tag
  内容用 12 组正则把真实协议节点匹配进对应地区 selector，见下方"还没做的"
  第 1 项）——这是三份 diff 里唯一剩下的差异来源，其余全部一致。

- `internal/classify`：脚本末尾"节点自动分类"后处理（对应原脚本
  `GROUPS_PATTERNS`），按 12 组正则把真实协议节点分进对应地区 selector。
  用真实数据验证：加上这一步之后，三份客户端配置**全部跟你上传的原始
  文件逐字段递归 diff 完全一致，0 处差异**（之前唯一剩下的差异来源）。

  这一步验证时有一个比之前几个更有意思的发现，值得展开说：原脚本在
  这段正则前面写了一大段注释，说"已经修复"了两个实测踩过的坑——一个是
  32 位随机 UUID 偶然带出 "de"/"ca" 子串误判进德国/加拿大，另一个是
  AnyTLS 固定 tag 前缀 "anytls-out-" 自带 "ny"、会把每个 AnyTLS 节点都
  错误分类进美国组。但我拿脚本里那段正则的**原文**、用真实 jq 二进制实测
  发现：只有每行排在最前面的那一个短代码真的加了 `\b` 词边界（`\bDE\b`、
  `\bUS\b` 这些），同一行后面出现的其它短代码别名——英国那行的 "GB"、
  美国那行的 "USA"/"LA"/"SF"/"NY"——依然是裸露的，没有 `\b`。也就是说
  注释里说"已修复"的 AnyTLS/NY 那个坑，其实还在，只是原脚本那次运行
  `NODE_REGION_TAG` 恰好也是"美国"，AnyTLS 节点不管走哪条路径（真的带
  "美国"两个字，还是被"ny"子串误判）结果都一样进了美国组，把这个未修完
  的坑彻底藏起来了，从生成结果上根本看不出来。

  Go 版按注释描述的**原意**补完了这几个 `\b`（`classify.go` 里详细记了
  这个发现和实测过程），不是照抄"看起来修好、实际没修完"的当前文本。
  用你的真实数据验证过这个改动不影响现有结果（因为这次运行里地区标记
  本来就是"美国"，两条判断路径殊途同归），但如果哪天用空的
  `NODE_REGION_TAG` 或者别的地区标记生成节点，这几个 `\b` 就会真的影响
  行为——如果你想要跟当前 bash 版本逐字节一致（包括这个未修完的坑），
  告诉我一声就可以去掉。

- `internal/links`：全部节点分享链接（vless/trojan/anytls/hysteria2/tuic
  明文 URI + vmess base64 JSON + vless-ws，含 CF 节点链接）+ 订阅文件
  拼合。用真实 golden 数据反推参数、生成、**跟原始 `subscription.txt` /
  `subscription_base64.txt` 做字节级 diff（不是结构化 diff，是完全的
  文本比对）：全部一致**，包括容易出错的两处细节：vmess 链接的 JSON
  字段顺序会直接影响 base64 结果（所以没有用一个大结构体 + omitempty
  去覆盖所有分支，而是按实际会用到的两种形态各自定义了字段顺序完全固定
  的小结构体）；以及 `subscription.txt`/`SUBSCRIPTION_BASE64` 之间那处
  容易漏掉的换行数量差异（base64 编码的是"链接 + 一个换行"，写进
  `.txt` 文件时又会多加一个换行，两者差一行）。

- `internal/fetch`：从 GitHub Releases 下载 sing-box / cloudflared，对应
  原脚本的 `downloadAndBuild()`/`downloadFile()`/`fetchPageContent()`。
  **这一块不需要再下载 jq 了**——原脚本装 jq 纯粹是为了后面解析 GitHub
  API 的 JSON 响应、以及给客户端配置做节点分类，这两件事 Go 版分别用标准库
  `encoding/json` 和 `internal/classify` 原生做了，jq 这个外部依赖、以及
  原脚本注释里提到的"先装 jq 还是先用 jq 解析 API 判断该装哪个 jq"这个
  先有鸡还是先有蛋的问题，都一并不存在了。同理，`tar zxvf` 换成标准库
  `archive/tar`+`compress/gzip` 原生解压，不需要系统装 tar；架构检测直接用
  Go 的 `runtime.GOARCH`，不需要 shell out 到 `uname -m` 再解析输出。

  版本探测**不走 GitHub REST API**（原脚本给 sing-box 走的是这条，会撞
  60次/小时的未认证限额）：stable 频道复用 `/releases/latest` 的 302
  跳转（cloudflared 本来就走这条，GitHub 对"latest"的定义就是"排除
  prerelease 和 draft 的最新版"，不需要自己再过滤）；testing 频道改成
  读取 `releases.atom`——结构化 XML 订阅源，不是拿正则去啃随时可能因为
  页面改版而碎掉的原始 HTML，GitHub 维护这个接口十几年了，比页面 DOM
  稳定得多，而且它只收录**已发布**的 release/prerelease，draft 从定义上
  就不会出现，第一条天然就是"最新发布版本，不管是不是预发布"。两条路径
  都不占用会被限流的 REST API 额度。

  验证方式是**真实打了 GitHub 网络请求**，不是拿录制数据回放：实际解析
  出了 cloudflared 的最新版本、sing-box 的 stable 版本（走跳转）和
  testing 版本（走 Atom，这次真的拿到了一个预发布版本号，证明确实在读
  预发布），然后真的下载了完整的 sing-box tar.gz、用标准库解压、重命名、
  chmod，执行了一次 `sing-box version` 拿到正确输出；cloudflared 同理。
  `cmd/verifyfetch` 保留了下来，不是最终交付物，是一个会发真实网络请求、
  真的下载几十 MB 二进制的手动验证工具——网络不受限的机器上想再核实一遍
  随时能跑。

- `internal/procmgr`：启动/停止 sing-box 和 cloudflared，对应原脚本
  "nohup+disown+pkill -f" 那一整套。核心差别是 Go 版启动进程时能拿到内核
  分配的真实 PID，后续全部操作（判活、停止）都是对这一个精确 PID 发信号，
  不再需要 `pkill -f "关键词"` 去按命令行文本模糊匹配——原脚本这么做完全
  可以理解（bash 里启动完 nohup 就跟子进程失去直接联系了），但存在"关键词
  恰好还匹配到无关进程"的理论风险，Go 版直接不存在这个问题。

  这一步的单元测试**真的抓出了一个 bug**，不是照抄验证：判活函数一开始
  用"能不能发信号 0"来判断进程死没死，第一版测试跑起来偶发失败——原因是
  Unix 的僵尸进程（子进程退出了但还没人 `wait()` 它）依然会对信号 0 有
  响应，等于"明明已经死了，却因为没人收尸而一直显示活着"。加了一个后台
  goroutine 专门负责 reap 掉自己启动的子进程后，这个问题才消失。这跟原
  bash 脚本没有直接对应关系（bash 的 nohup+disown 之后进程会被重新挂到
  init 下面由 init 收尸，不会有这个问题）——是 Go 版这种"父进程可能活得
  比较久、需要自己管理子进程生命周期"的设计带来的一个新坑，如果不是靠
  真实起停进程的测试，光看代码不会发现。

  最后又做了一次端到端的真实验证（`cmd/verifyprocmgr`）：复制了这个沙盒
  里已经下载验证过的真实 sing-box 二进制，配一份不需要联网就能启动的
  最小配置（用 `cmd/verify` 生成的完整生产配置去测这一步会卡在 sing-box
  自己联网拉取 remote rule-set 那一步，跟 procmgr 要验证的"进程生死管理"
  是两码事，配置内容本身的正确性已经在 `cmd/verify` 里用真实数据验证过
  了），真的执行了一次"check 配置 → 两阶段启动 → 直接拨号确认端口真的在
  监听（不依赖这个沙盒里没装的 ss/netstat）→ 停止 → 确认 PID 不再存活"，
  全部通过。

  还没做的一处设计决定留给你：原脚本对 sing-box 和 cloudflared 都是"先
  启动一次看看日志、杀掉、再正式启动"这种两阶段模式，我原样保留了（注释
  里写清楚了保留的原因——不确定这是不是在规避某个真实部署环境才会暴露的
  启动竞态，贸然砍掉可能引入原脚本从来没遇到过的问题），但如果你知道
  这背后到底是为什么，告诉我，能砍掉这一步的话代码会更直接。

- `internal/sysconfig`：BBR、时间同步、ufw 防火墙规则，对应原脚本
  `enable_bbr()`/`timedatectl`/`open_firewall_ports()`。这几块本质上还是
  在调同一批系统命令，Go 版没有假装能把 sysctl/ufw/timedatectl 也原生
  实现掉——这些事本来就该交给系统自己的工具做。收益在别处：内核版本读取
  `/proc/sys/kernel/osrelease`（内容跟 `uname -r` 完全一致），不用 shell
  out 到 `uname -r` 再解析文本；BBR/防火墙这几步原脚本设计成"无论发生
  什么都不中断安装"，Go 版用一个结果结构体（是否跳过/是否成功/清理了
  哪些旧规则）把这几种状态表达清楚，而不是用一个 error 把"跳过""失败"
  "成功"混在一起。

  **这里有一处真实踩过的坑，记录一下**：最初版本读内核版本用的是
  `syscall.Uname`——这是 Linux 独有的系统调用，`Utsname` 结构体在
  darwin 上根本不存在，导致你在 macOS 上 `go run ./cmd/provision -h`
  哪怕只是想看看参数说明，整个二进制都编译不过去。这不是你的环境有
  问题，是这段代码没考虑到"开发机是 macOS、部署目标是 Linux"这种交叉
  场景。换成读 `/proc/sys/kernel/osrelease` 之后，我用
  `GOOS=darwin GOARCH=arm64/amd64` 和 `GOOS=linux GOARCH=amd64/arm64`
  四种组合都跑了一遍 `go build`（不需要真的有一台 Mac，Go 交叉编译检查
  本身就能验证编译期正确性）确认全部编译通过，包含你那台 Mac mini 用的
  darwin/arm64。

  这一块的测试大多数是**真实调用，不是 mock**——因为这个沙盒本身就具备
  验证条件：内核版本读取是真的系统调用（读到这个沙盒真实的 6.18 内核）；
  BBR 启用是真的执行了 `sysctl -p` 和 `sysctl -n` 命令，写进一个临时
  sysctl.conf 文件，确认返回的拥塞控制算法确实是 `bbr`；时间同步真的调用
  了这个沙盒里存在的 `timedatectl`；防火墙那部分反过来，这个沙盒**确实
  没装 ufw**，正好真实验证了"未安装时打印手动指令"这条分支，不是构造出
  来的假场景。只有"ufw 已激活、需要清理旧规则、放行新规则"这条分支没条件
  实测（沙盒没有 ufw），这部分的纯文本解析逻辑（从 `ufw status numbered`
  的输出里挑出打了"sing-box"标记的规则编号、按从大到小排序）单独拆出来
  用固定文本做了单元测试。

- `internal/report`：`result.txt` 报告生成，纯人类可读的汇总文本，跟
  sing-box 或客户端实际解析什么都没关系。用你的真实数据反推参数、生成、
  跟原始 `result.txt` **字节级 diff：完全一致**。

  这一步验证时抓到一处不起眼但一旦出错就是"看起来对、实际全错位"的格式
  细节：Cloudflare 节点那部分每一行的 tag 名后面要 padding 到固定宽度
  再接链接，原脚本用的是 bash `printf "%-65s"`——这个 65 是**字节数**，
  不是字符数或者 Unicode 码点数。中文 tag（"美国cf-ob-..."）按字符数补
  和按字节数补，补出来的空格数量不一样，拿你的真实 `result.txt` 反推了
  三组不同长度的 tag 才确认这一点；Go 的 `len(string)` 天生就是字节数，
  用它直接补正好对，不需要额外转换，但如果没有拿真实数据反推、想当然
  按 rune 数去补，生成的报告文案在终端里会对不齐、跟原版逐字节比对也会
  出错，只是不影响任何链接的实际可用性，所以是那种"外观错了但没人会因
  为它报错"的坑，光靠肉眼审查代码很容易漏掉。

  写验证脚手架的过程中还踩到一个链接提取的坑，跟 report 包本身无关，
  记在这里避免以后重复踩：vmess:// 链接的 tag 是编码在 base64 JSON
  内部的（`ps` 字段），URI 本身没有 `#tag` 这个片段，不能像 vless/
  trojan/hysteria2/tuic/anytls 那样靠"找 #tag 定位这一行"去抠链接，
  只能按订阅文件里固定的行号顺序取。

## cmd/provision——最终编排

`cmd/provision` 是把前面十三个包（`randgen` `certgen` `sbconfig`
`clientconfig` `classify` `links` `netprobe` `portcheck` `fetch`
`fetch`（新增的 `ServerIdentity`）`procmgr` `sysconfig` `report`）按原脚本
的顺序串起来的最终入口，对应原脚本从头到尾的完整执行流程：

```
[1/12]  开启 BBR
[2/12]  同步服务器时间
[3/12]  下载 sing-box / cloudflared
[4/12]  探测服务器公网身份 + Reality 伪装域名
[5/12]  生成随机值（UUID / 密码 / short-id / Reality 密钥对 / padding）
[6/12]  生成自签名证书
[7/12]  分配端口
[8/12]  构建服务端 config.json
[9/12]  启动 sing-box
[10/12] 启动 cloudflared 隧道
[11/12] 生成客户端配置（3 份）/ 自动分类 / 分享链接 / 订阅文件
[12/12] 生成 result.txt / 放行防火墙端口
```

跟原脚本从头到尾的一处差别：`SERVER_CFNAT`/`PORT_CFNAT`/
`CLOUDFLARED_PROXYIP`/`CLOUDFLARED_PROXYIP_PORT` 在原脚本里是**硬编码的
字面值**（`127.0.0.1:1234` 和 `cloudflare.182682.xyz:443`），明显是原作者
自己的 NAT 转发和代理域名——这几个在 `cmd/provision` 里改成了命令行参数
（`-cfnat-server` / `-cfnat-port` / `-cf-proxyip` / `-cf-proxyip-port`），
默认留空，不会把别人的个人基础设施抄成默认值。

**实际跑了一遍**（`-workdir /tmp/xxx -skip-firewall`），第 1~8 步全部
真实成功：BBR 检查、时间同步、真实下载 sing-box/cloudflared、生成自签
证书、真实绑定测试分配端口、构建出跟 `cmd/verify` 同一套逻辑验证过的
config.json。第 9 步（启动 sing-box）在这个沙盒里会卡住——不是新问题，
是之前 `internal/procmgr` 那节已经记录过的同一个限制：生产配置里的
remote rule-set 需要联网拉取，这个沙盒的出站网络不允许，换到你的真实
VPS 就没这个限制（`procmgr` 那节已经用一份不需要联网的最小配置单独验证
过启动/停止的机制本身没问题）。

**这次端到端跑通顺手抓到一个真实 bug**：`ServerIdentity` 探测公网 IP
失败时，第一版会把网络策略拦截返回的错误文字（"Host not in allowlist:
..."）直接当成 IP 地址返回——这是只有真的跑一遍集成流程才会暴露的问题，
单独测 `fetch` 包内部逻辑测不出来。修法是校验响应内容真的能解析成合法
IP（`net.ParseIP`），解析不出来就换下一个探测服务，全部失败才老实返回
"无法获取公网IP"，已经补了单元测试。

## 真实环境跑通了

## 后续在真实使用中调整过的几处路由/规则细节

- **VmessWSTLS 客户端出站**：原来是 `insecure=true`（谁的证书都认），改成跟
  Hysteria2/TUIC 一样锁定自签证书（`insecure=false` + 内嵌证书）。三个协议
  用的是同一份自签证书，没理由单独放宽这一个协议的校验。
- **AI 分类规则集**：`geosite-openai`（只覆盖 OpenAI）→ 按需求换成社区维护的
  `OverseasAI.list` → 最终定为 `MetaCubeX/meta-rules-dat` 的
  `category-ai-!cn`（同一个来源已经在用于 `geosite-duolingo`，规模和活跃度
  都更高，替换过程见对话记录）。
- **邮件协议端口路由规则**：原脚本这条规则要求 `port` + `domain_suffix` +
  `ip_cidr` 同时满足（AND 关系）。实测跑出一个真实故障：sing-box 对
  IMAP/POP3/SMTP 这几个端口天生不做协议嗅探（服务端先说话的协议，没法从
  客户端字节里偷看域名），`domain_suffix` 在这几个端口上永远不可能匹配，
  是死代码；`ip_cidr` 硬编码固定 IP 又跟不上邮件服务商自己的 IP 池变化
  ——网易邮箱换了个不在名单里的 IP，直接被判给 `geoip-cn` 走直连，超时。
  另外端口列表里的 `994` 查证据不是任何标准邮件协议端口，大概率是 `587`
  （SMTP 提交端口，现代邮件客户端发信最常用）的笔误。现在改成只按端口
  匹配（`25,110,143,465,587,993,995`），不再要求 domain_suffix/ip_cidr，
  代价是这几个端口的流量不再局限于网易系、一律走代理，换来的是不会再
  因为服务商换 IP 而失效。

以上都是在这个开发沙盒里能做到的最大程度验证——沙盒本身的出站网络有
白名单限制，没法验证域名探测、sing-box 拉取 remote rule-set、cloudflared
隧道建立这几步在真实网络条件下到底行不行。这些现在都有了真实反馈：你在
Mac mini 的 Docker Desktop 容器里跑通了完整的 `cmd/provision`，12 步全部
成功，包括 sing-box 真的拉到了 remote rule-set 启动成功、cloudflared 真的
建立了隧道拿到了域名。我把你上传的完整生成结果（`config.json` / 三份
client json / 订阅文件 / `result.txt`）用你实际用的那个 sing-box 版本
（`v1.15.0-alpha.4`，专门下载下来核对，不是拿我这边缓存的旧版本蒙混）
重新跑了一遍 `sing-box check`，全部通过；又做了一轮跨文件一致性检查
（VLESS/Trojan 的 uuid、密码、端口在服务端和客户端两份配置里是否一致，
Hysteria2/TUIC 有没有正确共用 VLESS/VmessWSTLS 的端口数字，21 个 CF 节点
是否都出现在订阅文件里，地区分类是否真的把节点分进了对应分组而不是停在
占位状态）——全部通过。这不是"结构看起来对"，是对着你这次真实生成的数据
重新验证了一遍。

跑出来之后还真的抓到一个东西，就是你发现的那个：`sing-box check`/启动时
报 `stack` option in TUN is deprecated——这是因为你用的 testing 频道拉到
了 `v1.15.0-alpha.4`，而这个字段从 1.15.0 开始弃用、1.17.0 会彻底移除。
已经按你的判断修好：`client.json`/`client_openwrt_sing-box.json`（跟随
最新 sing-box 的两个变体）不再设置这个字段，交给 sing-box 自己选默认栈；
`client_1.11.4.json`（完全独立的旧版 schema，给老版本客户端用）不受影响，
继续显式设置。改完之后跟原来的 golden 参考文件做了结构化 diff：
`client.json`/OpenWrt 现在唯一的差异就是这一个字段被拿掉了（其余所有内容
逐一对比完全一致），`client_1.11.4.json`没有任何变化——再拿你实测的
`v1.15.0-alpha.4`跑了一遍 `check`，两个受影响的文件警告都消失了。

关于你提到的另外几点：
- **ca-certificates 缺失导致证书校验失败**：这不是这次移植引入的问题，是
  任何走 TLS 的客户端（包括原脚本用的 curl）在没有根证书信任库的最小系统
  上都会遇到的——精简 Docker 镜像常见，真实 VPS 发行版镜像基本都默认带
  这个包，遇到算是例外情况，你已经自己解决了，这里不需要改代码。
- **Docker Desktop 的 `-P` 全局端口映射在 Mac mini 上没生效**：这是 Docker
  Desktop 在 macOS 上的网络实现细节，跟这个项目的代码没有关系，不影响你
  已经验证过的东西（进程真的启动了、端口真的在监听、配置真的生成对了）。
- **服务器身份探测出来的域名是 Docker NAT 网关的反向 DNS，不是你未来 VPS
  的真实身份**：这个符合预期——`ServerIdentity()` 探测的就是"当前出站流量
  经过的公网身份"，在 NAT 后面测出来的自然是 NAT 网关的身份，不是这台机器
  自己的。换到真实 VPS 上、这台机器本身就有公网 IP 的时候，探测出来的就会
  是它自己的身份。你说的手动覆盖是对的，也可以等上了真实 VPS 之后不用管，
  让它自动测。

## 还没做完全的、留给你决定的几件事

- 原脚本对 sing-box/cloudflared 都是"先启动一次看日志、杀掉、再正式
  启动"的两阶段模式，`procmgr` 原样保留了，不确定这是不是在规避某个真实
  部署环境才会暴露的启动竞态。
- CF 节点表里 8 个不依赖任何配置的字面 Cloudflare IP 节点，哪怕完全没
  配置 cloudflared 隧道也会生成（这几个节点的 TLS server_name 会是空的，
  实际连不通）——`cmd/provision` 目前原样保留了这个行为，要不要在
  `-skip-cloudflared` 时干脆也跳过这几个节点，等你实际用起来再看要不要改。
- 三份客户端配置里那 12 个地区占位 urltest 分组，原作者自己的注释都说
  "可能未来替换等作用？"——功能上不影响任何东西，纯粹是想不想清理的问题。

## 怎么跑

```bash
export CGO_ENABLED=0         # 见下面"关于 CGO_ENABLED=0"，建议一直这样设置
go build ./...                # 编译所有包，包括最终的 cmd/provision
go test ./...                 # 跑全部单元测试
go run ./cmd/provision -h     # 查看 cmd/provision 的命令行参数
sudo -E go run ./cmd/provision -workdir /root   # 实际跑一遍完整流程（需要 root；-E 保留 CGO_ENABLED）
```

`cmd/verify` / `cmd/verifyclient` / `cmd/verifylinks` / `cmd/verifyfetch` /
`cmd/verifyprocmgr` / `cmd/verifyreport` 都还留着，是每个模块各自的自证
脚手架，不是重复劳动——`cmd/provision` 有问题时，先分别跑一遍这几个看
是哪个环节的锅，比对着一整坨输出去猜要快得多。

### 关于 `CGO_ENABLED=0`

Go 在 Linux 上默认只要检测到有 `gcc`，`net` 包就会优先用 cgo 版的域名解析
（走 glibc `getaddrinfo`，为了兼容 NSS 那些更复杂的解析场景），这需要一套
完整的 C 头文件才能编译。精简容器/镜像（比如只 `apt install golang`、没装
`build-essential` 的 `ubuntu:rolling`）常常只有 `gcc` 没有头文件，就会在编译
期直接报一堆 `stdint.h: No such file or directory` 之类的错——不是代码问题，
是这个默认行为撞上了不完整的 C 工具链。

这个项目从头到尾没用任何 C 绑定，禁用 cgo（`CGO_ENABLED=0`）不影响任何
功能，换成 Go 自带的纯 Go 网络解析器，副作用是正面的：编译出来的二进制
会变成**完全静态链接**，不依赖目标机器的 glibc 版本——这跟"一个二进制
丢到任意一台裸机 VPS 上就能跑"这个目标本来就更契合，比另外装一套 C 工具
链更干净。交叉编译时同理带上这个环境变量。

## 在 macOS 上编译出 Linux 二进制 / 或者直接在 VPS 上装 Go

两条路都可以，选哪条看你想在哪边调试：

**在 macOS 上装 Go，交叉编译出 Linux 二进制，scp 上去跑**（推荐——这样你在
本地就能跑 `go test`、`go run ./cmd/provision -h` 这些，改一行代码验证一次，
不用每次都传到 VPS 上试）：

```bash
brew install go                                   # macOS 上装 Go 工具链
cd singbox-provision
export CGO_ENABLED=0
go test ./...                                     # 本地先跑通单元测试
go run ./cmd/provision -h                         # 本地就能看参数说明，不需要 Linux
GOOS=linux GOARCH=amd64 go build -o provision ./cmd/provision   # 交叉编译成静态 Linux 二进制
scp provision your-vps:/root/                      # 传到 VPS，目标机器不需要装任何东西
```

`GOARCH` 按 VPS 实际架构改：普通云主机基本都是 `amd64`；如果是 ARM 机型
（比如 Oracle Cloud 的 Ampere 实例）用 `arm64`。这一步跟你现在给 ARM
交叉编译内核（`initdir-universal` 那边）是同一个套路，只是 Go 自带交叉编译，
不需要额外配工具链——从 macOS 交叉编译到 Linux 不会触发上面说的 cgo 问题
（交叉编译时 Go 本来就不会启用 cgo，除非你手动设 `CGO_ENABLED=1` 还装了
对应架构的交叉 C 工具链），显式设置只是保险起见、习惯统一。

**或者直接在 VPS（Ubuntu）上装 Go**，就不用交叉编译这一步，改完代码在 VPS
本地 `go build` 就行：

```bash
apt update && apt install -y golang-go   # apt 自带仓库版本够用（这个沙盒里
                                          # 装的就是这个渠道的 1.22.2，构建
                                          # 和跑测试全程没遇到问题）
export CGO_ENABLED=0
```

**如果在容器里测试**（比如 `docker run ubuntu:rolling` 之类只装了
`golang` 包的精简镜像），大概率会撞上前面说的 cgo 头文件缺失问题——两条
路都能解决：`export CGO_ENABLED=0` 之后再 `go run`/`go build`；或者
`apt install -y build-essential` 把完整 C 工具链补上。前者更快、也更贴合
这个项目的部署目标，没有特殊理由（比如就是想验证 cgo 场景本身）建议直接
用前者。

两条路我都建议先跑一遍 `go test ./...`，看到全绿再继续——这是免费的、比
"部署了跑一下看看"更快的反馈。

