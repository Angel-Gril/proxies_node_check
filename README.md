# 节点检测台

从混合文档中提取代理节点，发起真实 HTTPS 请求，标注状态并导出可用节点。支持本地命令行、本地网页，以及部署到自己的服务器。

本地脚本直接运行：

```sh
python -m pip install -r requirements.txt
python nodecheck.py nodes.txt
```

## 网页

本地网页访问 `http://127.0.0.1:18765`；服务器网页使用部署时通过 `NODECHECK_DOMAIN` 指定的自有域名。

1. 登录后上传一个或多个 TXT、MD、CSV、JSON、YAML 或 DOCX 文件；同一节点在多个文件中出现时只测试一次。
2. 对没有协议前缀的 `IP:端口:账号:密码`，选择 HTTP 或 SOCKS5。已有前缀的链接按自身协议识别。
3. 查看进度和结果，下载 ZIP。下载失败可重试，下载后结果仍保留；确认文件已保存，再点击“确认已保存并清理”。取消、退出或闲置超时会清理。

单个文件最多 5 MB、每次最多 20 个文件/总大小 100 MB、50000 个去重节点。每个任务可以选择 100 或 500 个节点作为一个检测单位；服务器一次只执行一个任务，第二个任务排队。任务最长 24 小时。完成或出错后，临时结果在最后一次查看或下载后的 24 小时才过期；页面显示倒计时，打开时每分钟自动续期，关闭页面后也有 24 小时的下载窗口。清理定时器间隔 10 秒。

刷新页面会自动恢复当前账号的任务；登录过期后重新登录同一账号，也能恢复保留期内的任务。点击下载不再删除任务，即使下载中断或文件读取失败也可以重试。“确认已保存并清理”需要再次确认才删除；退出登录会清理该账号的任务，页面会先提醒。任务只保存在当前应用进程中，服务重启会清空临时任务。

应用不保存检测历史。上传文件、任务状态和登录限流信息放在内存中；分单位汇总文件、ZIP 和短暂内核配置使用临时目录，部署服务将其指向 `/run/nodecheck`（tmpfs）。确认清理、退出或闲置过期后删除临时结果；内核配置随子进程退出删除。本地网页使用系统临时目录。服务禁用交换分区和 core dump，专用站点不写访问日志，也不落盘缓存请求或响应。服务管理器可能保留启动/停止状态；Cloudflare 等上游的日志策略需在其后台单独配置。本地命令行模式会按要求保存导出文件。

下载包含：

| 文件 | 内容 |
| --- | --- |
| `overall/` | 全部节点的状态、测试明细、可用分享链接、出口 IP、Clash 配置和说明 |
| `units/unit-XXXX/` | 每个检测单位独立的 `report.csv`、`report.json`、`available.txt`、`exit_ips.txt`、`clash.yaml` 和说明 |

## 支持的输入

```text
http://username:password@192.0.2.8:3128
https://username:password@192.0.2.8:443
socks5://username:password@192.0.2.9:1080
192.0.2.8:3128:username:password
192.0.2.8 3128 username password
http,192.0.2.8,3128,username,password
```

支持 IPv6、URL 编码密码、SS / VMess / VLESS / Trojan / Hysteria2 / TUIC 常见分享链接、Base64 订阅，以及 Clash `proxies` YAML/JSON。常见 WS、gRPC、Reality 参数会转换。SS、VMess 等需要 **Mihomo**；HTTP/SOCKS 直接使用 curl。未知协议、缺少内核或内核不接受的参数会明确标注，不能保证识别所有厂商的私有分享格式。

只提取文档中的节点，不执行文档中的规则、外部订阅、控制端口或其他程序。网页拒绝内网/本机/保留 IP 以及依赖本地证书或链式代理的节点。普通网站链接不当作节点。裸节点缺乏协议信息，无法可靠自动判断，应使用页面选项或命令行参数。

## 判定方式

默认通过每个节点分别请求 ipify、Cloudflare trace 和 Google 204。每个请求限定超时并校验目标 HTTPS 证书；只接受 2xx。两个 IP 检测站点还需返回有效 IP。三项中至少两项通过记为可用；只通过一项标注 `partial`，不加入可用节点。50k 节点会按选择的 100/500 个检测单位顺序执行，ZIP 同时提供每单位和整体结果。

报告的延迟是**完整请求耗时**，不是 ICMP ping。实际出口 IP 取自检测站点返回，可能不同于代理服务器地址，轮换代理可能返回多个 IP。测试仅反映测试时刻和位置；可用性不证明 IP 的住宅/机房归属，也不代表特定业务网站的解锁状态。

## 本地脚本

要求 Python 3.10+、curl。Windows 10/11 通常自带 curl。

```powershell
python -m pip install -r requirements.txt
python nodecheck.py "D:\nodes.txt"
python nodecheck.py "D:\nodes.txt" --default-protocol socks5
python nodecheck.py nodes.txt nodes.yaml --rounds 2 --min-success 4 -o results\batch-01
python nodecheck.py nodes.txt --parse-only
```

默认按日期创建 `results` 子目录；指定目录需不存在，避免覆盖历史结果。退出码：0=存在可用节点；1=已测试但没有可用节点；2=输入/参数错误。密码中的 `@`、`:` 等建议 URL 编码。

安装固定版本 Mihomo（校验官方 GitHub SHA-256）：

```powershell
python tools/install_mihomo.py --output .private/mihomo.exe
python nodecheck.py nodes.yaml --mihomo .private/mihomo.exe
```

TUN 模式会影响底层网络路由。脚本清除 curl 进程的代理环境变量，显式指定待测代理，但这**不会绕过系统 TUN**。可以关闭 TUN、在代理客户端为测试进程/目标节点配置直连，或将相同脚本放在国外服务器运行。Windows curl 支持用物理网卡的本地 IPv4 指定出口，仍需以真实路由为准：

```powershell
Get-NetIPAddress -AddressFamily IPv4
python nodecheck.py nodes.txt --interface 192.168.1.100
python nodecheck.py nodes.yaml --mihomo .private/mihomo.exe --core-interface "以太网"
```

Linux：

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python tools/install_mihomo.py --output .private/mihomo
.venv/bin/python nodecheck.py nodes.txt --mihomo .private/mihomo
```

自定义目标：`--target https://example.com --min-success 1`。可重复指定 `--target`；自定义目标只校验 2xx，域名特定的业务校验需另外实现。

## 本地网页与服务器维护

```powershell
python manage.py setup
python manage.py serve
```

访问 `http://127.0.0.1:18765`。`setup` 通过隐藏输入生成密码哈希与会话密钥，保存在 `.private/app.env`；本地启动只绑定 127.0.0.1。

服务器部署使用独立 `/opt/nodecheck`、`/etc/nodecheck`、`nodecheck` 系统用户、`nodecheck.service`、`127.0.0.1:18765` 及 Nginx `nodecheck` 站点；现有服务配置不应改写。`deploy/prepare.sh` 在命名空间/端口已占用时停止，不用于重复覆盖安装。

首次部署需要 Linux、Nginx、Python 3.10+（含 venv）、curl、certbot，以及指向自己服务器的域名。在 root shell 中从克隆的仓库目录执行，替换下面的示例域名：

```sh
export NODECHECK_DOMAIN=check.example.com
sh deploy/prepare.sh
# 只复制已跟踪的项目文件，账号配置单独生成
git archive HEAD | tar -x -C /opt/nodecheck/app
cd /opt/nodecheck/app
python3 -m venv /opt/nodecheck/venv
/opt/nodecheck/venv/bin/pip install -r requirements.txt
/opt/nodecheck/venv/bin/python manage.py setup --env /etc/nodecheck/app.env
# 应返回 nodecheck-origin-validation，确认域名到达这台服务器
curl --fail "http://$NODECHECK_DOMAIN/.well-known/acme-challenge/nodecheck-origin-check"
sh deploy/install.sh
```

`NODECHECK_DOMAIN` 必须是域名本身，例如 `check.example.com`，不带 `https://`、端口或路径。部署脚本据此生成 Nginx 站点、证书申请和续期钩子；`deploy/nginx.conf` 是带占位符的模板，不能直接复制到 Nginx。每次运行 `prepare.sh`、`install.sh` 或 `finalize.sh` 都需要设置该变量，缺失或格式无效时会在修改服务器之前停止。`finalize.sh` 用于完成已有安装的权限设置、续期钩子和健康检查。

```sh
systemctl status nodecheck --no-pager
curl -fsS http://127.0.0.1:18765/healthz
# 仅停止本应用
systemctl stop nodecheck
# 修改账号配置后仅重启本应用（当前内存任务会清空）
systemctl restart nodecheck
# Nginx 修改后先校验，再平滑加载
nginx -t && systemctl reload nginx
```

停用站点时只移除 `/etc/nginx/sites-enabled/nodecheck` 的链接，再校验并 reload Nginx；不要停止整个 Nginx，也不要修改其他站点。证书用独立 webroot 申请，续期钩子只在本域名证书更新后 reload Nginx。

## 验证

```powershell
python -m unittest discover -s tests -v
$env:MIHOMO_PATH = (Resolve-Path .private/mihomo.exe).Path
python -m unittest discover -s tests -p test_network.py -v
```

网络集成测试使用本机 TLS 服务与带认证的 HTTP CONNECT 代理，覆盖成功、错误密码、非 2xx、真实 Mihomo 转发和进程清理。TLS 测试夹具需要可选的 `cryptography`；未安装时会明确跳过。还覆盖混合解析、凭据不进报告、会话权限、CSRF、禁止内网目标、重复下载、中断后重试、闲置续期、确认清理和刷新/重新登录恢复任务等。
