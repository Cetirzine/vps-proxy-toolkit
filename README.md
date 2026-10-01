# VPS Proxy Toolkit

通过已有 SSH 公钥登录，在独立 Ubuntu VPS 上部署 Trojan/TLS 与 Hysteria 2，生成 Surge、Shadowrocket、Mihomo/Clash 配置和 HTTPS 私有订阅。

这套工具从实际部署、丢包排查和客户端配置流程整理而来。支持 IPv6 入口，同时让服务端统一使用 IPv4 出口。代码不包含运营中的服务器地址、账号密码、订阅令牌、机场配置或第三方二进制。

## 功能

- 从官方 GitHub release 下载 Xray/Hysteria，并核对发布资产 SHA-256。
- 使用 Let's Encrypt 短期 IP 证书，严格验证 TLS；每六小时检查续期。
- systemd 非登录服务用户、权限限制、服务自动恢复。
- Google、OpenAI、Claude、YouTube、Twitch、Discord 等优先代理；国内域名/IP 和局域网直连。
- 引用维护中的域名规则和 GeoIP，避免把地理规则列表硬编码进仓库。
- IPv6 节点、IPv4 备用节点，以及旧版 Clash 的 Trojan 配置。
- 私有 HTTPS 订阅、随机访问令牌、禁止从公网通过明文 HTTP 下载配置。
- Minecraft Java STATUS/PONG 与 ICMP 诊断，不登录账号、不修改游戏或系统代理。

## 环境

控制端：Python 3.10+、OpenSSH。Surge CLI 仅用于可选的 macOS 配置校验。

服务端：**独立、全新 Ubuntu 24.04 amd64 VPS**，root SSH 公钥登录。TCP 80 用于 ACME，TCP 443 用于 Trojan/HTTPS，UDP 443 和可选 UDP 8443 用于 Hysteria。使用 IPv6 时，VPS 和客户端网络都需要实际可用的 IPv6 路由。

部署会安装软件、配置默认 nginx 站点和命名服务。工具会备份 nginx 配置并拒绝接管未知配置；不要直接在承载其他网站的生产服务器上运行。`allow_existing=true` 是显式接管选项，使用前应自行备份和审阅配置。

## 快速开始

```bash
git clone https://github.com/Cetirzine/vps-proxy-toolkit.git
cd vps-proxy-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp project.example.json project.json
chmod 600 project.json
```

编辑 `project.json`，把文档示例地址换成自己的 VPS 地址和 SSH 目标。首次手动 SSH 登录并核对服务器主机密钥，随后确认公钥登录可用。脚本使用 BatchMode，不把登录密码放进命令行。

```bash
python deploy_proxy.py
python deploy_hysteria.py both
python make_client_configs.py
python publish_subscriptions.py
```

配置和订阅地址保存在 `private/`。不要提交或分享整个目录。订阅 URL 本身是访问凭据；客户端配置中包含节点密码。

### Hysteria 模式与带宽

`primary` 部署 UDP 443，`fast` 部署双栈 UDP 8443 并优先生成 IPv6 入口，`both` 部署两者。

`project.json` 的 `hysteria.*.upload_mbps`、`download_mbps` 从**服务器**方向命名：服务器上传限制对应客户端的下载设置。它们是测试和速率控制参数，不是物理线路速度承诺。先用保守值测丢包和持续吞吐，再逐级提高。

若希望 fast 入口启用 Salamander，先在本机创建只读于自己的密码文件；部署器会在配置和客户端蓝图中复用它：

```bash
mkdir -p private
chmod 700 private
python -c 'import secrets; from pathlib import Path; p=Path("private/hysteria-fast-obfs-password.txt"); p.write_text(secrets.token_urlsafe(32)); p.chmod(0o600)'
python deploy_hysteria.py fast
```

### 客户端

| 客户端 | 文件 |
|---|---|
| Surge | `private/VPS-Surge.conf` 或发布后的 `Surge.conf` |
| Shadowrocket | 节点订阅 `Shadowrocket.txt`，分流配置 `Shadowrocket.conf` |
| Mihomo/Clash Meta | `Clash.yaml` |
| 旧版 Clash | `Clash-Legacy.yaml`，仅 Trojan |

Shadowrocket 的标准 URI 没有定义带宽参数；不同版本可能需要在节点设置中手动校准。Windows TUN 模式需要相应权限。脚本不自动切换现有客户端配置。

如 macOS 的 IPv6 路由需要绑定物理网卡，可在 `project.json` 中添加 `"surge_interface": "en0"`，工具仅把它写入 Surge 的 IPv6 节点，并允许其他接口回退；其他平台不使用该接口名。

高级节点顺序可通过 `private/optimized-nodes.json` 指定。`nodes` 中支持 `name`、`type`、`server`、`port`、`sni`，以及可选 `download_mbps`、`upload_mbps`、`obfs_password`。密码默认使用本地部署生成的凭据。不要把这个带凭据的蓝图放进公共仓库。

## 诊断

```bash
python diagnostics.py network example.net --count 10 --family ipv4
python diagnostics.py network example.net --count 10 --family ipv6 --interface en0
python diagnostics.py minecraft mc.hypixel.net --samples 3
python diagnostics.py minecraft mc.hypixel.net --proxy http://127.0.0.1:6152 --samples 3
```

同一服务器、同一时段比较路径。Minecraft STATUS/PONG 反映状态协议响应，不能替代实际对局测试；域名不能证明游戏后端位于亚洲。修改代理只在实际 RTT、抖动和丢包改善后才有意义。

详见 [性能与丢包排查](docs/performance.md)。带宽、延迟和平台账号风控是不同问题；本工具不承诺低延迟、固定测速数字或规避账号限制。

## 本地验证

```bash
python -m unittest discover -s tests -v
python -m py_compile common.py deploy_proxy.py deploy_hysteria.py make_client_configs.py publish_subscriptions.py diagnostics.py
```

`make_client_configs.py --offline` 可不下载域名数据，只使用种子规则和客户端在线规则引用。生成前需要本地 `project.json` 和部署生成的凭据。`--check-surge` 在已安装 Surge 的 macOS 上执行语法校验。

本仓库重构后的验证包括离线生成、格式/权限检查、部署代码编译和诊断协议模拟；不宣称 CI 已在全新 VPS 上完成端到端部署。

## 来源与许可证

工具代码采用 [MIT](LICENSE)。依赖和引用数据遵循各自许可证，详见 [第三方说明](THIRD_PARTY_NOTICES.md)。

- [Xray](https://github.com/XTLS/Xray-core)
- [Hysteria 官方配置](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)
- [Let's Encrypt IP 证书与 Certbot](https://letsencrypt.org/2026/03/11/shorter-certs-certbot/)
- [Surge Hysteria 2 参数](https://manual.nssurge.com/policies/hysteria2.html)
- [Mihomo Hysteria 2 参数](https://wiki.metacubex.one/config/proxies/hysteria2/)

