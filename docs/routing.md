# 按用途分流与已有入口中转

默认生成的配置让海外服务使用自有 VPS，国内服务直连。若独立 VPS 的跨境入口很差，而你已经有一条较快的入口代理，可以在本机配置中复用它，再转发到自有 VPS。

以下是**添加到已有 Surge 配置的片段**，不是独立完整配置。`ExistingEntry` 必须是本地已定义并可用的代理；把文档地址和示例密码换成部署生成的值，并保留证书验证。

```ini
[Proxy]
OwnVPS = trojan, 203.0.113.10, 443, password=generated-secret, sni=203.0.113.10, skip-cert-verify=false, underlying-proxy=ExistingEntry

[Rule]
DOMAIN-SUFFIX,openai.com,OwnVPS
DOMAIN-SUFFIX,chatgpt.com,OwnVPS
DOMAIN-SUFFIX,oaistatic.com,OwnVPS
DOMAIN-SUFFIX,oaiusercontent.com,OwnVPS
DOMAIN-SUFFIX,anthropic.com,OwnVPS
DOMAIN-SUFFIX,claude.ai,OwnVPS
DOMAIN-SUFFIX,claude.com,OwnVPS
DOMAIN-SUFFIX,claudeusercontent.com,OwnVPS
DOMAIN-SUFFIX,claudecontent.com,OwnVPS
GEOIP,CN,DIRECT,no-resolve
FINAL,ExistingEntry
```

保留已有的局域网、国内域名、DNS 和其他分流规则，把需要固定出口的服务规则放在更宽泛规则之前。各账号登录、认证和资源域名应一起核对路径；仅代理一个 API 域名不足以说明网页访问也使用同一出口。

中转不会让服务器出口变成住宅网络，也不会改变服务器所在地。它增加一段路径，只有当入口和后续路由更好时才会改善吞吐或延迟。基于协议的 UDP 能力也需要确认，不能把 TCP 测速当成 UDP 游戏体验。

Minecraft 应按真实 STATUS/PONG 与实际对局比较 `DIRECT`、已有入口和自有 VPS。若直连确实更好，可在本机添加 `DOMAIN,mc.hypixel.net,DIRECT`；不要把一次网络的结果当成所有用户的默认规则。

现有入口的账号、密码、订阅 URL 保留在本机。公共仓库和默认私有订阅生成器都不包含现有入口的凭据。

参考：[Surge proxy chain 参数](https://manual.nssurge.com/policies/parameters.html)、[Hypixel 官方连接排查](https://support.hypixel.net/hc/en-us/articles/360019671939-Solving-Lag-and-Connection-Issues-on-Hypixel)。
