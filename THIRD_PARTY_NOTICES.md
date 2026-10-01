# 第三方组件与数据

本仓库只发布工具代码，不打包 Xray、Hysteria、Surge、Shadowrocket、Clash/Mihomo 的二进制，也不复制运行中的配置或机场订阅。

部署器从 [XTLS/Xray-core](https://github.com/XTLS/Xray-core) 与 [Hysteria](https://github.com/apernet/hysteria) 的官方发布下载二进制并校验 SHA-256。使用与再分发这些程序时，请查看其发布版本附带的许可证。

配置生成器引用 [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)、[Loyalsoldier/surge-rules](https://github.com/Loyalsoldier/surge-rules)、[Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) 与 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)。规则列表与 GeoIP 不随本仓库分发；缓存和生成的数据应保留来源并遵循相应上游许可证。本仓库的 MIT 许可证不替代这些数据的许可证。

[PyYAML](https://github.com/yaml/pyyaml) 是配置生成器依赖。客户端商业软件需自行从官方渠道获取。
