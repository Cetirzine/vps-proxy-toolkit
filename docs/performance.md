# 网络性能与延迟诊断

`diagnostics.py` 只使用 Python 标准库。它输出 JSON 到终端，不保存测量文件，也不改系统、路由器或代理配置。Minecraft 子命令只发送 Java STATUS 握手、Status Request 与 Ping/Pong；不会登录或进入游戏。网络子命令调用系统 `ping` 发少量 ICMP Echo。

## 使用

```sh
python3 diagnostics.py minecraft mc.hypixel.net --port 25565 --samples 3 --timeout 8
python3 diagnostics.py minecraft mc.hypixel.net --proxy http://127.0.0.1:6152
python3 diagnostics.py network example.net --count 10 --family ipv6
python3 diagnostics.py network example.net --count 10 --interface en0 --family ipv4
```

Minecraft 的 `connect_ms` 是 TCP 连接或 HTTP CONNECT 隧道建立时间；`status` 是 STATUS 请求往返时间；`pong` 是 Java Ping/Pong 往返时间。每项摘要分开报告样本数、最小值、中位数、平均值和最大值。PONG 是短连接应用层测量，仍不能代表真实对局中的持续延迟、抖动、丢包、服务器 tick、画面帧率或玩家所在区域。小样本只能用于初筛，建议同一主机、端口、设备和时段比较路径，再在普通游戏会话中复核。

`network` 输出 ICMP 丢包与 RTT 摘要。ICMP 可能被限速或过滤，因此它只能帮助观察到指定目标的网络路径，不能替代游戏 TCP 测量。报告会遮蔽字面 IP，不包含 ping 原始输出或解析出的地址；如需分享诊断信息，请先检查目标主机名是否也需要隐藏。Linux 使用 `ping -I` 绑定接口；macOS 使用 `ping -b`；Windows 系统 ping 不支持此工具的 `--interface` 参数。IPv4/IPv6 可用 `--family` 明确指定；`auto` 在域名同时解析到两种地址时优先 IPv6。

## 如何解读路径

- **丢包与延迟分开看。** “到 VPS 的 IPv4 入口丢包”描述玩家到 VPS 的那一段；VPS 再以 IPv4 或 IPv6 访问目标，是另一段路径。隧道若通过 IPv6 到达 VPS，可能避开本地到 VPS 的 IPv4 问题；如果 VPS 固定以 IPv4 出口连接游戏，VPS 到游戏的 IPv4 路径仍然存在。每次都要写清探测点、目标、地址族和代理出口。
- **`mc.hypixel.net` 是服务主机名，不是地理位置证明。** DNS、负载均衡、边缘网络和线路会影响实际接入点；仅凭主机名、DNS 地址或一次 RTT，不能断言流量抵达亚洲的某个固定服务器。Hypixel 的连接排查说明也列出距离、Cloudflare 和其他外部因素等不同来源；遇到持续问题时应按其官方步骤收集诊断信息。[Hypixel：连接与延迟排查](https://support.hypixel.net/hc/en-us/articles/360019671939-Solving-Lag-and-Connection-Issues-on-Hypixel)
- **吞吐率要分列。** 平均值代表整体速率，中位数降低单次尖峰的影响，峰值只说明短时最高速率；三者不可互换。每份吞吐结果应同时记录下载/上传方向、目标与协议、路线标签、并发连接数、测量时长、时间戳，以及是否多次/并行运行。短时多连接下载的 Mbps 不能预测单连接游戏延迟。
- **考虑代理 CPU 与队列。** 加密、封装、代理程序和单核负载都可能限制吞吐；链路 Mbps 很高也不表示负载时 RTT 稳定。若其他下载或上传使 RTT 上升，应检查队列延迟；支持时可评估 SQM/AQM（例如 CAKE 或 fq_codel），并基于线路实测配置整形。缓冲膨胀会增加负载下延迟，相关测量与缓解建议见 [Bufferbloat 项目](https://www.bufferbloat.net/projects/bloat/wiki/Tests_for_Bufferbloat/) 和 [缓解建议](https://www.bufferbloat.net/projects/bloat/wiki/What_can_I_do_about_Bufferbloat/)。
- **用 BDP 检查长距离 TCP 吞吐。** 带宽时延积（BDP）估算填满路径所需的在途数据量：`BDP(bytes) = bandwidth(bits/s) × RTT(seconds) ÷ 8`。例如 200 Mbit/s、300 ms RTT 对应约 7.5 MB。在途窗口或拥塞控制不足时，TCP 吞吐可能低于链路容量；BDP 不是游戏延迟指标，也不表示应盲目调大系统缓冲区。TCP 窗口扩展及高带宽时延路径见 [IETF RFC 7323](https://www.rfc-editor.org/rfc/rfc7323)。

## 匿名化样本说明

以下为 2026-10-01 的小规模实验摘录，只用于说明如何读数，不是推荐路线或服务承诺。网络位置、出口 IP、账号和凭据均未纳入。

| 测量 | 样本与结果 | 限制 |
|---|---|---|
| 直连 IPv4 到 VPS 的 ICMP | 家用网络 20 包约 40% 丢包；热点网络 20 包约 45% 丢包 | 只描述当时到该 VPS 的 IPv4 探测，不能代表所有 IPv4 目的地 |
| 家用 IPv6 ICMP | 15 包未观察到丢包；RTT 约 288–342 ms（不同快照） | RTT 目标不是游戏服务器；不同采样不可直接当作路线 A/B 结论 |
| Minecraft Java STATUS/PONG | `mc.hypixel.net:25565`；每条路线 2 次。PONG 中位数：直连约 245 ms、家用出口约 270 ms、链式代理约 310 ms、IPv6 隧道约 468 ms | 总共仅 8 次状态探测，运行约 18 秒；未登录或进入对局。主机名不能证明实际后端地区 |
| 下载吞吐实验 | 链式路线：4 并发、10 秒样本约 345 Mbps 平均、385 Mbps 中位、440 Mbps 峰值；另一次 8 并发、20 秒约 354 Mbps 平均、397 Mbps 中位。记录时代理 CPU 负载偏高 | 两次运行条件不同；仅为下载吞吐样本，不能与游戏 PONG RTT 混为一谈。公开发布前应为复现实验补记下载端点和具体时间 |

丢包率、RTT 与吞吐都依赖时间、目标、路由和采样方法。复测时保留每条路线的原始样本数与测试时长，并在分享前移除可识别网络与账户的信息。ICMP Echo 的定义见 [RFC 792](https://www.rfc-editor.org/rfc/rfc792)；不同操作系统的 `ping` 参数以各自实现为准，例如 [iputils ping 手册](https://man7.org/linux/man-pages/man8/ping.8.html)。
