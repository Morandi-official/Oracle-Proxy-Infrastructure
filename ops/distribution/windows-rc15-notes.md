Windows 10/11 x64 未签名便携验收版。旧版先断开退出，完整解压新版，打开 OracleProxy.exe 并点击“安装 / 升级服务”。保留原有 UDP8443 偏好、账号和设备身份。

本版在实际 WireGuard 用户态 TCP 栈启用 CUBIC，改善高延迟、丢包路径上的传输恢复；保留既有桌面 TCP 缓冲区及 TUN1280 / 内层 WG1200 MTU。当前 IPv6 阻断策略下，DNS 使用 IPv4-only，减少无效 IPv6 尝试。原生 UDP socket 补齐 WireGuard 标准7MiB收发缓冲策略，诊断显示调整前后的实际值；系统可钳制请求。全局网络参数不变。

“GitHub 连通性”新增只读 DNS/HTTP 检查，可识别 Steam++、FastGitHub 等把域名映射到本机的情况。不会修改 hosts、关闭其他软件、导出账号令牌或降低 TLS 证书验证。

已确认现有 Oracle 是伦敦 A1.Flex2OCPU/12GB，规格带宽2Gbps；AMD Micro 的公网50Mbps限速不适用于该实例。规格带宽不保证国际互联网实际速率；中国移动热点到伦敦的基础RTT不能用客户端参数消除。受控模型的 CUBIC 改善不代表实机必然达到相同比例，需用同一测速服务器复测。

GitHub 与 Oracle 两种下载地址均提供客户端、配套源码及校验文件。仍为候选版，IPv6 继续按策略阻断；实机吞吐、Win10及重启等后续正式交付验收仍待完成。
