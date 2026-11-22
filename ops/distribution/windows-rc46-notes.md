# Proxy 0.3.0-rc46

- Windows 客户端仅通过 WireGuard UDP 传输。仍可选 UDP 端口，并按账号授权的主备 IP 自动尝试备用入口。
- 已连接时，UDP 发包遇到阻塞不再占用收包所需的锁。连接状态仍以出口验证为准。
- 此版本提供 Windows x64 便携版和安装版。安卓版原本就使用 WireGuard UDP。
