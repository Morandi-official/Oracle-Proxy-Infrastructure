# Oracle Proxy integrated Windows candidate

This is the product integration under development, separate from the historic deny-only LabManager. **It has not passed release acceptance and is not a GA distribution.** Main-branch CI publishes an unsigned acceptance bundle only after real Oracle egress, account linkage and isolated Windows fault tests pass. Pull-request builds validate packaging but upload only review evidence. The client download includes explicit payload hashes and notices. The separately downloadable corresponding source archive contains the actual vendored Go dependency sources and the exact build pins; its filename and hash accompany the client download. Both artifacts are retained together for the same period.

Target: Windows x64, with Windows 11 as the current primary desktop and Windows 10 servicing/edition support subject to Microsoft's supported-OS matrix. Since rc22 the WinForms desktop and SYSTEM service use one self-contained .NET 10 LTS executable; no shared .NET 8 installation is required. The exact SDK/runtime pins, patch maintenance policy and cross-runtime upgrade evidence are described in [rc22 runtime migration](../../../docs/windows-rc22-dotnet-lts.md). First setup requires UAC to install the fixed, auto-start SCM service and protected files; everyday login/connect/disconnect uses an owner-authenticated local pipe. No WireSock, official WireGuard GUI, FlClash or daily SSH is required. Backend: administrator-issued accounts only; HTTPS account authentication, explicit device ownership confirmation and per-account telemetry.

The separate userspace WireGuard/TUN core is built from pinned sing-box v1.14.3 source with `with_gvisor,with_wireguard`. Its child-process interface accepts one configuration frame on anonymous stdin and closes gracefully on EOF. It has no exposed configuration server, shell, user-selected path or client-supplied endpoint. Application payload routing ends at the WireGuard endpoint; identified GameViewer program paths use the direct outbound. Upstream embeds Wintun; CI compares its exact bytes against the official signed x64 0.14.1 release before privileged tests. This is a custom application embedding an open-source core, not an independently invented VPN cryptographic protocol.

The native Windows SDK WFP component owns one provider/sublayer and persistent ALE filters plus boot transport filters. It blocks other application egress, permits loopback, DHCP/NDP, SYSTEM-only service/core identities, and verified UU paths. TUN packet-path permits live in a separate dynamic WFP session; process exit releases them while the persistent base blocks remain. Transactions replace/remove only this provider's filters. A core/service crash leaves persistent filters in place. Since rc36, confirmed death of the last registered GUI process requests audited Off cleanup; network loss while the GUI remains alive does not. Presence/count inspection is only an invariant, not sufficient proof of every traffic path: actual packet and fault tests are required before release.

Keys/tokens are DPAPI CurrentUser encrypted **under LocalSystem** in protected ProgramData storage; the UI never receives the private key/token. Passwords are forwarded through the authenticated pipe only for login and not persisted. The service generates X25519 locally; the backend receives only its public key. Managed string copies cannot be reliably erased; memory-only configuration and zeroed byte buffers reduce exposure, not defeat a malicious SYSTEM administrator.

UU discovery reads local machine and loaded user installation records plus running processes, independent of drive letter. Only validated NetEase-signed executables under protected directories become process-path exceptions. Signature/publisher changes require refresh/review, not a broad filename bypass. The exact publisher identity and helpers have been statically verified against official, SHA-256-pinned 4.39.2.1561 and 4.41.1.2335 installers in CI; this does not prove logged-in remote-control continuity. User-specific/writable installations must not silently receive SYSTEM path exceptions.

Cloud Windows evidence now covers compilation, non-admin owner/unauthorized IPC boundaries, SYSTEM DPAPI, real service setup/failed-upgrade rollback/uninstall, isolated WireGuard TCP/fresh UDP DNS, peer loss, GUI/service/core failures, stale permit removal and missing-state recovery. Remaining acceptance gaps include physical IPv6, BFE restart and actual Windows boot, and real logged-in UU controller/controlled-device continuity for the user's versions. Current Oracle client descriptor explicitly blocks IPv6 pending server-side IPv6 provisioning and dual-stack acceptance. No real restart/UU/IPv6 success may be inferred from a same-boot unit test.

License: new product integration GPL-3.0-or-later; upstream sing-box GPLv3-or-later (see LICENSE and pinned source). Bouncy Castle is MIT; Wintun and other linked upstream licenses must accompany any eventual binary distribution with corresponding build source/dependency versions. No proprietary signed publisher certificate is present. Build hashes are not an Authenticode publisher signature.


Main-branch CI additionally uses only the ordinary, low-quota account in the `windows-client-acceptance` Environment to verify actual Oracle egress, explicit device confirmation, usage linkage, GUI-process loss, SCM crash recovery and explicit disconnect. Pull-request jobs do not receive that Environment's credentials. This acceptance harness is excluded from the product executable and never uploads keys, bearer tokens, passwords or screenshots of a real account. A CI enrollment consumes a device slot; logging out intentionally does not erase the server's historical device record.


The sole VPN transport is native WireGuard UDP. The client retains the UDP
port picker and automatic failover to another authorized IP. The local control
service verifies the WireGuard exit before reporting the connection ready.

While the registered client window is open and disconnected, the service may keep its own empty Wintun adapter ready for the next click. Before reporting a direct connection, it checks that the WireGuard session has stopped and that the adapter has zero assigned addresses, routes and DNS servers. If it cannot verify the empty adapter, it removes it. The next Connect checks the current account policy and verifies the new encrypted connection and its public exits.

Closing the last registered window releases the holder and adapter and stops the control service. Confirmed loss of that window triggers the same cleanup. A cleanup failure retains protection and exposes the recovery action.

The hosted acceptance measures clicks through the actual GUI, checks direct Internet access while disconnected and tests both transfer directions through the verified tunnel. It records UDP round-trip times under each load.

rc11 adds bounded native per-port initiation/response/cookie/invalid/obsolete
counters and numeric socket errors. Failed native evidence survives fallback;
client_handshake_reply still describes only the current carrier/core. A shaped
response is diagnostic progress, not proof of cryptographic authentication or
a verified Oracle exit. No raw stderr, packet bytes, IP addresses or keys are
exported in these counters. Intended socket closure is not a read failure.

rc11协议重试：显式选择UDP或HTTP/3后，新的连接会重新尝试所选协议，不复用上次回退至其他协议的预备核心；在下拉框再次选择相同项目也会触发重新探测。自动模式保留已验证备用通道的快速重连。协议选择仍有受限网络下的自动兜底，实际协议继续明确显示。

The rc15 TCP policy and GitHub local-intermediary diagnosis are described in [network performance evidence](../../../docs/network-performance-and-github-20261024.md). The actual WireGuard stack uses CUBIC with unchanged desktop buffers and stable MTUs. Corresponding source includes the exact-preimage dependency patch and its actual-stack regression.


rc18 separates signing in from device enrollment. Sign in with the administrator-issued account, check the local name and short public-key fingerprint, choose a recognizable name, explicitly tick ownership confirmation, then select “确认并登记此设备”. A pending login consumes no device slot and receives no tunnel configuration; Connect and standby preparation are independently blocked in the SYSTEM service until server-confirmed enrollment. Registration does not itself connect the VPN. The server enforces the account limit (default three) atomically; a recognized key uses its existing slot. Old devices without a confirmation receipt need one confirmation on upgrade, without a second slot. The private device key stays DPAPI-protected on this Windows installation; this fingerprint is not physical hardware attestation.

The account/device section shows the account's own device names, short identifiers and current-device marker. Administrators see pending logins separately from allocated devices, plus confirmation time, recorded computer name, client version and recent client-reported state. Client presence is advisory; server WireGuard handshake and measured usage remain separate evidence. Revocation and account restrictions still deny access. No self-registration of user accounts or arbitrary local administrator command is added.

### 界面滚动与静态圆角

连接、断开事务期间抑制 Windows Forms 因禁用当前焦点按钮而触发的自动滚动；用户主动滚动和顶部模块导航仍正常工作，不强制复位到顶部。

按钮、下拉框、输入框边框、复选框、卡片和用量条使用静态连续曲率圆角。文本输入与下拉选择保留原生控件、密码掩码、IME、键盘与无障碍行为。轮廓按尺寸和 DPI 缓存，控件销毁时释放；没有新增绘制计时器、模糊或阴影动画。

Windows UI 验收覆盖异步连接/断开的焦点与滚动保持、手动导航、下拉展开、不同窗口尺寸、静态轮廓复用和重复绘制的 GDI 句柄增长。
