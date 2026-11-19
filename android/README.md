# ALiang Proxy / Android

通用安卓客户端，当前 Mac 客户端不受影响。没有 iQOO/vivo 专属接口、品牌白名单或机型绑定。手机安装要求为 Android 8.0（API 26）及以上，并运行 64 位 ARM（arm64-v8a）安卓系统；APK 另含 x86_64 原生库供模拟器使用。无需 Root，无需 Python / Go / Java 或 Google Play 服务。iQOO Neo5 只是用户提供的待验收手机之一，不限制其他品牌使用。

当前运行验证覆盖 Android 16（API 36）ARM64 模拟器。符合上述条件的其他品牌手机属于设计兼容范围，但尚未逐机型验证；不同厂商的后台省电、锁屏和网络切换行为仍需实机验收。32 位 ARM 系统、32 位 x86 系统不在当前 APK 支持范围内。

## 0.1.2 批量节点测试

- 批量连通性 / 延迟：最多同时测试 2 个节点，显示进度、实际延迟与测试时间。
- 批量下载测速：可选已连通节点、全部节点或自选节点；逐个测试，避免并发抢带宽。每节点最多约 5 MiB 加协议开销，确认窗口先显示整批上限。49 个节点为约 245 MiB 加协议开销，服务商还可能按节点倍率计费。
- 支持取消当前测试；离开应用、切换网络或检测到其他 VPN 时自动取消并释放连接。不自动开始测试。
- 结果可按低延迟或高下载速度排序，提供实际结果条形图和“选用此节点”。测速不会自动更改默认出口，需手动选用；先停止 VPN 再测试。

延迟是通过节点访问 Apple HTTPS 页面的耗时，包含解析、连接与 TLS；下载是 Cloudflare 固定约 5 MiB 样本的平均 MB/s，包含连接开销。这些数值适合当时同条件比较，不是持续最大带宽，也不保证其他网站同样快。结果只保存在当前界面会话，重启应用需重新测试。

## 保留的 0.1.1 修复

修复了“节点测试成功，但开启 VPN 后所有网站不通”的 TUN 自回环缺陷：内核必须启用 auto_detect_interface，才会实际安装 Android VpnService.protect 套接字保护回调。原版只实现了回调而未开启调用路径，导致到节点自身的连接再次进入 TUN。

已新增实际系统 TUN 的本机闭环 HTTP/TCP 与 UDP 收发回归测试，并保留异常退出恢复检查。按钮已明确标为“启动/停止 VPN（TUN）”，安卓无另一个 TUN 开关。节点测试不经 TUN；连接后的“验证 TUN 网页访问”才检查 Android 默认网络路径，且仅在用户确认后执行。

从旧版更新：先停止旧版 VPN，再直接覆盖安装 0.1.2；同一签名和包名保留本机配置，无需卸载。

## 安装

将交付目录中的 `ALiang-Proxy-Android.apk` 复制到手机，点开安装，按系统提示允许当前文件管理器安装应用。安装后可关闭该来源的安装授权。更新时直接安装使用相同签名的新 APK，无需卸载原应用。保留原签名密钥才能继续覆盖更新。

HarmonyOS NEXT 等不支持安卓 APK 的系统不适用。此 APK 是个人签名直装版本，不是 Google Play 发布版本。

## 使用

1. 导入 HTTPS Clash YAML 订阅或选择本地 YAML。订阅链接只在本机加密保存，不会放入安装包。
2. 查看导入差异并确认激活，选择默认出口或策略组成员。
3. 选择节点域名解析服务。阿里 DoH：223.5.5.5 / dns.alidns.com；Cloudflare DoH：1.1.1.1 / cloudflare-dns.com。仅发送节点域名，不发送订阅凭据；业务 DNS 经代理转发。
4. 点击连接，在 Android 系统 VPN 授权窗口确认。通知栏和应用内均可停止。
5. 节点测试、下载测速需在 VPN 停止后手动发起，并确认对外访问与流量消耗；开发期间不使用真实订阅联网。

当前使用全局代理；支持 VLESS Reality/Vision、Trojan 和手动选择策略组。域名/IP 分流、Fake-IP、DIRECT、外部控制器、远程规则集与桌面 TUN 配置停用，并在导入时说明。仅支持已校验的节点字段，不会静默忽略未知认证/传输参数。

## 停止与异常恢复

应用不修改 Android 的永久系统代理、永久 DNS 或永久路由，不注册开机自动启动，不自动开启系统“始终开启 VPN / 阻止未使用 VPN 的连接”。隧道使用独立进程；停止时关闭资源，若内核无法及时退出，8 秒内结束本应用的隧道进程，让系统释放隧道。

如果用户自己在系统中启用了断网保护，该设置仍可能阻止直连，请在系统 VPN 设置中处理。网络切换、锁屏、厂商省电策略与长期使用需在实际手机上验收；不承诺永久断网保护或绝对不会崩溃。

## 开发与构建

开发机需要 JDK 17、Android SDK 36、Build Tools 36.0.0、NDK 29.0.14206865、Go 1.26.11、SagerNet gomobile v0.1.12。Gradle 8.13 / AGP 8.13.1 / Kotlin 2.2.21 已固定；Gradle Wrapper 包含分发摘要校验。上述均不属于手机运行依赖。

先准备 `core/upstream.lock.json` 中固定 SHA-256 的 sing-box v1.14.4 源码归档到 `.cache/sing-box-v1.14.4.tar.gz`，安装工具后运行：

```sh
sh scripts/build-android-core.sh
sh scripts/test-android.sh
# ANDROID_SIGNING_PASSWORD 只在本机构建环境中设置；不写进源码。
sh scripts/build-android.sh
```

发布签名文件位于 `private/android-signing.p12`，私有密码文件与之一起保存在本机，不进入源码或交付目录。建议用户自行安全备份。Android 原生依赖的安全升级只作用于 `android/native/go.mod`，不修改已有 Mac 模块。

Android 新增代码及适配按 GPL-3.0-or-later 提供；内核 sing-box 的完整许可证见 `LICENSE` 和安装包 assets。商标属于原作者。构建时按锁定版本还原对应上游及 Go 模块，保留相关许可证。

详细实现与待验收项见 `docs/IMPLEMENTATION.md`、`docs/SECURITY_REVIEW.md`。
