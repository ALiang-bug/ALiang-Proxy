# ALiang Proxy

个人使用的跨平台代理客户端，支持导入自己的 Clash YAML 文件或 HTTPS 订阅，使用 VLESS Reality/Vision 与 Trojan 节点。请自行提供有权使用的订阅。

| 平台 | 下载 | 基本使用 |
| --- | --- | --- |
| Windows 10/11 x64 | Release 中的 `ALiang-Proxy-Setup-x64.exe` | 安装后导入订阅，选择默认出口。启动本地代理后可启用 Windows 系统代理，或停止本地代理后启动 TUN。TUN 每次启动需要管理员授权。 |
| macOS 26+ Apple Silicon | Release 中的 `ALiang-Proxy-macOS-arm64.zip` | 解压并将 App 放入“应用程序”。导入订阅，启动本地服务，再按需启用系统代理。首次使用 TUN 时，在应用内安装辅助程序。 |
| Android 8+ ARM64 | Release 中的 `ALiang-Proxy-Android-v0.1.2.apk` | 安装 APK，导入订阅，选择节点，点击连接并允许系统 VPN 权限。 |

系统代理与 TUN 使用启动时选择的出口。切换节点后请重新连接。使用结束后关闭对应模式。Windows 的 **Restore Windows Proxy** 会恢复启用前的系统代理设置。

macOS 包是临时签名且未经 Apple 公证。在另一台 Mac 上首次打开可能需要到系统设置的隐私与安全性页面手动允许。Windows 安装包未签名。Android 更新请使用相同签名的 APK。

源码位于 `android/`、`macos/`、`windows/`、`core/` 和 `scripts/`。Android 的完整依赖源码归档随 Release 提供。核心使用固定版本 sing-box v1.14.4，相关许可证见 `LICENSE` 与各平台包内的许可证文件。构建说明见各平台 README 和脚本。
