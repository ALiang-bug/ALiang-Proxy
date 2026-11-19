# ALiang Proxy

个人使用的跨平台代理客户端。请使用自己的订阅。

## 下载与安装

在 [v0.1.2 下载页](https://github.com/ALiang-bug/ALiang-Proxy/releases/tag/v0.1.2) 选择对应安装包：

| 平台 | 文件 | 安装 |
| --- | --- | --- |
| Windows 10/11 x64 | `ALiang-Proxy-Setup-x64.exe` | 运行安装程序。TUN 启动时需要管理员授权。 |
| macOS 26+ Apple Silicon | `ALiang-Proxy-macOS-arm64.dmg` | 打开 DMG，将应用拖入“应用程序”。首次使用 TUN 时在应用内安装辅助程序。 |
| Android 8+ ARM64 | `ALiang-Proxy-Android-v0.1.2.apk` | 安装 APK，连接时允许系统 VPN 权限。 |

安装后导入 Clash YAML 文件或 HTTPS 订阅，选择节点，再启动对应代理模式。Windows 与 macOS 可先启动本地代理服务，按需启用系统代理或 TUN。Android 点击连接即可。

macOS 构建未经 Apple 公证，首次打开可能需要在“系统设置 → 隐私与安全性”中允许。Windows 安装包未签名。安装包校验值见 Release 中的 `ALiang-Proxy-SHA256SUMS.txt`。

对应版本的源码及构建文件保存在 [`source-v0.1.2` 标签](https://github.com/ALiang-bug/ALiang-Proxy/tree/source-v0.1.2)，用于满足开源许可证要求；日常下载安装无需获取源码。
