# 交付物验收（2026-11-17）

交付位置：`artifacts/android/ALiang-Proxy-Android.apk`。

- 包名 local.aliang.proxy，版本 0.1.2 / 3，最低 API 26，目标 API 36。
- 最终 release APK 安装到离线 Android 36 ARM64 模拟器：安装成功，MainActivity 冷启动成功，保持前台，未观察到 AndroidRuntime 应用异常。
- 最终 Manifest：非 debuggable，禁止 backup/明文订阅网络，未包含 instrumentation；唯一 VPN Service 不导出、需 BIND_VPN_SERVICE，运行于 :tunnel。没有测试辅助 Activity。
- 实际权限仅 INTERNET、ACCESS_NETWORK_STATE、FOREGROUND_SERVICE、FOREGROUND_SERVICE_SYSTEM_EXEMPTED、POST_NOTIFICATIONS。未请求 Root、存储、通讯录、位置、无障碍、设备管理或开机启动。
- apksigner 严格验证通过，APK Signature Scheme v2；RSA 3072 私用签名。
- 签名证书 SHA-256：775cea17f03293f3933f01de1c906906dd5eac08c1bf66f70d99507b4f099980。
- APK 只含 arm64-v8a/libaliang.so 与 x86_64/libaliang.so；ARM64 动态依赖仅 liblog.so、libdl.so、libc.so（Android 系统提供）。
- 原生 ARM64 ELF LOAD 对齐 0x4000；zipalign 16 KiB 校验通过。该静态验证不冒充已在 16 KiB 真机运行。
- 未打包 Python、私有签名文件、外置 Go 运行时或脚本。Go 运行时代码已编译进入动态库，手机无需安装 Go。
- 对打包的 DEX/SO/文本做已知历史凭据、测试令牌和本机路径检查，未发现命中；打包输入仅新增 Android 工程、已知公共源码与许可证。配置由用户安装后导入。
- Kotlin stdlib 2.2.21 的 OSV 查询没有返回已知漏洞；Android/ARM64 Go 源码扫描为 0 项可达漏洞，仍有 6 项模块图中未被调用的报告，详见安全审查。
- 主机环回：安卓转换器生成的 VLESS Reality/Vision、Trojan 出站，TCP/UDP 收发通过。独立模拟器生命周期测试包含正常停止、重复启动、强制进程死亡、崩溃后重连、重复停止和系统撤销授权。
- 物理手机与真实节点联网未测试；设备厂商省电策略、蜂窝切换、24 小时稳定性不是上述证据的覆盖范围。

当前仅为个人直装交付，不是应用商店发行。安全检查代表当前版本与当前漏洞数据库，不保证未来不存在未知漏洞。Android 源码及对应上游和第三方源码随 source.zip 提供；手机安装只需 APK。

## 0.1.1 回归补充

修复前完整系统 TUN 测试记录为 TCP 连接超时；修复后本机闭环 HTTP/TCP、UDP 均通过。验收不再仅依赖“VPN 网络已出现”。新增测试网关只在 Mac 回环监听，模拟器出站白名单禁止外网；测试用 Root 仅用于隔离模拟器的防火墙，不是手机应用运行要求。

## 0.1.2 批量测试验收

- 已加入批量连通性 / 延迟和批量下载测速，支持已连通、全部、自选下载范围，进度与取消、排序、实际数值条形图和手动选用节点。
- 6 项 Kotlin 单元测试及 Go race/checkptr / vet 通过；原生真实 TLS 握手取消测试通过。隔离模拟器中通过真实 JNI 创建并预取消 20 个任务，整批正确完成且无对外访问。
- 既有 TUN HTTP/TCP、UDP、重复启动、停止、进程死亡、崩溃后重连、系统撤销授权，在当前 0.1.2 再次闭环通过。
- 正式 APK 在同一隔离模拟器从正式 0.1.1 覆盖安装到 0.1.2，安装及冷启动成功；未用 debug APK 冒充 release 安装结果。
- SHA-256：00f546ba89e9f8158b4f6a7266e701297d873541d2d1546b59e66666d5b01917。签名与 0.1.1 相同，可覆盖更新。
- 未进行私人节点批量测速，也未证明转发吞吐已有提升。客户端、手机网络、节点和目标站点均可能影响速度；本次主要提供筛选与对比工具。
