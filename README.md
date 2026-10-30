<!--
  README.md
  SimpleBCM

  Created by laobamac on 2026/9/7.
  Copyright © 2026 laobamac. All rights reserved.
-->
<div align="center">

# SimpleBCM

**在 macOS Sequoia 和 Tahoe 上恢复 Broadcom 无线支持**

![Version](https://img.shields.io/badge/version-1.0.0-2563eb)
![macOS](https://img.shields.io/badge/macOS-Sequoia%2015%20%7C%20Tahoe%2026-111827)
![Architecture](https://img.shields.io/badge/arch-x86__64-6b7280)
![OpenCore](https://img.shields.io/badge/boot-OpenCore-16a34a)

**简体中文** · [English](README.en.md)

OpenCore 注入 · 原生无线 API · Sequoia / Tahoe

</div>

---

SimpleBCM 是一个 Lilu 插件，通过 OpenCore 独立加载配套 Broadcom 驱动，并适配 Sequoia 和 Tahoe 的无线控制和事件接口。不修改系统卷，不替换系统框架。

## 要求

| 项目 | 要求 |
| :--- | :--- |
| 系统 | macOS Sequoia / Tahoe（Darwin 24.x / 25.x） |
| 架构 | Intel x86_64 |
| 引导 | OpenCore |
| 依赖 | Lilu ≥ 1.7.1，以及包内固定版本的配套驱动 |

## 安装

1. 选择对应系统的 RELEASE 包（日常使用）或 DEBUG 包（排查问题），解压后将 `EFI/OC/Kexts` 中的驱动放入可回退的 EFI 副本；Lilu 仅保留一个启用版本。
2. 合入 `config.fragment.plist`，加载顺序为 **Lilu → SimpleBCM → IOSkywalkFamily → IO80211FamilyLegacy → 对应系统的 AirPortBrcmNIC**。
3. 对系统 `com.apple.iokit.IOSkywalkFamily` 设置 `Kernel → Block → Exclude`；配置示例已包含此项。
4. 运行 `Extra/Tools/preflight.py`，再用当前 OpenCore 版本配套的 `ocvalidate` 校验完整配置。
5. 从该 EFI 启动，使用系统 Wi-Fi 界面连接网络。

仅部分旧网卡（如 BCM943224）需要 AirportBrcmFixup 及其 NIC Injector。将 `Extra/Optional/AirportBrcmFixup.kext` 放入 `EFI/OC/Kexts`，使用 `Extra/Optional/config.AirportBrcmFixup.fragment.plist`，或在配置生成命令末尾添加 `--airportbrcmfixup`。可选示例会将 AirportBrcmFixup 放在 SimpleBCM 后，并添加 `AirPortBrcmNIC_Injector` 条目。

同一构建类型的 Sequoia、Tahoe 包使用完全相同的 SimpleBCM.kext，它始终同时支持两个系统。每个包只携带所选系统的配套 AirPort 后端：Sequoia 使用 `IO80211FamilyLegacy.kext/Contents/PlugIns/AirPortBrcmNIC.kext`，Tahoe 使用 `AirPortBrcmNIC-Tahoe.kext`。Sequoia 包须保留 Legacy 的 PlugIns 目录。

配置示例只启用包对应系统的条目。在双系统 EFI 中，分别部署两个系统的配套驱动；同名 SimpleBCM 和共享驱动保留一份。生成配置时保留另一系统的既有条目。

发行包根目录为：

```text
EFI/                    对应系统的配套驱动和所选构建的 SimpleBCM
config.fragment.plist   对应系统的配置示例
Extra/                  文档、工具、当前构建符号、验证报告及可选驱动
```

<details>
<summary>生成配置副本与启动前检查</summary>

从解压后的发行包目录执行：

```sh
python3 Extra/Tools/configure.py /Volumes/USB/EFI/OC/config.plist --output /Volumes/USB/EFI/OC/config.SimpleBCM.plist
```

生成器要求输入配置已有唯一启用的 Lilu，只输出单独副本。它会补齐独立驱动条目、处理旧配置中的重复项，并保留原有启动参数。旧网卡可添加 `--airportbrcmfixup`。包内工具自动读取 manifest 选择系统，只更新该系统范围，并保留已有的另一系统配置。从源码运行工具时，可用 `--system Sequoia` 或 `--system Tahoe` 指定系统；省略则生成双系统配置。审阅后将副本用作 USB EFI 的 `config.plist`，再执行：

```sh
python3 Extra/Tools/preflight.py /Volumes/USB/EFI/OC --manifest Extra/manifest.json
```

preflight 检查目标系统版本范围、加载顺序、Lilu 最低版本、重复或冲突的驱动及实际文件。`--manifest` 额外核对 SimpleBCM、配套驱动和已启用的可选 AirportBrcmFixup 文件哈希，允许使用现有的 Lilu ≥ 1.7.1。可用 `--target-volume "/Volumes/Macintosh HD 1"` 检查待启动的系统卷；省略时检查运行中的系统。运行时按 Darwin 主版本选择 ABI，并验证载荷字节。

</details>

## 启动参数

| 参数 | 用途 |
| :--- | :--- |
| `-simplebcmoff` | 停用驱动 |
| `-simplebcmdbg` | 开启 Debug 版本日志 |

Release 保留基本状态计数，命令错误明细仅在 Debug 记录。

## 状态与诊断

```sh
./Extra/bcmprobe
python3 Extra/Tools/collect.py
```

`Extra/bcmprobe` 默认查询 CoreWLAN 和 IORegistry，不输出 SSID、BSSID 或密码；`./Extra/bcmprobe --scan` 会实际发起扫描。采集脚本按需保存驱动、客户端、awdl0 状态和相关系统日志，无常驻监听。

`ActiveABI` 显示当前 Sequoia/Tahoe 配置，`AirPortBackend` 显示 Original/Tahoe。`PatchState=7` 与 `Status=ReadyForHardwareValidation` 表示接口挂接完成，联网状态以实际连接为准。`Commands`、`Events`、`Notifications`、`LastRequest` 和 `LastResult` 保留真实计数与返回码。

## 构建

需要完整 Xcode、Git 和 Python 3，实际使用的工具链为 Xcode 26.5 / 17F42。

```sh
python3 Tools/build.py --configuration Debug
python3 Tools/build.py --configuration Release
python3 Tools/build.py --configuration Release --analyze
python3 Tools/package.py
```

## 致谢

[Lilu](https://github.com/acidanthera/Lilu) · [MacKernelSDK](https://github.com/acidanthera/MacKernelSDK) · [OpenCore Legacy Patcher](https://github.com/dortania/OpenCore-Legacy-Patcher) · [PatcherSupportPkg](https://github.com/dortania/PatcherSupportPkg) · [Apple XNU](https://github.com/apple-oss-distributions/xnu)

第三方组件及许可见 [NOTICE](NOTICE.md)，发行包 `Extra/Licenses` 目录附有 Lilu、OCLP 和 MacKernelSDK 许可。

<div align="center">

Copyright © 2026 **laobamac**. All rights reserved.

</div>
