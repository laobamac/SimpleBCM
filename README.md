<!--
  README.md
  SimpleBCM

  Created by laobamac on 2026/9/7.
  Copyright © 2026 laobamac. All rights reserved.
-->
<div align="center">

# SimpleBCM

![Version](https://img.shields.io/badge/version-1.2.1-2563eb)
![macOS](https://img.shields.io/badge/macOS-Sonoma%2014%20%7C%20Sequoia%2015%20%7C%20Tahoe%2026-111827)
![Architecture](https://img.shields.io/badge/arch-x86__64-6b7280)
![OpenCore](https://img.shields.io/badge/boot-OpenCore-16a34a)

**简体中文** · [English](README.en.md)

</div>

SimpleBCM 通过 OpenCore 注入恢复 macOS Sonoma、Sequoia 和 Tahoe 的 Broadcom Wi-Fi 支持。同一个 Kext 使用各系统原生 IOSkywalkFamily，无需修改系统卷。

1.2.1 修复部分 CN 地区记录在 36–48 信道下无法协商 80 MHz 的问题，保留原生睡眠恢复行为。覆盖范围和实现见 [无线地区策略](Docs/Radio-Policy.md)。

## 安装

1. 将 `SimpleBCM.kext` 放入 `EFI/OC/Kexts`，替换旧版本。
2. 禁用 IOSkywalkFamily、IO80211FamilyLegacy、AirPortBrcmNIC 的独立 Add 项。
3. 合入包内 `config.fragment.plist`，用 `ocvalidate` 检查后重启。

**删除或禁用已有的 `com.apple.iokit.IOSkywalkFamily` 的 `Kernel → Block` 规则，保持系统原生 IOSkywalkFamily 和 IO80211Family 启用。**

支持 macOS Sonoma 14、Sequoia 15 和 Tahoe 26，不限制系统小版本。使用 `MinKernel=23.0.0`、`MaxKernel=25.99.99`。

需要 AirportBrcmFixup 时，按 `Extra/config.AirportBrcmFixup.fragment.plist` 添加 Lilu、AirportBrcmFixup 和 AirPortBrcmNIC_Injector。

## 调试

使用 DEBUG 包，在解压目录运行：

```sh
./Extra/bcmprobe
./Extra/bcmprobe --scan
python3 Extra/collect.py
```

## 构建

需要完整 Xcode 和 Intel Mac。ABI 参考数据随源码提供，CI 使用 GitHub 托管的 `macos-26-intel`。详见[构建与 CI](Docs/Build.md)。

```sh
python3 Tools/bootstrap.py
python3 Tools/build.py build --configuration Debug
python3 Tools/build.py build --configuration Release
python3 Tools/build.py analyze --configuration Release
python3 Tools/build.py package --configuration Debug
python3 Tools/build.py package --configuration Release
```

Xcode 工程：`SimpleBCM.xcodeproj`。产物目录：`dist`。

[实现说明](Docs/Native-Universal.md) · [第三方许可](NOTICE.md)
