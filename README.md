<!--
  README.md
  SimpleBCM

  Created by laobamac on 2026/9/7.
  Copyright © 2026 laobamac. All rights reserved.
-->
<div align="center">

# SimpleBCM

![Version](https://img.shields.io/badge/version-1.0.1-2563eb)
![macOS](https://img.shields.io/badge/macOS-Sonoma%2014%20%7C%20Sequoia%2015%20%7C%20Tahoe%2026-111827)
![Architecture](https://img.shields.io/badge/arch-x86__64-6b7280)
![OpenCore](https://img.shields.io/badge/boot-OpenCore-16a34a)

**简体中文** · [English](README.en.md)

</div>

通过 OpenCore 注入恢复 Broadcom Wi-Fi，不修改系统卷。支持 Intel 平台的 macOS Sonoma 14、Sequoia 15 和 Tahoe 26，依赖 Lilu ≥ 1.7.1。

## 安装

1. 下载对应系统的 [RELEASE 包](https://github.com/laobamac/SimpleBCM/releases)。
2. 将包内驱动合入 `EFI/OC/Kexts`，保留完整目录结构；Lilu 只启用一份。
3. 合入 `config.fragment.plist`，其中已包含 `IOSkywalkFamily` 的 `Kernel → Block → Exclude` 配置。
4. 用当前 OpenCore 配套的 `ocvalidate` 检查完整配置，然后重启。

加载顺序：**Lilu → SimpleBCM → IOSkywalkFamily → IO80211FamilyLegacy → AirPortBrcmNIC**。

BCM943224 等旧卡另需将 `Extra/Optional/AirportBrcmFixup.kext` 复制到 `EFI/OC/Kexts`，并改用 `Extra/Optional/config.AirportBrcmFixup.fragment.plist`。

## 排查问题

使用 DEBUG 包并添加 `-simplebcmdbg` 开启日志；`-simplebcmoff` 可停用驱动。在解压包根目录执行：

```sh
./Extra/bcmprobe
python3 Extra/Tools/collect.py
```

## 构建

需要完整 Xcode、Git 和 Python 3。

```sh
python3 Tools/build.py --configuration Debug
python3 Tools/build.py --configuration Release
python3 Tools/build.py --configuration Release --analyze
python3 Tools/package.py
```

第三方组件、致谢及许可见 [NOTICE](NOTICE.md)。
