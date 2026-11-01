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

## 安装

1. 将 `SimpleBCM.kext` 放入 `EFI/OC/Kexts`，替换旧版本。
2. 禁用 IOSkywalkFamily、IO80211FamilyLegacy、AirPortBrcmNIC 的独立 Add 项。
3. 合入包内 `config.fragment.plist`，用 `ocvalidate` 检查后重启。

**必须启用 `Kernel → Block`：`Identifier=com.apple.iokit.IOSkywalkFamily`、`Strategy=Exclude`、`Enabled=true`。**

需要 AirportBrcmFixup 时，按 `Extra/config.AirportBrcmFixup.fragment.plist` 添加 Lilu、AirportBrcmFixup 和 AirPortBrcmNIC_Injector。

## 调试

使用 DEBUG 包，添加启动参数 `-simplebcmdbg`，在解压目录运行：

```sh
./Extra/bcmprobe
python3 Extra/collect.py
```

## 构建

```sh
python3 Tools/bootstrap.py
python3 Tools/build.py build --configuration Debug
python3 Tools/build.py build --configuration Release
python3 Tools/build.py analyze --configuration Release
python3 Tools/build.py package --configuration Debug
python3 Tools/build.py package --configuration Release
```

Xcode 工程：`SimpleBCM.xcodeproj`。产物目录：`dist`。

[第三方许可](NOTICE.md)
