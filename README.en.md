<!--
  README.en.md
  SimpleBCM

  Created by laobamac on 2026/9/17.
  Copyright © 2026 laobamac. All rights reserved.
-->
<div align="center">

# SimpleBCM

![Version](https://img.shields.io/badge/version-1.0.1-2563eb)
![macOS](https://img.shields.io/badge/macOS-Sonoma%2014%20%7C%20Sequoia%2015%20%7C%20Tahoe%2026-111827)
![Architecture](https://img.shields.io/badge/arch-x86__64-6b7280)
![OpenCore](https://img.shields.io/badge/boot-OpenCore-16a34a)

[简体中文](README.md) · **English**

</div>

Restore Broadcom Wi-Fi through OpenCore injection without modifying the system volume. Supports macOS Sonoma 14, Sequoia 15 and Tahoe 26 on Intel. Requires Lilu ≥ 1.7.1.

## Installation

1. Download the [RELEASE package](https://github.com/laobamac/SimpleBCM/releases) for your macOS version.
2. Merge the packaged kexts into `EFI/OC/Kexts`, preserving the full directory structure. Enable only one copy of Lilu.
3. Merge `config.fragment.plist`, which includes the `Kernel → Block → Exclude` entry for `IOSkywalkFamily`.
4. Check the complete configuration with `ocvalidate` from your OpenCore version, then reboot.

Load order: **Lilu → SimpleBCM → IOSkywalkFamily → IO80211FamilyLegacy → AirPortBrcmNIC**.

Older cards such as BCM943224 also need `Extra/Optional/AirportBrcmFixup.kext` copied to `EFI/OC/Kexts`. Use `config.AirportBrcmFixup.fragment.plist` from the same Optional directory instead.

## Troubleshooting

Use the DEBUG package with `-simplebcmdbg` for logs; `-simplebcmoff` disables the driver. Run from the extracted package root:

```sh
./Extra/bcmprobe
python3 Extra/Tools/collect.py
```

## Building

Requires full Xcode, Git and Python 3.

```sh
python3 Tools/build.py --configuration Debug
python3 Tools/build.py --configuration Release
python3 Tools/build.py --configuration Release --analyze
python3 Tools/package.py
```

See [NOTICE](NOTICE.md) for third-party components, credits and licenses.
