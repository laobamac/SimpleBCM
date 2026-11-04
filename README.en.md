<!--
  README.en.md
  SimpleBCM

  Created by laobamac on 2026/9/17.
  Copyright © 2026 laobamac. All rights reserved.
-->
<div align="center">

# SimpleBCM

![Version](https://img.shields.io/badge/version-1.2.1-2563eb)
![macOS](https://img.shields.io/badge/macOS-Sonoma%2014%20%7C%20Sequoia%2015%20%7C%20Tahoe%2026-111827)
![Architecture](https://img.shields.io/badge/arch-x86__64-6b7280)
![OpenCore](https://img.shields.io/badge/boot-OpenCore-16a34a)

[简体中文](README.md) · **English**

</div>

SimpleBCM restores Broadcom Wi-Fi on macOS Sonoma, Sequoia and Tahoe through OpenCore injection. One kext uses each system’s native IOSkywalkFamily without modifying the system volume.

## Installation

1. Place `SimpleBCM.kext` in `EFI/OC/Kexts`, replacing the previous version.
2. Disable the separate Add entries for IOSkywalkFamily, IO80211FamilyLegacy and AirPortBrcmNIC.
3. Merge the packaged `config.fragment.plist`, check with `ocvalidate`, then reboot.

**Remove or disable existing `Kernel → Block` rules for `com.apple.iokit.IOSkywalkFamily`. Keep native IOSkywalkFamily and IO80211Family enabled.**

Supports macOS Sonoma 14, Sequoia 15 and Tahoe 26 without restricting minor versions. Use `MinKernel=23.0.0` and `MaxKernel=25.99.99`.

If AirportBrcmFixup is needed, add Lilu, AirportBrcmFixup and AirPortBrcmNIC_Injector using `Extra/config.AirportBrcmFixup.fragment.plist`.

## Debugging

Use the DEBUG package. Run from the extracted package directory:

```sh
./Extra/bcmprobe
./Extra/bcmprobe --scan
python3 Extra/collect.py
```

## Building

Requires full Xcode and an Intel Mac. ABI reference data is included in the source; CI uses GitHub-hosted `macos-26-intel`. See [Build and CI](Docs/Build.md).

```sh
python3 Tools/bootstrap.py
python3 Tools/build.py build --configuration Debug
python3 Tools/build.py build --configuration Release
python3 Tools/build.py analyze --configuration Release
python3 Tools/build.py package --configuration Debug
python3 Tools/build.py package --configuration Release
```

Xcode project: `SimpleBCM.xcodeproj`. Output: `dist`.

[Implementation](Docs/Native-Universal.md) · [Third-party licenses](NOTICE.md)
