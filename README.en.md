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

## Installation

1. Place `SimpleBCM.kext` in `EFI/OC/Kexts`, replacing the previous version.
2. Disable the separate Add entries for IOSkywalkFamily, IO80211FamilyLegacy and AirPortBrcmNIC.
3. Merge the packaged `config.fragment.plist`, check with `ocvalidate`, then reboot.

**Required `Kernel → Block` entry: `Identifier=com.apple.iokit.IOSkywalkFamily`, `Strategy=Exclude`, `Enabled=true`.**

If AirportBrcmFixup is needed, add Lilu, AirportBrcmFixup and AirPortBrcmNIC_Injector using `Extra/config.AirportBrcmFixup.fragment.plist`.

## Debugging

Use DEBUG with the `-simplebcmdbg` boot argument. Run from the extracted package directory:

```sh
./Extra/bcmprobe
python3 Extra/collect.py
```

## Building

```sh
python3 Tools/bootstrap.py --standalone
python3 Tools/standalone.py build --configuration Debug
python3 Tools/standalone.py build --configuration Release
python3 Tools/standalone.py analyze --configuration Release
python3 Tools/standalone.py package --configuration Debug
python3 Tools/standalone.py package --configuration Release
```

Xcode project: `SimpleBCMStandalone.xcodeproj`. Output: `dist`.

[Third-party licenses](NOTICE.md)
