<!--
  README.en.md
  SimpleBCM

  Created by laobamac on 2026/9/17.
  Copyright © 2026 laobamac. All rights reserved.
-->
<div align="center">

# SimpleBCM

**Restore Broadcom Wi-Fi support on macOS Sequoia and Tahoe**

![Version](https://img.shields.io/badge/version-1.0.0-2563eb)
![macOS](https://img.shields.io/badge/macOS-Sequoia%2015%20%7C%20Tahoe%2026-111827)
![Architecture](https://img.shields.io/badge/arch-x86__64-6b7280)
![OpenCore](https://img.shields.io/badge/boot-OpenCore-16a34a)

[简体中文](README.md) · **English**

OpenCore injection · Native wireless APIs · Sequoia / Tahoe

</div>

---

SimpleBCM is a Lilu plug-in that adapts the wireless control and event interfaces of companion Broadcom drivers to Sequoia and Tahoe. Each driver loads separately through OpenCore. It does not modify the system volume or replace system frameworks.

## Requirements

| Item | Requirement |
| :--- | :--- |
| System | macOS Sequoia / Tahoe (Darwin 24.x / 25.x) |
| Architecture | Intel x86_64 |
| Bootloader | OpenCore |
| Dependencies | Lilu ≥ 1.7.1 and the pinned companion drivers in the package |

## Installation

1. Choose the RELEASE package for your OS for daily use, or DEBUG for troubleshooting. Extract it and copy the drivers from `EFI/OC/Kexts` into an EFI copy you can roll back. Keep exactly one enabled Lilu version.
2. Merge `config.fragment.plist`. Load in this order: **Lilu → SimpleBCM → IOSkywalkFamily → IO80211FamilyLegacy → AirPortBrcmNIC for the selected OS**.
3. Add a `Kernel → Block → Exclude` entry for the system `com.apple.iokit.IOSkywalkFamily`. The configuration example includes this setting.
4. Run `Extra/Tools/preflight.py`, then validate the complete configuration with `ocvalidate` from your OpenCore version.
5. Boot from that EFI and connect using the system Wi-Fi interface.

Only some older cards, such as BCM943224, need AirportBrcmFixup and its NIC Injector. Copy `Extra/Optional/AirportBrcmFixup.kext` to `EFI/OC/Kexts`, then use `Extra/Optional/config.AirportBrcmFixup.fragment.plist` or append `--airportbrcmfixup` to the configuration command. The optional example loads AirportBrcmFixup after SimpleBCM and adds the `AirPortBrcmNIC_Injector` entry.

Sequoia and Tahoe packages of the same build type contain byte-identical SimpleBCM.kext binaries. SimpleBCM always supports both operating systems. Each package includes only its matching AirPort backend: Sequoia uses `IO80211FamilyLegacy.kext/Contents/PlugIns/AirPortBrcmNIC.kext`; Tahoe uses `AirPortBrcmNIC-Tahoe.kext`. Retain the Legacy PlugIns directory from the Sequoia package.

Each configuration example targets its package's OS. For a dual-boot EFI, install both sets of companion drivers and keep one copy of SimpleBCM and shared drivers. Configuration migration preserves existing entries for the other OS.

The package root contains:

```text
EFI/                    OS-specific companion drivers and the selected SimpleBCM build
config.fragment.plist   Configuration for the selected OS
Extra/                  Documentation, tools, matching symbols, reports, optional drivers
```

<details>
<summary>Generate a configuration copy and run preflight checks</summary>

Run from the extracted package directory:

```sh
python3 Extra/Tools/configure.py /Volumes/USB/EFI/OC/config.plist --output /Volumes/USB/EFI/OC/config.SimpleBCM.plist
```

The generator requires exactly one enabled Lilu entry and writes a separate configuration copy. It adds the individual driver entries, handles duplicate entries from older configurations, and preserves existing boot arguments. For older cards, append `--airportbrcmfixup`. Packaged tools select the OS from the manifest and preserve the other OS configuration. When running from source, use `--system Sequoia` or `--system Tahoe`; omitting the option generates a dual-system configuration. Review the copy, use it as the USB EFI's `config.plist`, then run:

```sh
python3 Extra/Tools/preflight.py /Volumes/USB/EFI/OC --manifest Extra/manifest.json
```

Preflight checks the target kernel range, load order, minimum Lilu version, duplicate or conflicting drivers, and actual files. `--manifest` also checks file hashes for SimpleBCM, its companion drivers, and an enabled optional AirportBrcmFixup. You can retain your existing Lilu ≥ 1.7.1. Use `--target-volume "/Volumes/Macintosh HD 1"` to inspect an offline system volume; the default checks the running system. Runtime selection uses the Darwin major version and validates payload bytes.

</details>

## Boot arguments

| Argument | Purpose |
| :--- | :--- |
| `-simplebcmoff` | Disable the driver |
| `-simplebcmdbg` | Enable Debug build logging |

Release retains basic status counters. Detailed command errors are logged only in Debug builds.

## Status and diagnostics

```sh
./Extra/bcmprobe
python3 Extra/Tools/collect.py
```

By default, `Extra/bcmprobe` queries CoreWLAN and IORegistry without printing SSIDs, BSSIDs, or passwords. `./Extra/bcmprobe --scan` actively starts a scan. The collector saves driver, client, awdl0, and related system log information on demand, with no persistent listener.

`ActiveABI` identifies Sequoia/Tahoe; `AirPortBackend` identifies Original/Tahoe. `PatchState=7` and `Status=ReadyForHardwareValidation` indicate that interface hooks are installed. Confirm connectivity through actual use. `Commands`, `Events`, `Notifications`, `LastRequest`, and `LastResult` retain real counts and return codes.

## Building

Requires full Xcode, Git, and Python 3. The validated toolchain is Xcode 26.5 / 17F42.

```sh
python3 Tools/build.py --configuration Debug
python3 Tools/build.py --configuration Release
python3 Tools/build.py --configuration Release --analyze
python3 Tools/package.py
```

## Credits

[Lilu](https://github.com/acidanthera/Lilu) · [MacKernelSDK](https://github.com/acidanthera/MacKernelSDK) · [OpenCore Legacy Patcher](https://github.com/dortania/OpenCore-Legacy-Patcher) · [PatcherSupportPkg](https://github.com/dortania/PatcherSupportPkg) · [Apple XNU](https://github.com/apple-oss-distributions/xnu)

See [NOTICE](NOTICE.md) for third-party components and licenses. The package's `Extra/Licenses` directory includes the Lilu, OCLP, and MacKernelSDK licenses.

<div align="center">

Copyright © 2026 **laobamac**. All rights reserved.

</div>
