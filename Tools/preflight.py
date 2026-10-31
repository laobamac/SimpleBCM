#!/usr/bin/env python3
#
#  preflight.py
#  SimpleBCM
#
#  Created by laobamac on 2026/9/3.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import hashlib
import json
import plistlib
import subprocess
from pathlib import Path

from configure import AIRPORT_ORIGINAL, AIRPORT_TAHOE, CONFLICTING_DRIVERS, FIXUP, INJECTOR, SYSTEMS, drivers


def version(value):
    parts = tuple(int(x) for x in value.split('.'))
    return parts + (0,) * (3 - len(parts))


def enabled(entry, running):
    return entry.get("Enabled") and entry.get("Arch", "Any") in ("Any", "x86_64") and \
        (not entry.get("MinKernel") or version(entry["MinKernel"]) <= running) and \
        (not entry.get("MaxKernel") or version(entry["MaxKernel"]) >= running)


def check_configuration(oc, running, manifest=None):
    issues = []
    if running[0] not in (23, 24, 25):
        issues.append("要求 macOS Sonoma、Sequoia 或 Tahoe / Darwin 23.x、24.x 或 25.x。")
    config = plistlib.loads((oc / "config.plist").read_bytes())
    entries = [entry for entry in config["Kernel"]["Add"] if enabled(entry, running)]
    use_fixup = any(entry.get("BundlePath") == FIXUP[0] for entry in entries)
    expected = drivers(use_fixup, running[0])
    positions = {}
    for bundle, identifier, executable, _ in expected:
        matching = [(i, entry) for i, entry in enumerate(entries) if
                    (Path(entry.get("BundlePath", "")).name == bundle if bundle == "Lilu.kext" else entry.get("BundlePath") == bundle)]
        if len(matching) != 1:
            issues.append(f"需要唯一启用项：{bundle}")
            continue
        position, entry = matching[0]
        positions[bundle] = position
        if entry.get("ExecutablePath") != (f"Contents/MacOS/{executable}" if executable else "") or entry.get("PlistPath") != "Contents/Info.plist":
            issues.append(f"{bundle} 的 ExecutablePath / PlistPath 不正确。")
            continue
        path = oc / "Kexts" / entry["BundlePath"]
        try:
            info = plistlib.loads((path / "Contents/Info.plist").read_bytes())
            if info["CFBundleIdentifier"] != identifier:
                issues.append(f"{bundle} 的标识不匹配。")
            if bundle == "Lilu.kext" and version(info["CFBundleVersion"]) < version("1.7.1"):
                issues.append("Lilu 要求 1.7.1 或更新。")
            if executable and not (path / entry["ExecutablePath"]).is_file():
                issues.append(f"缺少可执行文件：{bundle}")
        except (OSError, KeyError, ValueError, plistlib.InvalidFileException) as error:
            issues.append(f"无法核对 {bundle}：{error}")
    ordered = [positions[bundle] for bundle, *_ in expected if bundle in positions]
    if ordered != sorted(ordered):
        issues.append("无线驱动加载顺序不正确，请参考 config.fragment.plist。")
    identifiers = {identifier: [] for _, identifier, _, _ in expected}
    for entry in entries:
        path = entry.get("BundlePath", "")
        try:
            info = plistlib.loads((oc / 'Kexts' / path / entry.get('PlistPath', 'Contents/Info.plist')).read_bytes())
            identifier = info.get('CFBundleIdentifier')
            if identifier in identifiers:
                identifiers[identifier].append(path)
        except (OSError, ValueError, plistlib.InvalidFileException):
            pass
        if Path(path).name in CONFLICTING_DRIVERS or (
                Path(path).name == "AirPortBrcmNIC.kext" and path != AIRPORT_ORIGINAL[0]) or (
                path in (AIRPORT_ORIGINAL[0], AIRPORT_TAHOE[0]) and path not in {item[0] for item in expected}):
            issues.append(f"此项与目标系统的 AirPort 后端冲突：{path}")
        if path == INJECTOR[0] and not use_fixup:
            issues.append("NIC Injector 必须与可选 AirportBrcmFixup 一起启用。")
    for identifier, paths in identifiers.items():
        if len(paths) > 1:
            issues.append(f"重复的活动 Bundle ID：{identifier}: {paths}")
    blocks = [entry for entry in config["Kernel"].get("Block", []) if enabled(entry, running)
              and entry.get("Identifier") == "com.apple.iokit.IOSkywalkFamily" and entry.get("Strategy") == "Exclude"]
    if len(blocks) != 1:
        issues.append("需要一项 IOSkywalkFamily / Exclude 屏蔽。")
    if manifest:
        data = json.loads(Path(manifest).read_text())
        if data.get('system') in SYSTEMS and SYSTEMS[data['system']] != running[0]:
            issues.append(f"发布包面向 {data['system']}，与目标系统不匹配。")
        active_bundles = {Path(bundle).parts[0] for bundle, *_ in expected if bundle != "Lilu.kext"}
        for relative, digest in data['files'].items():
            if relative.startswith('EFI/OC/Kexts/'):
                local = Path(relative.removeprefix('EFI/OC/Kexts/'))
                if local.parts[0] not in active_bundles:
                    continue
                target = oc / 'Kexts' / local
            elif use_fixup and relative.startswith('Extra/Optional/AirportBrcmFixup.kext/'):
                target = oc / 'Kexts' / relative.removeprefix('Extra/Optional/')
            else:
                continue
            if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                issues.append(f"注入文件 SHA-256 不匹配：{target}")
    return issues, use_fixup


def check(oc, manifest, target_volume=None):
    build = subprocess.check_output(["sysctl", "-n", "kern.osversion"], text=True).strip()
    kernel = subprocess.check_output(["sysctl", "-n", "kern.osrelease"], text=True).strip()
    target = Path(target_volume).resolve() if target_volume else Path('/')
    if target_volume:
        from kernel_collection import system_version
        build, kernel = system_version(target)
    issues, use_fixup = check_configuration(oc, version(kernel), manifest)
    if (target / 'System/Library/Extensions/IO80211FamilyLegacy.kext').exists():
        issues.append("系统卷已有 Legacy 无线根补丁，会与 EFI 注入的驱动重复。")
    return dict(build=build, kernel=kernel, targetVolume=str(target), airportbrcmfixup=use_fixup, passed=not issues, issues=issues)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("oc", type=Path, help="待启动 EFI 的 OC 目录")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--target-volume", type=Path, help="只读检查待启动系统卷；省略时检查运行中的系统")
    args = parser.parse_args()
    result = check(args.oc.resolve(), args.manifest, args.target_volume)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == '__main__':
    main()
