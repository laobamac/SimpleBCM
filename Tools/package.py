#!/usr/bin/env python3
#
#  package.py
#  SimpleBCM
#
#  Created by laobamac on 2026/9/13.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from configure import AIRPORT_ORIGINAL, AIRPORT_TAHOE, FIXUP, INJECTOR, SYSTEMS, fragment, save


ROOT = Path(__file__).resolve().parent.parent
VERSION = "1.0.1"
CONFIGURATIONS = ("Debug", "Release")


def variants():
    return [(system, configuration) for system in SYSTEMS for configuration in CONFIGURATIONS]


def source_revision(sha=None):
    sha = sha or os.environ.get("GITHUB_SHA") or subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
        raise ValueError("Invalid commit SHA")
    return sha.lower()


def package_name(system, configuration, channel, sha=None):
    if system not in SYSTEMS or configuration not in CONFIGURATIONS or channel not in ("pre", "rel"):
        raise ValueError("Invalid package variant")
    name = f"SimpleBCM-{system}-v{VERSION}-{configuration.upper()}"
    return f"{name}-alpha-{source_revision(sha)[:7]}" if channel == "pre" else name


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def copy(source, target, exclude=()):
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, target, ignore=shutil.ignore_patterns(
            ".DS_Store", "__pycache__", "xcuserdata", *exclude))
    else:
        shutil.copy2(source, target)


def validate_builds():
    from bootstrap import validate_payloads
    from macho import Image
    from verify import source_fingerprint

    version = re.search(r"^MODULE_VERSION\s*=\s*(\S+)", (ROOT / "Config/Kernel.xcconfig").read_text(), re.M).group(1)
    if version != VERSION:
        raise RuntimeError("驱动版本与打包版本不一致。")
    validate_payloads()
    fingerprint, _ = source_fingerprint()
    lilu_digest = digest(ROOT / "build/Lilu/Release/Lilu.kext/Contents/MacOS/Lilu")
    reports = {}
    for configuration in CONFIGURATIONS:
        report = json.loads((ROOT / f"build/Validation-{configuration}.json").read_text())
        product = ROOT / f"build/DerivedData/Build/Products/{configuration}"
        binary = product / "SimpleBCM.kext/Contents/MacOS/SimpleBCM"
        info = plistlib.loads((binary.parent.parent / "Info.plist").read_bytes())
        if info["CFBundleVersion"] != VERSION or info["CFBundleShortVersionString"] != VERSION:
            raise RuntimeError(f"{configuration} 的驱动版本与发行版本不一致。")
        if report["sourceFingerprint"] != fingerprint or report["sha256"] != digest(binary):
            raise RuntimeError(f"{configuration} 尚未通过当前源码版本的验证。")
        if report["probeSHA256"] != digest(product / "bcmprobe") or report["probeMinimumMacOS"] != "14.0.0":
            raise RuntimeError(f"{configuration} 的诊断工具尚未通过 Sonoma 部署目标验证。")
        if report["liluSHA256"] != lilu_digest or report["driverLoading"] != "external":
            raise RuntimeError(f"{configuration} 的配套驱动与验证结果不一致。")
        symbols = product / "SimpleBCM.kext.dSYM/Contents/Resources/DWARF/SimpleBCM"
        if Image(symbols).uuid != report["uuid"]:
            raise RuntimeError(f"{configuration} 符号文件与已验证二进制不一致。")
        reports[configuration] = report
    analysis = json.loads((ROOT / "build/Analysis-Release.json").read_text())
    if not analysis["passed"] or analysis["sourceFingerprint"] != fingerprint or \
            analysis["logSHA256"] != digest(ROOT / "build/analyze-Release.log"):
        raise RuntimeError("Release 静态分析尚未覆盖当前源码。")
    return fingerprint, reports


def bundle_record(kexts, entry):
    bundle = kexts / entry["BundlePath"]
    info = plistlib.loads((bundle / entry["PlistPath"]).read_bytes())
    if entry["ExecutablePath"] and not (bundle / entry["ExecutablePath"]).is_file():
        raise RuntimeError(f"缺少 {entry['ExecutablePath']}")
    return {"path": entry["BundlePath"], "identifier": info["CFBundleIdentifier"], "version": info["CFBundleVersion"],
            "minKernel": entry["MinKernel"], "maxKernel": entry["MaxKernel"]}


def create_package(system, configuration, channel, sha, fingerprint, report, target_report):
    name = package_name(system, configuration, channel, sha)
    kernel = SYSTEMS[system]
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    archive = dist / (name + ".zip")
    with tempfile.TemporaryDirectory(prefix=".package-", dir=dist) as temporary:
        stage = Path(temporary) / name
        extra = stage / "Extra"
        kexts = stage / "EFI/OC/Kexts"
        product = ROOT / f"build/DerivedData/Build/Products/{configuration}"
        copy(product / "SimpleBCM.kext", kexts / "SimpleBCM.kext")
        copy(ROOT / "build/Lilu/Release/Lilu.kext", kexts / "Lilu.kext")
        binaries = ROOT / ".research/binaries"
        copy(binaries / "IOSkywalkFamily-v1.2.0/IOSkywalkFamily.kext", kexts / "IOSkywalkFamily.kext")
        copy(binaries / "IO80211FamilyLegacy-v1.0.0/IO80211FamilyLegacy.kext", kexts / "IO80211FamilyLegacy.kext",
             exclude=("PlugIns",) if system == "Tahoe" else ())
        if system == "Tahoe":
            copy(binaries / "AirPortBrcmNIC-Tahoe-v1.0.0/AirPortBrcmNIC-Tahoe.kext", kexts / "AirPortBrcmNIC-Tahoe.kext")
        optional = extra / "Optional"
        copy(binaries / "AirportBrcmFixup-v2.2.1-RELEASE/AirportBrcmFixup.kext", optional / "AirportBrcmFixup.kext",
             exclude=("AirPortBrcm4360_Injector.kext",))
        copy(product / "SimpleBCM.kext.dSYM", extra / "Symbols/SimpleBCM.kext.dSYM")
        copy(product / "bcmprobe", extra / "bcmprobe")
        for prefix in ["Validation", "DependencySymbols"]:
            filename = f"{prefix}-{configuration}.json"
            copy(ROOT / "build" / filename, extra / filename)
            if target_report:
                filename = f"{prefix}-{system}-{configuration}.json"
                copy(ROOT / "build" / filename, extra / filename)
        for filename in ["Analysis-Release.json", "analyze-Release.log", "Lilu-build.json"]:
            copy(ROOT / "build" / filename, extra / filename)
        for filename in ["README.md", "README.en.md", "NOTICE.md", "Docs"]:
            copy(ROOT / filename, extra / filename)
        for filename in ["configure.py", "preflight.py", "kernel_collection.py", "collect.py"]:
            copy(ROOT / "Tools" / filename, extra / "Tools" / filename)
        for filename, relative in {
            "Lilu-LICENSE.txt": ".research/Lilu/LICENSE.txt",
            "OCLP-LICENSE.txt": ".research/OpenCore-Legacy-Patcher/LICENSE.txt",
            "MacKernelSDK-LICENSE.txt": ".research/MacKernelSDK/LICENSE.txt",
        }.items():
            copy(ROOT / relative, extra / "Licenses" / filename)
        config = fragment(kernel=kernel)
        optional_config = fragment(airportbrcmfixup=True, kernel=kernel)
        save(stage / "config.fragment.plist", config)
        save(optional / "config.AirportBrcmFixup.fragment.plist", optional_config)
        bundles = [bundle_record(kexts, entry) for entry in config["Kernel"]["Add"]]
        optional_bundles = [bundle_record(optional, entry) for entry in optional_config["Kernel"]["Add"]
                            if entry["BundlePath"] in (FIXUP[0], INJECTOR[0])]
        manifest = {
            "copyright": "Copyright © 2026 laobamac. All rights reserved.",
            "project": "SimpleBCM", "version": VERSION, "system": system, "kernel": f"{kernel}.x",
            "configuration": configuration, "architecture": "x86_64", "channel": channel,
            "sourceRevision": sha, "sourceFingerprint": fingerprint,
            "driverSupportedKernels": [f"{major}.x" for major in SYSTEMS.values()], "driverSHA256": report["sha256"],
            "driverLoading": "external", "hardwareValidation": "pending",
            "validationEnvironment": {"OSBuild": report["OSBuild"], "validationMode": report["validationMode"]},
            "targetValidations": [target_report] if target_report else [],
            "bundles": bundles, "optionalBundles": optional_bundles,
            "files": {str(path.relative_to(stage)): digest(path) for path in sorted(stage.rglob("*")) if path.is_file()},
        }
        (extra / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        packed = Path(temporary) / archive.name
        with zipfile.ZipFile(packed, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as output:
            for path in sorted(stage.rglob("*")):
                if path.is_file():
                    output.write(path, str(Path(name) / path.relative_to(stage)))
        packed.replace(archive)
    archive.with_name(archive.name + ".sha256").write_text(f"{digest(archive)}  {archive.name}\n")
    return archive


def verify_package(archive, system, configuration, channel, sha):
    name = package_name(system, configuration, channel, sha)
    if archive.name != name + ".zip":
        raise RuntimeError("Unexpected archive name")
    if archive.with_name(archive.name + ".sha256").read_text().split() != [digest(archive), archive.name]:
        raise RuntimeError(f"Archive SHA-256 differs: {archive}")
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None:
            raise RuntimeError(f"Invalid archive: {archive}")
        names = bundle.namelist()
        assert all(path.startswith(name + "/") and ".." not in Path(path).parts for path in names)
        paths = {path.removeprefix(name + "/") for path in names}
        manifest = json.loads(bundle.read(name + "/Extra/manifest.json"))
        assert manifest["system"] == system and manifest["configuration"] == configuration
        assert manifest["channel"] == channel and manifest["sourceRevision"] == sha
        assert manifest["version"] == VERSION and manifest["driverSupportedKernels"] == [f"{major}.x" for major in SYSTEMS.values()]
        assert {path.split('/')[0] for path in paths} == {"EFI", "Extra", "config.fragment.plist"}
        assert paths == set(manifest["files"]) | {"Extra/manifest.json"} and len(paths) == len(names)
        assert not any(path.startswith("Extra/Sources/") or "/__pycache__/" in path for path in paths)
        for relative, expected in manifest["files"].items():
            assert hashlib.sha256(bundle.read(name + "/" + relative)).hexdigest() == expected, relative
        binary = "EFI/OC/Kexts/SimpleBCM.kext/Contents/MacOS/SimpleBCM"
        assert manifest["files"][binary] == manifest["driverSHA256"]
        info = plistlib.loads(bundle.read(name + "/EFI/OC/Kexts/SimpleBCM.kext/Contents/Info.plist"))
        assert info["CFBundleVersion"] == VERSION
        config = plistlib.loads(bundle.read(name + "/config.fragment.plist"))
        assert config == fragment(kernel=SYSTEMS[system])
        optional = plistlib.loads(bundle.read(name + "/Extra/Optional/config.AirportBrcmFixup.fragment.plist"))
        assert optional == fragment(True, SYSTEMS[system])
        assert len(manifest["bundles"]) == 5 and len(manifest["optionalBundles"]) == 2
        selected = AIRPORT_TAHOE if system == "Tahoe" else AIRPORT_ORIGINAL
        other = AIRPORT_ORIGINAL if system == "Tahoe" else AIRPORT_TAHOE
        assert any(entry["BundlePath"] == selected[0] for entry in config["Kernel"]["Add"])
        assert not any(path.startswith("EFI/OC/Kexts/" + other[0] + "/") for path in paths)
        for entry in config["Kernel"]["Add"]:
            prefix = "EFI/OC/Kexts/" + entry["BundlePath"] + "/"
            assert prefix + entry["PlistPath"] in paths
            assert not entry["ExecutablePath"] or prefix + entry["ExecutablePath"] in paths
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel", choices=["pre", "rel"], default="rel")
    parser.add_argument("--target-volume", type=Path, action="append", help="附带已分析系统卷的静态验证；可重复指定")
    parser.add_argument("--verify", action="store_true", help="只验证已有的六个发布包")
    args = parser.parse_args()
    sha = source_revision()
    if not args.verify:
        fingerprint, reports = validate_builds()
        target_reports = {}
        if args.target_volume:
            from audit_target import validate
            for volume in args.target_volume:
                for configuration in CONFIGURATIONS:
                    target = validate(volume, configuration)
                    target_reports[(target["system"], configuration)] = target
        for system, configuration in variants():
            create_package(system, configuration, args.channel, sha, fingerprint, reports[configuration],
                           target_reports.get((system, configuration)))
    binaries = {}
    for system, configuration in variants():
        archive = ROOT / "dist" / (package_name(system, configuration, args.channel, sha) + ".zip")
        manifest = verify_package(archive, system, configuration, args.channel, sha)
        previous = binaries.setdefault(configuration, manifest["driverSHA256"])
        assert previous == manifest["driverSHA256"], "SimpleBCM must be identical across all system packages"
        print(archive)
    print("六个包及全部文件哈希通过验证；同一构建类型的 SimpleBCM 跨系统字节一致。")


if __name__ == "__main__":
    main()
