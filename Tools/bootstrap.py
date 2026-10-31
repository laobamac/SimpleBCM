#!/usr/bin/env python3
#
#  bootstrap.py
#  SimpleBCM
#
#  Created by laobamac on 2026/9/25.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import hashlib
import subprocess
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REPOSITORIES = {
    "Lilu": ("https://github.com/acidanthera/Lilu.git", "dc01cb583295ceded4f42a6310a15e3abac1c025",
             ["/Lilu/Headers/", "/Lilu/Library/", "/Lilu/Sources/", "/Lilu/PrivateHeaders/", "/Lilu/Info.plist", "/Lilu.xcodeproj/",
              "/hde/", "/capstone/", "/lzvn/", "/sha256/", "/umm_malloc/", "/LICENSE.txt"]),
    "MacKernelSDK": ("https://github.com/acidanthera/MacKernelSDK.git", "3f750085caa17ec3a7880f11c11bf4f48cd6a164",
                     ["/Headers/", "/Library/x86_64/", "/Library/universal/", "/LICENSE.txt"]),
    "OpenCore-Legacy-Patcher": ("https://github.com/dortania/OpenCore-Legacy-Patcher.git", "8da38565fa1551a8e5ce8613ea835d04dd97e089",
                               ["/payloads/Kexts/Wifi/IOSkywalkFamily-v1.2.0.zip", "/payloads/Kexts/Wifi/IO80211FamilyLegacy-v1.0.0.zip",
                                "/payloads/Kexts/Wifi/AirPortBrcmNIC-Tahoe-v1.0.0.zip", "/payloads/Kexts/Acidanthera/AirportBrcmFixup-v2.2.1-RELEASE.zip",
                                "/LICENSE.txt"]),
}
ARCHIVES = {
    "Wifi/IOSkywalkFamily-v1.2.0.zip": "1e12b7ef42f55b39ea54ada97b46331220668b2c48a28656e9875c5145fe2479",
    "Wifi/IO80211FamilyLegacy-v1.0.0.zip": "e681dcc76a2cd2cea4b0ad5f27a3c816055fde3cdccd890dd10a3e2c84e96d93",
    "Wifi/AirPortBrcmNIC-Tahoe-v1.0.0.zip": "04edd7127ce096f5de9f8112af6d06744f27e5bc659e3d6516408755cb9af032",
    "Acidanthera/AirportBrcmFixup-v2.2.1-RELEASE.zip": "6dbac239702afdd5425289b97056da1bc3552e662f66bbe28a66eade2c81842f",
}


def git(folder, *args):
    return subprocess.check_output(["git", "-C", str(folder), *args], text=True).strip()


def validate_payloads(extract=False, include_optional=True):
    for relative, digest in ARCHIVES.items():
        if not include_optional and relative.startswith('Acidanthera/'):
            continue
        archive = ROOT / ".research/OpenCore-Legacy-Patcher/payloads/Kexts" / relative
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"归档校验失败：{archive}")
        destination = ROOT / ".research/binaries" / archive.stem
        with zipfile.ZipFile(archive) as bundle:
            for item in bundle.infolist():
                if ".." in Path(item.filename).parts or item.filename.startswith("/"):
                    raise RuntimeError("非法归档路径")
                if item.is_dir() or "__MACOSX" in Path(item.filename).parts:
                    continue
                target = destination / item.filename
                original = bundle.read(item)
                if extract and not target.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(original)
                if not target.is_file() or target.read_bytes() != original:
                    raise RuntimeError(f"解包文件与固定归档不一致：{target}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--standalone', action='store_true')
    args = parser.parse_args()
    research = ROOT / ".research"
    research.mkdir(exist_ok=True)
    for name, (url, revision, sparse) in REPOSITORIES.items():
        if args.standalone and name == 'Lilu':
            continue
        if args.standalone:
            sparse = [entry for entry in sparse if '/Acidanthera/' not in entry]
        path = research / name
        if not path.exists():
            print(f"获取构建所需上游：{url} @ {revision}", flush=True)
            subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", "--depth=1", url, str(path)], check=True)
            subprocess.run(["git", "-C", str(path), "fetch", "--depth=1", "origin", revision], check=True)
            subprocess.run(["git", "-C", str(path), "sparse-checkout", "set", "--no-cone", "--stdin"], input="\n".join(sparse), text=True, check=True)
            subprocess.run(["git", "-C", str(path), "checkout", "--detach", revision], check=True)
        if git(path, "rev-parse", "HEAD") != revision:
            raise RuntimeError(f"上游版本不匹配：{path}")
        if git(path, "status", "--porcelain", "--untracked-files=no"):
            raise RuntimeError(f"上游工作树已修改：{path}")
        subprocess.run(["git", "-C", str(path), "sparse-checkout", "set", "--no-cone", "--stdin"], input="\n".join(sparse), text=True, check=True)
    validate_payloads(extract=True, include_optional=not args.standalone)
    print("所需上游提交、驱动归档及解包文件的逐字节校验通过。")


if __name__ == "__main__":
    main()
