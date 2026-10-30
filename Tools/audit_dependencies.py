#!/usr/bin/env python3
#
#  audit_dependencies.py
#  SimpleBCM
#
#  Created by laobamac on 2026/9/10.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import hashlib
import json
import plistlib
import struct
import subprocess
from pathlib import Path

from bootstrap import validate_payloads
from macho import Image
from kernel_collection import KernelCollection
from profiles import IMAGES, relocations


ROOT = Path(__file__).resolve().parent.parent


def nm(path, *options):
    return subprocess.check_output(["nm", *options, str(path)], text=True).splitlines()


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def audit(configuration, volume=Path('/'), output=None):
    validate_payloads()
    collection = KernelCollection(Path(volume) / 'System/Library/KernelCollections/BootKernelExtensions.kc')
    running = int(collection.version().split('.')[0])
    require(running in (24, 25), 'Unsupported target kernel')
    paths = {name: path for name, path in IMAGES.items() if name != 'AirPortSequoia'}
    if running == 24:
        paths['AirPort'] = IMAGES['AirPortSequoia']
    paths["AirportBrcmFixup"] = ROOT / ".research/binaries/AirportBrcmFixup-v2.2.1-RELEASE/AirportBrcmFixup.kext/Contents/MacOS/AirportBrcmFixup"
    paths["Lilu"] = ROOT / "build/Lilu/Release/Lilu.kext/Contents/MacOS/Lilu"
    paths["SimpleBCM"] = ROOT / f"build/DerivedData/Build/Products/{configuration}/SimpleBCM.kext/Contents/MacOS/SimpleBCM"
    images = {name: Image(path) for name, path in paths.items()}
    providers = {'com.apple.kernel'}
    for path in paths.values():
        libraries = plistlib.loads((path.parent.parent / 'Info.plist').read_bytes())['OSBundleLibraries']
        providers.update(name for name in libraries if name in collection.images and
                         name not in ('com.apple.iokit.IO80211Family', 'com.apple.iokit.IOSkywalkFamily',
                                      'com.apple.iokit.IO80211FamilyLegacy', 'com.apple.driver.AirPort.BrcmNIC'))
    available = set().union(*(collection.images[name].exports for name in providers))
    imports = {}
    for name, path in paths.items():
        available.update(nm(path, "-g", "-j", "-U"))
        imports[name] = set(nm(path, "-u", "-j"))
    missing = {name: names - available for name, names in imports.items()}
    aliases = [
        (0xA70, "__ZN26IOSkywalkEthernetInterface18getHardwareAddressEP12ether_addr_t", "__ZN26IOSkywalkEthernetInterface18getHardwareAddressEP10ether_addr"),
        (0xA80, "__ZN26IOSkywalkEthernetInterface19setLinkLayerAddressEP12ether_addr_t", "__ZN26IOSkywalkEthernetInterface19setLinkLayerAddressEP10ether_addr"),
        (0xA90, "__ZN26IOSkywalkEthernetInterface21setMulticastAddressesEPK12ether_addr_tj", "__ZN26IOSkywalkEthernetInterface21setMulticastAddressesEPK10ether_addrj"),
    ]
    reserved = [
        (0x428, "__ZN9IOService19_RESERVEDIOService0Ev", "__ZN9IOService15configureReportEP19IOReportChannelListjPvS2_"),
        (0x430, "__ZN9IOService19_RESERVEDIOService1Ev", "__ZN9IOService12updateReportEP19IOReportChannelListjPvS2_"),
    ]
    require(missing["AirPort"] == {entry[1] for entry in aliases}, "AirPort 未匹配的导入发生变化")
    require(missing["AirportBrcmFixup"] == {entry[1] for entry in reserved}, "AirportBrcmFixup 未匹配的导入发生变化")
    repairs = []
    legacy_relocations = relocations(images["Legacy"])
    for slot, old, new in aliases:
        child = images["AirPort"].symbols["__ZTV34AirPort_Brcm43xxLLSkywalkInterface"] + 16 + slot
        references = [(a, size, kind) for a, size, name, kind in relocations(images["AirPort"]) if name == old]
        require(references == [(child, 8, 0)], f"非预期的 AirPort 引用：{old}")
        for table in ["__ZTV21IO80211InfraInterface", "__ZTV23IO80211SkywalkInterface"]:
            address = images["Legacy"].symbols[table] + 16 + slot
            require((address, 8, new, 0) in legacy_relocations, f"Legacy 父类虚表不匹配：{old}")
        parent = images["Skywalk"].symbols["__ZTV26IOSkywalkEthernetInterface"] + 16 + slot
        target = struct.unpack("<Q", images["Skywalk"].read(parent, 8))[0]
        require(target == images["Skywalk"].symbols[new], f"Skywalk 父类虚表不匹配：{old}")
        repairs.append({"image": "AirPort", "import": old, "replacement": new, "slot": hex(slot), "relocations": [hex(child)]})
    kernel_symbols = collection.kernel.symbols
    fixup = images["AirportBrcmFixup"]
    fixup_relocations = relocations(fixup)
    for slot, old, new in reserved:
        expected = sorted(fixup.symbols[table] + 16 + slot for table in ["__ZTV8FakeBrcm", "__ZTV16AirportBrcmFixup"])
        references = sorted(a for a, size, name, kind in fixup_relocations if name == old and size == 8 and kind == 0)
        require(references == expected, f"非预期的 AirportBrcmFixup 引用：{old}")
        for name in ["__ZN8FakeBrcm10superClassE", "__ZN16AirportBrcmFixup10superClassE"]:
            require((fixup.symbols[name], 8, "__ZN9IOService10gMetaClassE", 0) in fixup_relocations, "AirportBrcmFixup 父类不匹配")
        parent = kernel_symbols["__ZTV9IOService"] + 16 + slot
        target = collection.pointer(parent)
        require(target == kernel_symbols[new], f"IOService 父类虚表不匹配：{old}")
        repairs.append({"image": "AirportBrcmFixup", "import": old, "replacement": new, "slot": hex(slot), "relocations": [hex(x) for x in references]})
    for name in missing:
        missing[name] -= {entry["import"] for entry in repairs if entry["image"] == name}
        require(not missing[name], f"仍有未匹配的导入：{name}: {sorted(missing[name])}")
    report = {
        "copyright": "Copyright © 2026 laobamac. All rights reserved.",
        "configuration": configuration,
        "kernelCollectionUUID": collection.root.uuid,
        "kernel": collection.version(),
        "OSBuild": plistlib.loads((Path(volume) / "System/Library/CoreServices/SystemVersion.plist").read_bytes())["ProductBuildVersion"],
        "targetVolume": str(volume),
        "kernelProviders": sorted(providers),
        "images": {name: {"uuid": image.uuid, "sha256": hashlib.sha256(paths[name].read_bytes()).hexdigest(), "imports": len(imports[name])} for name, image in images.items()},
        "unmatchedImports": [],
        "inheritedVtableRepairs": repairs,
        "openCoreSource": "https://github.com/acidanthera/OpenCorePkg/blob/25d02c8d051dc2e9d9166b5a3b343ec5b77104cc/Library/OcAppleKernelLib/Vtables.c",
        "openCoreLinkExecuted": False,
        "hardwareValidation": "pending",
    }
    collection.close()
    destination = Path(output) if output else ROOT / f"build/DependencySymbols-{configuration}.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--configuration', choices=['Debug', 'Release'], default='Release')
    parser.add_argument('--target-volume', type=Path, default=Path('/'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.configuration, args.target_volume, args.output), indent=2))
