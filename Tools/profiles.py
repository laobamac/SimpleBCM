#!/usr/bin/env python3
#
#  profiles.py
#  SimpleBCM
#
#  Created by laobamac on 2026/9/18.
#  Copyright © 2026 laobamac. All rights reserved.
#

import hashlib
import json
import struct
from pathlib import Path

from macho import Image


ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / ".research/binaries"
IMAGES = {
    "Legacy": BINARY / "IO80211FamilyLegacy-v1.0.0/IO80211FamilyLegacy.kext/Contents/MacOS/IO80211FamilyLegacy",
    "Skywalk": BINARY / "IOSkywalkFamily-v1.2.0/IOSkywalkFamily.kext/Contents/MacOS/IOSkywalkFamily",
    "AirPortSequoia": BINARY / "IO80211FamilyLegacy-v1.0.0/IO80211FamilyLegacy.kext/Contents/PlugIns/AirPortBrcmNIC.kext/Contents/MacOS/AirPortBrcmNIC",
    "AirPort": BINARY / "AirPortBrcmNIC-Tahoe-v1.0.0/AirPortBrcmNIC-Tahoe.kext/Contents/MacOS/AirPortBrcmNIC",
}
SYMBOLS = {
    "Legacy": [
        "__ZN16IO80211Interface13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient",
        "__ZN23IO80211VirtualInterface13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient",
        "__ZN16IO80211Interface27IO80211InterfacePostMessageEjPvm",
        "__ZN23IO80211VirtualInterface27IO80211InterfacePostMessageEjPvm",
        "__ZN21IO80211InfraInterface19postMessageInternalEjPvm",
        "__ZN17IO80211Controller20apple80211_ioctl_getEP16IO80211InterfaceP23IO80211VirtualInterfaceP23IO80211SkywalkInterfacePv",
        "__ZN17IO80211Controller20apple80211_ioctl_setEP16IO80211InterfaceP23IO80211VirtualInterfaceP23IO80211SkywalkInterfacePv",
        "__ZN16IO80211Interface13getControllerEv",
        "__ZN23IO80211VirtualInterface13getControllerEv",
        "__ZNK17IO80211Controller11getWorkLoopEv",
        "__ZN16IO80211Interface10getBSDNameEv",
        "__ZN23IO80211VirtualInterface10getBSDNameEv",
        "__ZN23IO80211SkywalkInterface10getBSDNameEv",
        "__ZN16IO80211Interface14performCommandEP19IONetworkControllermPvS2_",
    ],
    "Skywalk": ["__ZN26IOSkywalkEthernetInterface13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient"],
    "AirPort": ["_bcm_decode_anqp_nai_realm_print", "__dma_detach", "_dma64_txfast", "__dma_rxfill", "__dma_getnextrxp"],
}
SYMBOLS["AirPortSequoia"] = SYMBOLS["AirPort"]
SCALAR_GET_REQUESTS = [5, 8, 13, 15, 18, 21, 26, 28, 31, 33, 34, 35, 36, 41, 45, 50, 52, 55, 56, 57, 58, 59, 60,
                       63, 64, 70, 71, 72, 82, 87, 88, 96, 100, 101, 235, 241, 256, 258, 259, 261, 265, 267, 336, 353, 369]


def relocations(image):
    pos = 32
    symtab = dysymtab = None
    for _ in range(struct.unpack_from("<I", image.data, 16)[0]):
        cmd, size = struct.unpack_from("<II", image.data, pos)
        if cmd == 2:
            symtab = struct.unpack_from("<IIII", image.data, pos + 8)
        if cmd == 0xB:
            dysymtab = struct.unpack_from("<18I", image.data, pos + 8)
        pos += size
    result = []
    for n in range(dysymtab[15]):
        address, flags = struct.unpack_from("<II", image.data, dysymtab[14] + n * 8)
        index = flags & 0xFFFFFF
        nameoff = struct.unpack_from("<I", image.data, symtab[0] + index * 16)[0]
        name = image.data[symtab[2] + nameoff:].split(b"\0", 1)[0].decode()
        result.append((address, 1 << ((flags >> 25) & 3), name, flags >> 28))
    return result


def numbers(data):
    return ", ".join(f"0x{x:02X}" for x in data)


def main():
    lines = ["//", "//  Profiles.hpp", "//  SimpleBCM", "//", "//  Created by laobamac on 2026/9/15.", "//  Copyright © 2026 laobamac. All rights reserved.", "//", "", "#ifndef SIMPLEBCM_PROFILES_HPP", "#define SIMPLEBCM_PROFILES_HPP", "", "#include <stdint.h>", "", "namespace bcm {", "struct ByteGuard { uint32_t offset; uint8_t bytes[32]; uint8_t mask[32]; };", "struct CopySite { uint32_t offset; bool output; };", ""]
    manifest = {"copyright": "Copyright © 2026 laobamac. All rights reserved.", "supportedKernel": "24.x / 25.x", "images": {}}
    for label, path in IMAGES.items():
        image = Image(path)
        relocs = relocations(image)
        guards = []
        for name in SYMBOLS[label]:
            address = image.symbols[name]
            guards.append((address, name))
        scalar = []
        if label == "Legacy":
            table = struct.unpack("<417Q", image.read(image.symbols["_gGetHandlerTable"], 417 * 8))
            for request in SCALAR_GET_REQUESTS:
                address = table[request - 1]
                name = image.name(address)
                if not name.startswith("__ZL") or not name.endswith("P13apple80211reqb+0x0"):
                    raise RuntimeError("Unexpected scalar GET codec")
                scalar.append({"request": request, "address": hex(address), "symbol": name})
                if (address, name) not in guards:
                    guards.append((address, name))
            lines.append(f"static const uint16_t ScalarGetRequests[] = {{{', '.join(str(x) for x in SCALAR_GET_REQUESTS)}}};")
        copies = [(a - 1, n == "_copyout") for a, _, n, kind in relocs if n in ("_copyin", "_copyout") and kind == 2]
        if label in ("Legacy", "AirPort", "AirPortSequoia"):
            if len(copies) != (14 if label == "Legacy" else 2):
                raise RuntimeError("Unexpected copy callsite count")
            for address, _ in copies:
                if image.read(address, 1) != b"\xe8":
                    raise RuntimeError("Expected direct relative call")
                guards.append((address, image.name(address)))
        if label.startswith("AirPort"):
            guards += [(0x2C2612, "TX backend identity"), (0x2C3D78, "RX fill backend identity"), (0x2C4286, "RX consume backend identity")]
        lines.append(f"static const ByteGuard {label}Guards[] = {{")
        for address, _ in guards:
            mask = bytearray([255] * 32)
            for start, size, _, _ in relocs:
                for offset in range(max(start, address), min(start + size, address + 32)):
                    mask[offset - address] = 0
            lines.append(f"    {{0x{address:X}, {{{numbers(image.read(address, 32))}}}, {{{numbers(mask)}}}}},")
        lines.append("};")
        if label in ("Legacy", "AirPort", "AirPortSequoia"):
            lines.append(f"static const CopySite {label}CopySites[] = {{")
            for address, output in sorted(copies):
                lines.append(f"    {{0x{address:X}, {'true' if output else 'false'}}},")
            lines.append("};")
        lines.append("")
        manifest["images"][label] = {"path": str(path.relative_to(ROOT)), "uuid": image.uuid, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "guards": [{"address": hex(a), "symbol": n} for a, n in guards], "copySites": [{"address": hex(a), "output": o} for a, o in sorted(copies)]}
        if scalar:
            manifest["images"][label]["scalarGetRequests"] = scalar
    for label, other in [("AirPort", "AirPortSequoia"), ("AirPortSequoia", "AirPort")]:
        image, alternative = Image(IMAGES[label]), Image(IMAGES[other])
        relocs = relocations(image) + relocations(alternative)
        mismatches = []
        for guard in manifest["images"][label]["guards"]:
            address = int(guard["address"], 16)
            ignored = {offset for start, size, _, _ in relocs
                       for offset in range(max(start, address), min(start + size, address + 32))}
            if any(a != b and address + index not in ignored for index, (a, b) in
                   enumerate(zip(image.read(address, 32), alternative.read(address, 32)))):
                mismatches.append(hex(address))
        if len(mismatches) < 5:
            raise RuntimeError("AirPort backend guards do not distinguish the original and Tahoe payloads")
        manifest["images"][label]["rejectsOtherBackendAt"] = mismatches
    lines += ["}", "", "#endif", ""]
    outputs = {ROOT / "SimpleBCM/Profiles.hpp": "\n".join(lines), ROOT / "Docs/ABI.json": json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"}
    for path, content in outputs.items():
        if not path.exists() or path.read_text() != content:
            path.write_text(content)


if __name__ == "__main__":
    main()
