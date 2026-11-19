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
import re
import struct
from pathlib import Path

from macho import Image


ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / ".research/binaries"
IMAGES = {
    "Legacy": BINARY / "IO80211FamilyLegacy-v1.0.0/IO80211FamilyLegacy.kext/Contents/MacOS/IO80211FamilyLegacy",
    "Skywalk": BINARY / "IOSkywalkFamily-v1.2.0/IOSkywalkFamily.kext/Contents/MacOS/IOSkywalkFamily",
    "AirPortOriginal": BINARY / "IO80211FamilyLegacy-v1.0.0/IO80211FamilyLegacy.kext/Contents/PlugIns/AirPortBrcmNIC.kext/Contents/MacOS/AirPortBrcmNIC",
    "AirPort": BINARY / "AirPortBrcmNIC-Tahoe-v1.0.0/AirPortBrcmNIC-Tahoe.kext/Contents/MacOS/AirPortBrcmNIC",
}
AWDL_SELECT_SYMBOL = "__ZN22IO80211AWDLPeerManager26selectChannelsToUseForAWDLEv"
NETWORK_MODE_SYMBOL = "__ZL22setIBSS_Or_HostAP_ModeP17IO80211ControllerP16IO80211InterfaceP23IO80211VirtualInterfaceP21IO80211InfraInterfaceP13apple80211reqb"
NETWORK_DISABLE_SYMBOL = "__ZN17IO80211Controller7disableEP18IONetworkInterface"
SYSTEM_POWER_CHANGE_SYMBOL = "__ZN17IO80211Controller16powerChangeGatedEP8OSObjectPvS2_S2_S2_"
HOST_AP_SYMBOL = "__ZN15AirPort_BrcmNIC15setHOST_AP_MODEEP8OSObjectP23apple80211_network_data"
NETWORK_CIPHER_SYMBOL = "__ZN15AirPort_BrcmNIC13setCIPHER_KEYEP8OSObjectP14apple80211_key"
NETWORK_IOVAR_SYMBOL = "__ZN15AirPort_BrcmNIC13wlIovarSetIntEPKci"
NETWORK_FIRMWARE_SYMBOL = "__ZN15AirPort_BrcmNIC7wlIoctlEjPvmbP8OSObject"
NETWORK_CALCULATE_SYMBOL = "__ZN15AirPort_BrcmNIC12wl_calc_wsecEP8OSObject"
NETWORK_SSID_SYMBOL = "__ZN15AirPort_BrcmNIC7setSSIDEP8OSObjectP20apple80211_ssid_data"
NETWORK_MAC_SYMBOL = "_wlc_validate_mac_pub"
NETWORK_AUTHENTICATOR_SYMBOL = "_wlc_authenticator_attach"
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
        "__ZN17IO80211Controller22apple80211RequestIoctlEjiP16IO80211InterfacePv",
        "__ZN16IO80211Interface25updateCountryCodePropertyEb",
        AWDL_SELECT_SYMBOL,
        NETWORK_MODE_SYMBOL,
        NETWORK_DISABLE_SYMBOL,
        SYSTEM_POWER_CHANGE_SYMBOL,
    ],
    "AirPort": ["_bcm_decode_anqp_nai_realm_print", "__dma_detach", "_dma64_txfast", "__dma_rxfill", "__dma_getnextrxp",
                "__ZN15AirPort_BrcmNIC9getLOCALEEP8OSObjectP22apple80211_locale_data",
                "__ZN15AirPort_BrcmNIC15getCOUNTRY_CODEEP8OSObjectP28apple80211_country_code_data",
                HOST_AP_SYMBOL, NETWORK_CIPHER_SYMBOL, NETWORK_IOVAR_SYMBOL,
                NETWORK_FIRMWARE_SYMBOL, NETWORK_CALCULATE_SYMBOL, NETWORK_SSID_SYMBOL,
                NETWORK_AUTHENTICATOR_SYMBOL,
                "__ZNK15AirPort_BrcmNIC9getVirtIfEP8OSObject", "_wlc_bsscfg_find_by_wlcif", "_wlc_sae_process_akm_type",
                NETWORK_MAC_SYMBOL, "_wlc_validate_mac"],
}
SYMBOLS["AirPortOriginal"] = SYMBOLS["AirPort"]
HARDWARE_VERSION_SYMBOL = "__ZN15AirPort_BrcmNIC19getHARDWARE_VERSIONEP8OSObjectP23apple80211_version_data"
ROUTE_SYMBOLS = {
    "Legacy": SYMBOLS["Legacy"][:5] + ["__ZN16IO80211Interface25updateCountryCodePropertyEb",
                                       AWDL_SELECT_SYMBOL, NETWORK_MODE_SYMBOL],
    "AirPort": [HARDWARE_VERSION_SYMBOL, "__ZN15AirPort_BrcmNIC9getLOCALEEP8OSObjectP22apple80211_locale_data"],
}
ROUTE_SYMBOLS["AirPortOriginal"] = ROUTE_SYMBOLS["AirPort"]
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


def network_power_sites(image):
    from native_abi import Mach, insns

    binary = Mach(image.path)
    try:
        address, data = binary.funcbytes(NETWORK_DISABLE_SYMBOL)
        rows = list(insns(data, address))
        target = image.symbols['__ZN17IO80211Controller22apple80211RequestIoctlEjiP16IO80211InterfacePv']
        calls = [a for index, (a, _, _, raw) in enumerate(rows)
                 if len(raw) == 5 and raw[0] == 0xE8 and
                 a + 5 + struct.unpack_from('<i', raw, 1)[0] == target and
                 any(re.fullmatch(r'movl\s+\$19,\s*%edx', row[2]) for row in rows[max(0, index - 4):index])]
        assert len(calls) == 1
        address, data = binary.funcbytes(SYSTEM_POWER_CHANGE_SYMBOL)
        writes = [int(match[1]) for _, _, text, _ in insns(data, address)
                  if (match := re.fullmatch(r'movb\s+\$[01],\s*(\d+)\(%rdi\)', text))]
        assert len(writes) == 2 and writes[0] == writes[1] and writes[0] < 1048
        return calls[0], writes[0]
    finally:
        binary.close()


def network_cipher_site(image):
    from native_abi import Mach, insns

    binary = Mach(image.path)
    try:
        start, data = binary.funcbytes(HOST_AP_SYMBOL)
        target = image.symbols[NETWORK_CIPHER_SYMBOL]
        rows = list(insns(data, start))
        calls = [address for address, _, _, raw in rows
                 if len(raw) == 5 and raw[0] == 0xE8 and
                 address + 5 + struct.unpack_from('<i', raw, 1)[0] == target]
        assert len(calls) == 2 and calls[0] - start == 0xA61
        assert calls[1] - start == 0xA98
        instructions = {address: text for address, _, text, _ in rows}
        assert re.fullmatch(r'xorl\s+%edx,\s*%edx', instructions[calls[0] - 2])
        assert re.fullmatch(r'cmpl\s+\$0,\s*64\(%r13\)', instructions[start + 0xA71])
        assert re.fullmatch(r'leaq\s+60\(%r13\),\s*%rdx', instructions[start + 0xA7C])
        return calls[1]
    finally:
        binary.close()


def network_ssid_cipher_site(image):
    from native_abi import Mach, insns

    binary = Mach(image.path)
    try:
        start, body = binary.funcbytes(NETWORK_SSID_SYMBOL)
        target = image.symbols[NETWORK_CALCULATE_SYMBOL]
        calls = [address for address, _, _, raw in insns(body, start)
                 if len(raw) == 5 and raw[0] == 0xE8 and
                 address + 5 + struct.unpack_from('<i', raw, 1)[0] == target]
        assert len(calls) == 1 and calls[0] - start == 0xB5
        return calls[0]
    finally:
        binary.close()


def main():
    lines = ["//", "//  Profiles.hpp", "//  SimpleBCM", "//", "//  Created by laobamac on 2026/9/15.", "//  Copyright © 2026 laobamac. All rights reserved.", "//", "", "#ifndef SIMPLEBCM_PROFILES_HPP", "#define SIMPLEBCM_PROFILES_HPP", "", "#include <stdint.h>", "", "namespace bcm {", "struct ByteGuard { uint32_t offset; uint8_t bytes[32]; uint8_t mask[32]; };", "struct CopySite { uint32_t offset; bool output; };", ""]
    manifest = {"copyright": "Copyright © 2026 laobamac. All rights reserved.", "supportedKernel": "23.x / 24.x / 25.x", "images": {}}
    for label, path in IMAGES.items():
        if label not in SYMBOLS:
            continue
        image = Image(path)
        relocs = relocations(image)
        guards = []
        for name in SYMBOLS[label]:
            if name == AWDL_SELECT_SYMBOL:
                continue
            address = image.symbols[name]
            guards.append((address, name))
        scalar = []
        if label == "Legacy":
            power_call, transition = network_power_sites(image)
            guards.append((power_call, 'HostAP network-disable power request'))
            lines.append(f'static constexpr uint32_t LegacyNetworkDisablePowerCall = 0x{power_call:X};')
            lines.append(f'static constexpr uint32_t LegacySystemPowerTransitionOffset = 0x{transition:X};')
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
        if label in ("Legacy", "AirPort", "AirPortOriginal"):
            if len(copies) != (14 if label == "Legacy" else 2):
                raise RuntimeError("Unexpected copy callsite count")
            for address, _ in copies:
                if image.read(address, 1) != b"\xe8":
                    raise RuntimeError("Expected direct relative call")
                guards.append((address, image.name(address)))
        if label.startswith("AirPort"):
            guards += [(0x2C2612, "TX backend identity"), (0x2C3D78, "RX fill backend identity"), (0x2C4286, "RX consume backend identity")]
            cipher_call = network_cipher_site(image)
            guards.append((cipher_call, 'HostAP cipher installation'))
            lines.append(f'static constexpr uint32_t {label}NetworkCipherCall = 0x{cipher_call:X};')
            ssid_cipher_call = network_ssid_cipher_site(image)
            guards.append((ssid_cipher_call, 'SSID encryption calculation'))
            lines.append(f'static constexpr uint32_t {label}NetworkSSIDCipherCall = 0x{ssid_cipher_call:X};')
        lines.append(f"static const ByteGuard {label}Guards[] = {{")
        for address, _ in guards:
            mask = bytearray([255] * 32)
            for start, size, _, _ in relocs:
                for offset in range(max(start, address), min(start + size, address + 32)):
                    mask[offset - address] = 0
            lines.append(f"    {{0x{address:X}, {{{numbers(image.read(address, 32))}}}, {{{numbers(mask)}}}}},")
        lines.append("};")
        if label in ("Legacy", "AirPort", "AirPortOriginal"):
            lines.append(f"static const CopySite {label}CopySites[] = {{")
            for address, output in sorted(copies):
                lines.append(f"    {{0x{address:X}, {'true' if output else 'false'}}},")
            lines.append("};")
        lines.append("")
        manifest["images"][label] = {"path": str(path.relative_to(ROOT)), "uuid": image.uuid, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "guards": [{"address": hex(a), "symbol": n} for a, n in guards], "copySites": [{"address": hex(a), "output": o} for a, o in sorted(copies)]}
        if scalar:
            manifest["images"][label]["scalarGetRequests"] = scalar
            manifest["images"][label]["networkModePower"] = {
                "disablePowerCall": hex(power_call), "systemPowerTransitionOffset": transition,
                "scope": "Retain active HostAP radio during network-interface disable; allow system power transitions"}
        if label.startswith('AirPort'):
            manifest['images'][label]['networkCipherCall'] = hex(cipher_call)
            manifest['images'][label]['networkSSIDCipherCall'] = hex(ssid_cipher_call)
    for label, other in [("AirPort", "AirPortOriginal"), ("AirPortOriginal", "AirPort")]:
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
