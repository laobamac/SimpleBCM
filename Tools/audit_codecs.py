#!/usr/bin/env python3
#
#  audit_codecs.py
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
from profiles import IMAGES, ROOT, SCALAR_GET_REQUESTS, NETWORK_MODE_SYMBOL, NETWORK_CIPHER_SYMBOL, NETWORK_IOVAR_SYMBOL, NETWORK_FIRMWARE_SYMBOL, NETWORK_MAC_SYMBOL, NETWORK_AWDL_FLAGS_SYMBOL, relocations, network_power_sites, network_cipher_site, network_ssid_cipher_site


def audit_native_network_modes():
    from native_abi import Mach, insns

    layouts = {23: (0x6DC, 0x3C, 0x18, 0x2D8), 24: (0x6E4, 0x40, 0x1C, 0x2DC),
               25: (0x6E8, 0x40, 0x1C, 0x2DC)}
    verified = []
    for volume in (Path('/'), Path('/Volumes/Macintosh HD 1'), Path('/Volumes/Macintosh HD 2')):
        path = volume / 'System/Library/KernelCollections/BootKernelExtensions.kc'
        if not path.is_file():
            continue
        kernel = Mach(path, 'com.apple.kernel')
        major = struct.unpack('<I', kernel.read(kernel.names['_version_major'][4], 4))[0]
        kernel.close()
        if major not in layouts:
            continue
        image = Mach(path, 'com.apple.iokit.IO80211Family')
        try:
            name = next(n for n in image.names if n.startswith('__ZL22setIBSS_Or_HostAP_Mode') and n.endswith('reqb'))
            start, data = image.funcbytes(name)
            rows = list(insns(data, start))
            expected, key, ssid, ie = layouts[major]
            zero = next(index for index, (_, _, text, _) in enumerate(rows)
                        if re.fullmatch(r'movl\s+\$' + str(expected) + r',\s*%esi', text))
            base = int(re.fullmatch(r'leaq\s+(-\d+)\(%rbp\),\s*%rdi', rows[zero - 1][2])[1])
            check = next(address for n, (_, _, _, _, address) in image.names.items()
                         if n.startswith('__ZL31checkValidationForApple80211Key'))
            call = next(index for index, (address, _, _, raw) in enumerate(rows)
                        if len(raw) == 5 and raw[0] == 0xE8 and
                        address + 5 + struct.unpack('<i', raw[1:])[0] == check)
            key_address = int(re.fullmatch(r'leaq\s+(-\d+)\(%rbp\),\s*%rdi', rows[call - 1][2])[1])
            reads = [int(match[1]) - base for _, _, text, _ in rows
                     if (match := re.fullmatch(r'movl\s+(-\d+)\(%rbp\),\s*%r10d', text))]
            if key_address - base != key or reads[:2] != [ssid, ie] or not any(
                    re.fullmatch(r'cmpl\s+\$' + str(expected) + r',\s*24\(%r1[23]\)', text)
                    for _, _, text, _ in rows):
                raise RuntimeError('原生热点配置 ABI 与转换布局不一致：' + str(volume))
            verified.append(major)
        finally:
            image.close()
    return verified


def audit_network_security():
    from native_abi import Mach, insns

    legacy = Mach(IMAGES['Legacy'])
    try:
        flags_address, data = legacy.funcbytes(NETWORK_AWDL_FLAGS_SYMBOL)
        assert len(data) == 336
        rows = [text for _, _, text, _ in insns(data, flags_address)]
        for pattern in (r'testb\s+\$1,\s*%r12b', r'testb\s+\$64,\s*%r12b',
                        r'callq\s+\*3336\(%rax\)', r'callq\s+\*3344\(%rax\)'):
            assert any(re.fullmatch(pattern, text) for text in rows)
        calls = [address + 5 + struct.unpack_from('<i', raw, 1)[0]
                 for address, _, _, raw in insns(data, flags_address) if len(raw) == 5 and raw[0] == 0xE8]
        for name in ('__ZN23IO80211VirtualInterface24configureBpfOutputQueuesEb',
                     '__ZN18IO80211PeerManager7disableEPKc', '__ZN18IO80211PeerManager6enableEPKc'):
            assert legacy.names[name][4] in calls
    finally:
        legacy.close()

    consumers = {}
    for label in ('AirPortOriginal', 'AirPort'):
        binary = Mach(IMAGES[label])
        try:
            call = network_cipher_site(Image(IMAGES[label]))
            start, cipher = binary.funcbytes(NETWORK_CIPHER_SYMBOL)
            assert len(cipher) == 0x690
            dispatch = start + 0x664
            offsets = struct.unpack_from('<11i', cipher, 0x664)
            assert dispatch + offsets[6] == 0x44515 and dispatch + offsets[10] == 0x445A3
            rows = [text for _, _, text, _ in insns(cipher[:0x664], start)]
            for pattern in (r'movw\s+\$1,\s*-118\(%rbp\)', r'movl\s+\$268,\s*%esi',
                            r'movl\s+\$68,\s*%ecx'):
                assert any(re.fullmatch(pattern, text) for text in rows)
            parser, data = binary.funcbytes('_wlc_auth_set_pmk')
            rows = [text for _, _, text, _ in insns(data, parser)]
            for pattern in (r'testb\s+\$1,\s*2\(%r14\)', r'cmpw\s+\$64,\s*%ax',
                            r'orb\s+\$2,\s*32\(%rbx\)'):
                assert any(re.fullmatch(pattern, text) for text in rows)
            policy, data = binary.funcbytes('_wlc_sae_process_akm_type')
            rows = [text for _, _, text, _ in insns(data, policy)]
            for pattern in (r'cmpw\s+\$8,\s*%si', r'orb\s+\$1,\s*1058\(%r14\)',
                            r'andb\s+\$-2,\s*1058\(%r14\)', r'movw\s+\$0,\s*116\(%r14\)'):
                assert any(re.fullmatch(pattern, text) for text in rows)
            consumers[label] = {'keyInstallCall': hex(call), 'keyClearCall': hex(call - 0x37),
                                'cipherDispatch': hex(dispatch), 'rawPMKNoInstallBranch': hex(dispatch + offsets[6]),
                                'PSKInstallBranch': hex(dispatch + offsets[10]), 'PMKParser': hex(parser),
                                'AESSetter': hex(binary.names[NETWORK_IOVAR_SYMBOL][4]),
                                'SSIDCipherCall': hex(network_ssid_cipher_site(Image(IMAGES[label]))),
                                'firmwareRequest': hex(binary.names[NETWORK_FIRMWARE_SYMBOL][4])}
            consumers[label]['SAEPolicyReset'] = hex(policy)
            setter, data = binary.funcbytes(NETWORK_MAC_SYMBOL)
            assert len(data) == 10
            validator, data = binary.funcbytes('_wlc_validate_mac')
            rows = [text for _, _, text, _ in insns(data, validator)]
            for pattern in (r'cmpq\s+%rsi,\s*832\(%rdi\)', r'movl\s+%ecx,\s*8\(%rax\)',
                            r'movl\s+%eax,\s*238\(%r14\)'):
                assert any(re.fullmatch(pattern, text) for text in rows)
            calls = [address + 5 + struct.unpack_from('<i', raw, 1)[0]
                     for address, _, _, raw in insns(data, validator) if len(raw) == 5 and raw[0] == 0xE8]
            for name in ('_wlc_bmac_set_hw_etheraddr', '_wlc_bmac_suspend_mac_and_wait', '_wlc_set_mac', '_wlc_bmac_enable_mac'):
                assert binary.names[name][4] in calls
            ra, data = binary.funcbytes('_wlc_set_mac')
            rows = [text for _, _, text, _ in insns(data, ra)]
            for pattern in (r'cmpq\s+%rdi,\s*832\(%rbx\)', r'addq\s+\$238,\s*%rdx', r'movl\s+\$32776,\s*%ecx'):
                assert any(re.fullmatch(pattern, text) for text in rows)
            bssid, data = binary.funcbytes('_wlc_set_bssid')
            assert any(re.fullmatch(r'leaq\s+232\(%rbx\),\s*%rdx', text) for _, _, text, _ in insns(data, bssid))
            up, data = binary.funcbytes('_wlc_up')
            rows = [text for _, _, text, _ in insns(data, up)]
            for pattern in (r'movb\s+\$1,\s*32\(%rax\)', r'cmpb\s+\$0,\s*33\(%rax\)'):
                assert any(re.fullmatch(pattern, text) for text in rows)
            down, data = binary.funcbytes('_wlc_down')
            assert any(re.fullmatch(r'movb\s+\$0,\s*32\(%rax\)', text) for _, _, text, _ in insns(data, down))
            consumers[label]['MACValidator'] = hex(setter)
            consumers[label]['receiveMACSetter'] = hex(ra)
            consumers[label]['BSSIDSetter'] = hex(bssid)
        finally:
            binary.close()
    return {'scope': 'HostAP request 25; WPA2 Personal CCMP/PSK without management frame protection',
            'nativeAuthUpper': 8, 'legacyAuthUpper': 1024, 'firmwareWPAAuth': 128,
            'nativeProducer': 'airportd CWHostAPModeManager',
            'nativeCipher': 0, 'nativeKeyVersion': 0, 'nativePassphraseBytes': [8, 63],
            'nativeRSN': 'Empty for normal WPA2 hotspot configurations', 'legacyCipher': 10, 'legacyKeyVersion': 1,
            'hexPSKBytes': 64, 'alternativeRawPMK': {'nativeCipher': 6, 'bytes': 32, 'requires': 'CCMP/PSK RSN'},
            'firmwarePMKCommand': 268, 'firmwarePMKFlags': 1,
            'firmwareAESWsec': 4, 'keyMaterial': 'Preserve UTF-8 passphrase bytes and length; encode supplied raw PMKs as hexadecimal',
            'ordering': 'Set authentication, clear keys, enable AES, install PMK, preserve AES during final SSID calculation',
            'SSIDCipherScope': 'Matching thread, controller and interface of a normalized WPA2 HostAP start',
            'firmwareErrors': 'Direct wlIoctl PMK request propagates the firmware result instead of ignoring it',
            'authenticator': {'scope': 'AP BSS only; create only when the existing authentication pointer is null',
                              'constructor': '_wlc_authenticator_attach', 'size': 296, 'BSSOffset': 32,
                              'cleanup': 'Existing _wlc_bsscfg_ap_deinit calls _wlc_authenticator_detach and clears the pointer',
                              'association': 'Existing AP association completion starts the original four-way handshake'},
            'AKMPolicy': {'scope': 'Normalized WPA2 HostAP key installation only',
                          'originalSetter': '_wlc_sae_process_akm_type', 'AKM': 2,
                          'behavior': 'Use Open System authentication and clear the incompatible mandatory-MFP policy'},
            'APMACSynchronization': {'scope': 'Validated bridge endpoint after successful HostAP dispatch; active controller interface reconfiguration and deferred event/status maintenance',
                                     'BSSIDOffset': 232, 'currentMACOffset': 238,
                                     'setter': NETWORK_MAC_SYMBOL, 'receiveFilter': '_wlc_set_mac',
                                     'behavior': 'Use original MAC validation to update public/BSS addresses and hardware cache, with native MAC suspension and receive-filter programming',
                                     'maintenance': 'Check active primary AP address equality under the controller workloop after events and during existing status updates; write only on mismatch',
                                     'powerScope': 'Skip inactive controllers, sleeping/power-transition devices and down AP BSS configurations',
                                     'invalidAddress': 'Reject zero or multicast BSSID and non-primary BSS without writing hardware',
                                     'failure': 'Return synchronization errors and retry while active; preserve accepted asynchronous HostAP startup'},
            'AWDLRestoration': {'scope': 'Successful bridged HostAP stop after an active hotspot',
                                'handler': NETWORK_AWDL_FLAGS_SYMBOL, 'handlerAddress': hex(flags_address),
                                'behavior': 'Cycle IFF_UP through the original flags handler, restoring controller, BPF queues and peer-manager state',
                                'ownership': 'Same-controller virtual interface; BSD ifnet softc must match the IOService',
                                'scheduling': 'Existing periodic status update under the controller workloop after radio recovery',
                                'radioUpOffset': 32, 'hardwareOffOffset': 33,
                                'guards': 'Skip active AP, inactive controller, system power transitions and down radio; preserve disabled AWDL interfaces',
                                'cancellation': 'New network-mode start or explicit radio off; restore pending work if dispatch fails'},
            'unsupportedProfiles': 'Reject before mutation; no implicit open-network fallback',
            'explicitOpen': 'Preserved; no AES or PMK installation', 'IBSS': 'Layout conversion only',
            'consumers': consumers,
            'validation': 'Native configuration layouts and original driver consumer instructions audited from the shipped binaries'}


def main():
    image = Image(IMAGES["Legacy"])
    table = struct.unpack("<417Q", image.read(image.symbols["_gGetHandlerTable"], 417 * 8))
    assembly = image.disassemble(r"^__ZL.*get.*P17IO80211Controller")
    blocks = {}
    for block in assembly.split("\n\n"):
        match = re.match(r"([0-9a-f]+) <([^>]+)>:", block)
        if match:
            blocks[int(match[1], 16)] = block
    if not (set(table) - {0}) <= blocks.keys():
        raise RuntimeError("GET 表含未反汇编入口")
    scalar = []
    for request, address in enumerate(table, 1):
        if not address:
            continue
        block = blocks[address]
        stores = [line.strip() for line in block.splitlines() if re.search(r"\bmov[lqw]\s+[^\n]*, 0x14\(%r(?:bx|1[2345]|8)\)", line)]
        if "copyOut" in block or not stores:
            continue
        if re.search(r"0x20\(%r(?:bx|1[2345]|8)\)", block):
            raise RuntimeError("标量入口包含数据指针访问，需重新分析")
        register = re.search(r"0x14\(%(r\w+)\)", stores[0])[1]
        if register != "r8" and not re.search(r"movq\s+%r8, %" + register + r"\b", block):
            raise RuntimeError("未确认标量目标为 apple80211req")
        scalar.append({"request": request, "symbol": image.name(address), "address": hex(address), "stores": stores})
    if [entry["request"] for entry in scalar] != SCALAR_GET_REQUESTS:
        raise RuntimeError("标量 GET 映射与真实代码不一致")
    copies = []
    for label in ["Legacy", "AirPort", "AirPortOriginal"]:
        binary = Image(IMAGES[label])
        for address, _, symbol, kind in relocations(binary):
            if symbol in ("_copyin", "_copyout") and kind == 2:
                copies.append({"image": label, "address": hex(address - 1), "symbol": binary.name(address - 1), "operation": symbol})
    assert len(copies) == 18
    for backend in ["AirPort", "AirPortOriginal"]:
        assert len([entry for entry in copies if entry["image"] in ("Legacy", backend)]) == 16
    scan = blocks[table[10]]
    if not re.search(r"cmpl\s+\$0x48c, 0x18\(%rbx\)", scan):
        raise RuntimeError("扫描结果旧结构长度检查发生变化")
    capabilities = blocks[table[11]]
    if not re.search(r"cmpl\s+\$0xc, %eax", capabilities) or not re.search(r"leaq\s+-0x24\(%rbp\), %rsi", capabilities):
        raise RuntimeError("能力位图旧结构发生变化")
    set_entries = {request: struct.unpack("<Q", image.read(image.symbols["_gSetHandlerTable"] + (request - 1) * 8, 8))[0]
                   for request in [20, 24, 25, 216]}
    set_assembly = image.disassemble(r"^__ZL19setAssociateRequest|^__ZL14setRoamProfile|^__ZL22setIBSS_Or_HostAP_Mode")
    if set_entries != {20: 0x84430, 24: 0x84B4F, 25: 0x84B4F, 216: 0x8B211} or not re.search(r"movl\s+\$0x224, %ecx", set_assembly) or not re.search(r"cmpl\s+\$0x7c, 0x18\(%r8\)", set_assembly):
        raise RuntimeError("关联或漫游配置旧结构发生变化")
    network_assembly = image.disassemble('^' + NETWORK_MODE_SYMBOL + '$')
    if not all(re.search(pattern, network_assembly) for pattern in (
            r'movl\s+\$0x5dc, %esi', r'leaq\s+-0x610\(%rbp\), %rdx',
            r'movl\s+0x18\(%r15\), %ecx', r'cmpq\s+-0x30\(%rbp\), %rax')):
        raise RuntimeError('旧热点处理入口的复制边界发生变化')
    native_network_modes = audit_native_network_modes()
    network_security = audit_network_security()
    power_call, transition = network_power_sites(image)
    assert power_call == 0x8F4B9 and transition == 0x3F8
    report = {"copyright": "Copyright © 2026 laobamac. All rights reserved.", "legacySHA256": hashlib.sha256(image.path.read_bytes()).hexdigest(),
              "getTableCapacity": 417, "populatedGetEntries": sum(bool(x) for x in table), "uniqueGetCodecs": len(set(table) - {0}),
              "scalarGetRequests": scalar, "adaptedCopySites": copies,
              "networkModeTransfer": {"requests": [24, 25], "start": 1, "stop": 2,
                                      "legacySize": 0x5DC,
                                      "nativeSize": {"Sonoma": 0x6DC, "Sequoia": 0x6E4, "Tahoe": 0x6E8},
                                      "legacyCodec": "0x84b4f", "canaryOffset": 0x5E0,
                                      "returnAddressOffset": 0x618, "routePrefixSize": 20,
                                      "legacyKeyOffset": 0x3C, "extendedKeyOffset": 0x40,
                                      "keySize": 0x94, "legacyRSNOffset": 0xD4,
                                      "legacyRSNCapacity": 0x100, "nativeRSNCapacity": 0x200,
                                      "extendedAuthSystems": ["Sequoia", "Tahoe"],
                                      "stopTransfer": "Zero length; no payload conversion",
                                      "security": network_security,
                                      "powerPreservation": {
                                          "networkDisableCall": hex(power_call),
                                          "systemPowerTransitionOffset": transition,
                                          "owner": "Controller of a successful bridged primary HostAP start",
                                          "scope": "Retain radio for network-interface disable while HostAP is active",
                                          "release": "HostAP stop, association, explicit mode change, radio off, system power transition or termination"},
                                      "unrepresentableExtensions": "Rejected without changing authentication or encryption"},
              "associateTransfer": {"request": 20, "legacySize": 0x224, "nativeSize": {"Sonoma": 0x358, "Sequoia": 0x384, "Tahoe": 0x38C},
                                    "legacyCodec": "0x84430", "nativeProducer": {"Sequoia": "0xa053", "Tahoe": "0xa094"}, "driverConsumer": "0x42b8e",
                                    "extendedLayoutSystems": ["Sequoia", "Tahoe"],
                                    "authLower": {"legacyOffset": 6, "legacyWidth": 2, "nativeOffset": 8, "nativeWidth": 4},
                                    "authUpper": {"legacyOffset": 8, "legacyWidth": 2, "nativeOffset": 12, "nativeWidth": 4},
                                    "ssidLength": {"legacyOffset": 0xC, "nativeOffset": 0x10},
                                    "key": {"legacyOffset": 0x38, "nativeOffset": 0x3C},
                                    "rsnLength": {"legacyOffset": 0xCC, "nativeOffset": 0xD0},
                                    "pmkLength": {"legacyOffset": 0x1D4, "nativeOffset": 0x1D8},
                                    "bssidCount": {"legacyOffset": 0x202, "nativeOffset": 0x206, "legacyMaximum": 3, "nativeMaximum": 10},
                                    "scopeLength": {"legacyOffset": 0x218, "nativeOffset": 0x244}},
              "roamProfileTransfer": {"request": 216, "legacyBandSize": 0x7C, "nativeBandSize": 0x80, "aggregateSystems": ["Sequoia", "Tahoe"],
                                      "sonomaTransfer": "Single 0x7C-byte Legacy band, passed through unchanged",
                                      "nativeAllBandsSize": 0x180, "nativeValidOffset": 12,
                                      "legacyRecordsOffset": 12, "nativeRecordsOffset": 16,
                                      "legacySetCodec": "0x8b211", "legacyGetCodec": "0x806fb",
                                      "nativeBandParser": {"Sequoia": "0x33d0a", "Tahoe": "0x37432"}, "bands": [2, 4]},
              "capabilityTransfer": {"request": 12, "legacySize": 12, "nativeSize": {"Sonoma": 16, "Sequoia": 19, "Tahoe": 21},
                                     "legacyCodec": "0x78cb7", "nativeBindSizeInstruction": {"Sequoia": "0x2672a", "Tahoe": "0x26a29"},
                                     "scanCompletionCapability": 46, "nativeScanWaitTest": "0x4259",
                                     "scope": "Native-sized output for all endpoints; only Classic advertises bridge scan completion events; other hardware bits are preserved."},
              "scanResultTransfer": {"request": 11, "legacySize": 0x48C, "nativeSize": {"Sonoma": 0x4CC, "Sequoia": 0x8D8, "Tahoe": 0x8E0},
                                     "commonHeaderSize": 0x8C, "ieLengthOffset": 0x8A,
                                     "legacyIECapacity": 0x400, "nativeIECapacity": {"Sequoia": 0x800, "Tahoe": 0x800},
                                     "legacyCodec": "0x78a33", "nativeCallerSizeInstruction": "0x4333",
                                     "nativeParser": "0x6d4f", "nativeControllerSizeInstruction": "0x7ff8007d28a9"},
              "nativeCaller": {"imageUUID": "A7A35846-4067-3182-B70E-F7477FBC32BD", "symbol": "Apple80211RawGet",
                               "instructionOffset": "0x6984", "behavior": "If req_data is NULL, the native caller supplies &req_val and length 4 as IOUC output."}}
    report["sonoma"] = {
        "OSBuild": "23J620", "kernel": "23.6.0", "airPortBackend": "Original",
        "nativeIO80211UUID": "0a93a0f4c12532fe918856f7c24ddc41",
        "nativeIO80211FamilyUUID": "ec4ba6726e083ad2b88201690a960ff4",
        "scanResultSizeInstruction": "0x4baa", "capabilitySizeInstruction": "0x20e10",
        "associateSizeInstruction": "0xa5fe", "associateTransfer": {
            "nativeSize": 0x358, "legacyPrefixSize": 0x224, "prefixUnchanged": True,
            "authLowerOffset": 6, "authUpperOffset": 8, "authWidth": 2,
            "ssidLengthOffset": 0xC, "keyOffset": 0x38, "rsnLengthOffset": 0xCC,
            "pmkLengthOffset": 0x1D4, "bssidCountOffset": 0x202, "bssidMaximum": 3,
            "authWriteInstructions": ["0xa99c", "0xa9be"],
        },
        "scanMultipleSize": 0x14E0, "roamProfileSize": 0x7C, "selectorCount": 7,
        "commandPacketSize": 0x3C30, "largeCommandPacketSize": 0x3C030, "eventHeaderSize": 0x30,
        "driverAvailableSize": 0xB8, "associationDonePolicy": "Preserve Legacy empty event; no synthetic JoinStatus",
        "associationDoneConsumer": {"symbol": "__eventRead", "eventDispatch": "0x22376",
                                    "resultRequest21": "0x224d7", "getterCall": "0x224e5",
                                    "emptyPayloadCallback": ["0x22502", "0x22517"]},
        "validation": "Native binary analysis and host-executed codec vectors",
        "upstreamWireless": "https://github.com/dortania/OpenCore-Legacy-Patcher/blob/8da38565fa1551a8e5ce8613ea835d04dd97e089/opencore_legacy_patcher/efi_builder/networking/wireless.py",
    }
    destination = ROOT / "Docs/Control-Codecs.json"
    content = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if not destination.exists() or destination.read_text() != content:
        destination.write_text(content)
    print(f"GET 表核对：{report['populatedGetEntries']} 项 / {report['uniqueGetCodecs']} 个编解码入口，{len(scalar)} 项标量结果，每个后端 16 处受限拷贝入口。")
    print(f'热点入口、1500 字节复制边界及原生配置布局核对通过：Darwin {native_network_modes}')


if __name__ == "__main__":
    main()
