#!/usr/bin/env python3
#
#  native_payload.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/1.
#  Copyright © 2026 laobamac. All rights reserved.
#

import bisect
import struct
import re

from native_abi import NativeModel, Mach, class_size, table, method_key, vtable_name, insns, NATIVE_CLASSES
from system_profiles import SYSTEMS

API_SYMBOLS = [
    '__ZN26IOSkywalkEthernetInterfaceC2EPK11OSMetaClass',
    '__ZN26IOSkywalkEthernetInterfaceD2Ev',
    '__ZN26IOSkywalkEthernetInterface4initEP12OSDictionary',
    '__ZN26IOSkywalkEthernetInterface4freeEv',
    '__ZTV26IOSkywalkEthernetInterface',
    '__ZTV22IOSkywalkNetworkPacket',
    '__ZTV25IOSkywalkPacketBufferPool',
    '__ZN26IOSkywalkEthernetInterface25registerEthernetInterfaceEPKNS_16RegistrationInfoEPP20IOSkywalkPacketQueuejP25IOSkywalkPacketBufferPoolS7_j',
    '__ZN26IOSkywalkEthernetInterface25registerEthernetInterfaceEPKNS_16RegistrationInfoEP20IOSkywalkLogicalLinkP25IOSkywalkPacketBufferPoolS6_j',
    '__ZN25IOSkywalkNetworkInterface39registerNetworkInterfaceWithLogicalLinkEPKNS_16RegistrationInfoEP20IOSkywalkLogicalLinkP25IOSkywalkPacketBufferPoolS6_j',
    '__ZN26IOSkywalkEthernetInterface27deregisterEthernetInterfaceEj',
    '__ZN26IOSkywalkTxSubmissionQueue8withPoolEP25IOSkywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PjEPFjS3_S4_PKP15IOSkywalkPacketjPvESC_jj',
    '__ZN26IOSkywalkTxSubmissionQueue16packetSubmissionEb',
    '__ZN26IOSkywalkTxSubmissionQueue14requestDequeueEPvj',
    '_OSObject_typed_operator_new',
    '_OSObject_typed_operator_delete',
    '__ZN25IOSkywalkNetworkInterface10joinPMtreeEP9IOService',
]

CLIENT_CLASSES = ('IO80211APIUserClient', 'IO80211AsyncEventUserClient')
CLIENT_SUFFIXES = ('C2EPK11OSMetaClass', 'D2Ev', '4freeEv', '10gMetaClassE')

INTERFACE_CLASSES = ('IOSkywalkInterface', 'IOSkywalkNetworkInterface', 'IOSkywalkEthernetInterface')
PACKET_CLASS = 'AirPort_Brcm43xxSkywalkPacket'
POOL_CLASS = 'AirPort_Brcm43xxSkywalkPacketBufferPool'

def interface_method(name):
    return any(name.startswith(('__ZN' + str(len(cls)) + cls, '__ZNK' + str(len(cls)) + cls))
               for cls in INTERFACE_CLASSES)

def normalized(name):
    return name.replace('12ether_addr_t', '10ether_addr')

class SkywalkPlan:
    def __init__(self, system='Tahoe'):
        self.model = NativeModel(system)
        self.system = system
        self.profile = SYSTEMS[system]
        if self.model.native.uuid != self.profile['skywalk']:
            raise ValueError('The native Skywalk implementation has no verified profile')
        self.old = self.model.old
        self.native = self.model.native
        self.legacy = self.model.images['Legacy']
        self.air = self.model.images['BrcmTahoe']
        self.wireless = Mach(self.native.path, 'com.apple.iokit.IO80211Family')
        if self.wireless.uuid != self.profile['wireless']:
            raise ValueError('Unsupported native IO80211Family')
        self.link_symbol = API_SYMBOLS[8] if self.profile['kernel'] != 23 else '__ZN26IOSkywalkEthernetInterface39registerNetworkInterfaceWithLogicalLinkEPKNS_16RegistrationInfoEP20IOSkywalkLogicalLinkP25IOSkywalkPacketBufferPoolS6_j'
        if self.link_symbol not in self.native.defined():
            raise ValueError('Missing native Ethernet logical-link registration method')
        ethernet = self.model.new_tables['IOSkywalkEthernetInterface']
        self.link_slot = ethernet.index(self.link_symbol) if self.link_symbol in ethernet else 0xffffffff
        self.api_symbols = list(API_SYMBOLS)
        self.api_symbols[8] = API_SYMBOLS[0]
        self.client_symbols = []
        self.client_tables = []
        for cls in CLIENT_CLASSES:
            if class_size(self.wireless, cls) != 224:
                raise ValueError('Unsupported native user-client layout')
            symbols = ['__ZN' + str(len(cls)) + cls + suffix for suffix in CLIENT_SUFFIXES]
            symbols.append(vtable_name(cls))
            if not set(symbols) <= self.wireless.defined():
                raise ValueError('Native user-client exports missing')
            self.client_symbols.append(symbols)
            self.client_tables.append(table(self.wireless, cls, self.model.kernel))
        def classes(image):
            return {match[2] for name in image.defined()
                    if (match := re.fullmatch(r'__ZN(\d+)(.*)10gMetaClassE', name))
                    and len(match[2]) == int(match[1])}
        collisions = (classes(self.legacy) | classes(self.air)) & classes(self.wireless)
        self.namespace = {}
        for name in sorted(collisions):
            if name == 'IO80211Controller':
                replacement = 'AirPortDriver'
            elif name.startswith('IO'):
                replacement = 'SB' + name[2:]
            elif name.startswith('Log'):
                replacement = 'BCM' + name[3:]
            else:
                raise ValueError('Unknown class collision: ' + name)
            self.namespace[name] = replacement
        if len(self.namespace) != 42:
            raise ValueError('Changed legacy/native class collision set')
        if 'AirPortDriver' in classes(self.wireless) | classes(self.model.kernel):
            raise ValueError('Wireless controller compatibility name is already in use')
        self.compat = {}
        ethernet = self.model.old_tables['IOSkywalkEthernetInterface']
        public_callbacks = {ethernet[offset // 8] for offset in (0x428, 0x430, 0x780)}
        needed = set(ethernet)
        for image in (self.legacy, self.air):
            needed.update(normalized(name) for name in image.undef() if interface_method(name))
        needed = sorted(name for name in needed if interface_method(name) or name in public_callbacks)
        self.methods = needed
        self.method_index = {name: index for index, name in enumerate(needed)}
        old_slots = {method_key(name): i for i, name in enumerate(ethernet)}
        self.method_slots = [old_slots.get(method_key(name), 0xffffffff) for name in needed]
        for name, i in self.method_index.items():
            if interface_method(name):
                self.compat[name] = f'_bcmSkyForward{i}'
        self.compat.update({
            '__bcm_interface_start': '_bcmLegacySkywalkStart',
            '__ZN25IOSkywalkNetworkInterface10joinPMtreeEP9IOService': '_bcmLegacyJoinPowerTree',
            '__ZN26IOSkywalkEthernetInterfaceC2EPK11OSMetaClass': '__ZN18BCMLegacyInterfaceC2EPK11OSMetaClass',
            '__ZN26IOSkywalkEthernetInterfaceD2Ev': '__ZN18BCMLegacyInterfaceD2Ev',
            '__ZN26IOSkywalkEthernetInterfaceD1Ev': '__ZN18BCMLegacyInterfaceD1Ev',
            '__ZN26IOSkywalkEthernetInterfaceD0Ev': '__ZN18BCMLegacyInterfaceD0Ev',
            '__ZNK26IOSkywalkEthernetInterface12getMetaClassEv': '__ZNK18BCMLegacyInterface12getMetaClassEv',
            '__ZN26IOSkywalkEthernetInterface10gMetaClassE': '__ZN18BCMLegacyInterface10gMetaClassE',
            '__ZTV26IOSkywalkEthernetInterface': '_bcmLegacySkywalkVtable',
            '__ZTV22IOSkywalkNetworkPacket': '_bcmPacketCompatibilityVtable',
            '__ZN26IOSkywalkEthernetInterface4initEP12OSDictionary': '_bcmLegacySkywalkInit',
            '__ZN26IOSkywalkEthernetInterface4freeEv': '_bcmLegacySkywalkFree',
            '__ZN25IOSkywalkNetworkInterface4stopEP9IOService': '_bcmLegacySkywalkStop',
            '__ZN18IOSkywalkInterface13willTerminateEP9IOServicej': '_bcmLegacyWillTerminate',
            '__ZN18IOSkywalkInterface12didTerminateEP9IOServicejPb': '_bcmLegacyDidTerminate',
            '__ZN26IOSkywalkEthernetInterface13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient': '_bcmLegacySkywalkUserClient',
            API_SYMBOLS[7]: '_bcmRegisterLegacyEthernet',
            API_SYMBOLS[10]: '_bcmDeregisterLegacyEthernet',
            '__ZN26IOSkywalkEthernetInterface39registerNetworkInterfaceWithLogicalLinkEPKNS_16RegistrationInfoEP20IOSkywalkLogicalLinkP25IOSkywalkPacketBufferPoolS6_j': '_bcmRegisterLegacyEthernetLink',
            API_SYMBOLS[9]: '_bcmRegisterLegacyNetworkLink',
            '__ZN25IOSkywalkNetworkInterface22handleDoorbellForQueueEP20IOSkywalkPacketQueuej': '_bcmLegacyDoorbell',
            '__ZN26IOSkywalkTxSubmissionQueue8withPoolEP25IOSkywalkPacketBufferPooljjP8OSObjectPFjS3_PS_PjEPFjS3_S4_PKP15IOSkywalkPacketjPvESC_j': '_bcmLegacyTxWithPool',
            '__ZNK25IOSkywalkPacketBufferPool7releaseEv': '_bcmLegacyPoolRelease',
            '_OSObject_typed_operator_new': '_bcmLegacyTypedNew',
            '_OSObject_typed_operator_delete': '_bcmLegacyTypedDelete',
        })
        for image in (self.legacy, self.air):
            for name in image.undef():
                if normalized(name) in self.compat:
                    self.compat[name] = self.compat[normalized(name)]
        self.compat_names = sorted(self.compat)
        self.compat_index = {name: index for index, name in enumerate(self.compat_names)}
        self.native_names = set(self.api_symbols)
        self.native_names.update(name for group in self.client_symbols for name in group)
        self.native_names.update(name for name in needed if name in self.native.defined() and
            name != '__ZN26IOSkywalkEthernetInterface39registerNetworkInterfaceWithLogicalLinkEPKNS_16RegistrationInfoEP20IOSkywalkLogicalLinkP25IOSkywalkPacketBufferPoolS6_j')
        self.native_names.update(name for name in ethernet if not interface_method(name))
        self.callbacks = []
        native_slots = {method_key(name): i for i, name in enumerate(self.model.new_tables['IOSkywalkEthernetInterface'])}
        for label, cls in [('Legacy', 'IO80211SkywalkInterface'), ('Legacy', 'IO80211InfraInterface'),
                           ('BrcmTahoe', 'AirPort_Brcm43xxLLSkywalkInterface')]:
            old = self.model.old_tables[cls]
            rows = []
            for index, name in enumerate(old[:len(ethernet)]):
                if index * 8 < 0x850 and index * 8 not in (0x428, 0x430, 0x770, 0x780):
                    continue
                base = ethernet[index]
                if index * 8 != 0x770 and normalized(name) == normalized(base):
                    continue
                if method_key(name) not in native_slots:
                    raise ValueError(f'Native callback has no equivalent: {name}')
                if base not in self.method_index:
                    raise ValueError(f'Callback does not originate in Skywalk: {name}')
                rows.append((native_slots[method_key(name)], self.method_index[base]))
            self.callbacks.append((0 if label == 'Legacy' else 1,
                                   self.model.images[label].names[vtable_name(cls)][4], rows))
        self.packet_calls = self.packet_call_patches()
        self.vptr_sites = self.packet_vptr_sites()
        self.pool_meta = [0x24e2e, 0x24f0c, 0x64ad0]
        for address in self.pool_meta:
            if self.air.read(address - 1, 5) != bytes.fromhex('b9b8000000'):
                raise ValueError('Unrecognized packet pool class-size initializer')
        self.pool_type = self.air.names['__ZL43AirPort_Brcm43xxSkywalkPacketBufferPool_ktv'][4]
        self.power_template = self.air.names['__ZL20power_state_template'][4]
        self.power_states = [struct.unpack('<12Q', self.air.read(self.power_template + i * 96, 96))
                             for i in range(3)]
        if [state[:4] for state in self.power_states] != [(1, 0, 0, 0), (1, 0x400, 0x400, 0x400),
                                                        (1, 0xf000, 0, 2)]:
            raise ValueError('Unrecognized Broadcom power domain')

    def packet_call_patches(self):
        rows = [
            (0x25bf6, 0x1d0, '__ZN15AirPort_BrcmNIC11llTxDequeue'),
            (0x25d43, 0x1e8, '__ZN15AirPort_BrcmNIC11llTxEnqueue'),
            (0x25e70, 0x1d8, '__ZN15AirPort_BrcmNIC11llRxEnqueue'),
            (0x26658, 0x1e0, '__ZN34AirPort_Brcm43xxLLSkywalkInterface11logTxPacket'),
            (0x266ce, 0x1e0, '__ZN34AirPort_Brcm43xxLLSkywalkInterface11inputPacket'),
            (0x287ef, 0x1f0, '__ZN15AirPort_BrcmNIC14llTxCompletion'),
            (0x2884b, 0x1f0, '__ZN15AirPort_BrcmNIC14llTxCompletion'),
        ]
        functions = self.air.funcs()
        addresses = [a for a, name in functions]
        result = []
        for address, slot, prefix in rows:
            function = functions[bisect.bisect_right(addresses, address) - 1][1]
            raw = self.air.read(address, 6)
            if not function.startswith(prefix) or raw[:1] != b'\xff' or raw[1] & 0xf8 != 0x90:
                raise ValueError(f'Unrecognized packet virtual call: {address:#x}')
            if struct.unpack('<I', raw[2:])[0] != slot:
                raise ValueError(f'Packet virtual slot mismatch: {address:#x}')
            result.append((address + 2, slot, slot + 24))
        return result

    def packet_vptr_sites(self):
        destination = self.air.names[vtable_name(PACKET_CLASS)][4] + 16
        section = next(s for s in self.air.sects if s[0] == '__text')
        start, length = section[2:4]
        data = self.air.read(start, length)
        rows = []
        offset = 0
        while True:
            offset = data.find(b'\x48\x8d\x05', offset)
            if offset < 0:
                break
            if offset + 7 <= len(data):
                delta = struct.unpack_from('<i', data, offset + 3)[0]
                if start + offset + 7 + delta == destination:
                    rows.append(start + offset)
            offset += 1
        if not rows:
            raise ValueError('Packet vtable construction sites were not found')
        return rows

    def namespace_payload(self, label, data, image=None):
        image = image or (self.legacy if label == 'Legacy' else self.air)
        found = {}
        for section in image.sects:
            if section[0] != '__cstring':
                continue
            start, size = section[2:4]
            position = start
            while position < start + size:
                end = data.index(0, position, start + size)
                raw = bytes(data[position:end])
                name = raw.decode('ascii', errors='replace')
                if name in self.namespace:
                    replacement = self.namespace[name].encode()
                    if len(replacement) > len(raw):
                        raise ValueError('Class name exceeds its original storage: ' + name)
                    data[position:end] = replacement.ljust(len(raw), b'\0')
                    found.setdefault(name, []).append(position)
                position = end + 1
        if label == 'Legacy' and set(found) != set(self.namespace):
            raise ValueError('Class strings missing: ' + str(set(self.namespace) - set(found)))
        return found

    def resolve(self, name):
        return self.compat_index.get(name)

    def emit(self, native_index):
        import json
        cpp = []
        assembly = []
        api = [native_index[name] for name in self.api_symbols]
        cpp.append('const uint32_t skyAPIImports[] = {' + ','.join(map(str, api)) + '};')
        self.emit_rows(cpp, 'NativeClientProfile', 'nativeClientProfiles',
                       [tuple(native_index[name] for name in symbols) + (len(vtable),)
                        for symbols, vtable in zip(self.client_symbols, self.client_tables)])
        cpp.append('const uint32_t compatibilityImportCount = ' + str(len(self.compat_names)) + ';')
        cpp.append('const char *const compatibilityImportNames[] = {' +
                   ','.join(json.dumps(name) for name in self.compat_names) + '};')
        method_rows = [(native_index.get(name, 0xffffffff), self.method_slots[i])
                       for i, name in enumerate(self.methods)]
        self.emit_rows(cpp, 'SkyMethod', 'skyMethods', method_rows)
        cpp.append(f'const uint32_t skyMethodCount = {len(method_rows)};')
        old = self.model.old_tables['IOSkywalkEthernetInterface']
        entries = [(self.compat_index[name], 1) if name in self.compat_index else (native_index[name], 0)
                   for name in old]
        entries[0x5c0 // 8] = (self.compat_index['__bcm_interface_start'], 1)
        self.emit_rows(cpp, 'SkyEntry', 'skyLegacyEntries', entries)
        cpp.append(f'const uint32_t skyLegacySlotCount = {len(entries)};')
        packet_base = self.model.old_views['IOSkywalkNetworkPacket']
        if any(row[0] != 'native' for row in packet_base):
            raise ValueError('A native packet base method is missing')
        self.emit_rows(cpp, 'SkyEntry', 'skyPacketEntries', [(row[2] // 8, 3) for row in packet_base])
        cpp.append(f'const uint32_t skyPacketSlotCount = {len(packet_base)};')
        subclass = self.model.tables[PACKET_CLASS]
        packet_entries = []
        for source, name, target in subclass:
            if source == 'native' and name == 'IOSkywalkNetworkPacket':
                packet_entries.append((target // 8, 3))
            elif source == 'BrcmTahoe':
                packet_entries.append((target, 4))
            else:
                raise ValueError(f'Unsupported native packet entry: {source}, {name}')
        self.emit_rows(cpp, 'SkyEntry', 'skyPacketSubclassEntries', packet_entries)
        cpp.append(f'const uint32_t skyPacketSubclassSlotCount = {len(packet_entries)};')
        cpp.append(f'const uint32_t skyClassCount = {len(self.callbacks)};')
        self.emit_rows(cpp, 'SkyPatch', 'skyPacketCalls', self.packet_calls)
        cpp.append(f'const uint32_t skyPacketCallCount = {len(self.packet_calls)};')
        cpp.append('const uint32_t skyPacketVptrSites[] = {' + ','.join(map(str, self.vptr_sites)) + '};')
        cpp.append(f'const uint32_t skyPacketVptrSiteCount = {len(self.vptr_sites)};')
        cpp.append('const uint32_t skyPoolMetaSizeSites[] = {' + ','.join(map(str, self.pool_meta)) + '};')
        cpp.append(f'const uint32_t skyPoolMetaSizeSiteCount = {len(self.pool_meta)};')
        cpp.append(f'const uint32_t skyPoolTypeView = {self.pool_type};')
        cpp.append(f'const uint32_t skyPoolVtable = {self.air.names[vtable_name(POOL_CLASS)][4]};')
        cpp.append(f'const uint32_t skyPacketVtable = {self.air.names[vtable_name(PACKET_CLASS)][4]};')
        assembly += ['.section __DATA_CONST,__const', '.p2align 3',
                     '.globl _bcmCompatibilityImports', '_bcmCompatibilityImports:']
        assembly += ['.quad ' + self.compat[name] for name in self.compat_names]
        for array, prefix in [('bcmSkyForwarders', 'bcmSkyForward'), ('bcmSkyCallbacks', 'bcmSkyCallback')]:
            assembly += ['.p2align 3', '.globl _' + array, '_' + array + ':']
            assembly += [f'.quad _{prefix}{i}' for i in range(len(self.methods))]
        assembly += ['.section __TEXT,__text']
        for prefix, resolver in [('bcmSkyForward', 'bcmResolveOldSkywalk'),
                                 ('bcmSkyCallback', 'bcmResolveNativeSkywalk')]:
            for i in range(len(self.methods)):
                assembly += ['.p2align 4', f'.globl _{prefix}{i}', f'_{prefix}{i}:',
                             'pushq %rax', 'pushq %rdi', 'pushq %rsi', 'pushq %rdx',
                             'pushq %rcx', 'pushq %r8', 'pushq %r9', ('movl $' + str(i) + ', %esi'),
                             f'callq _{resolver}', 'movq %rax, %r11']
                if prefix == 'bcmSkyCallback':
                    assembly += ['movq %rdx, %r10', 'andq $-2, %rdx']
                assembly += ['movq %rdx, 40(%rsp)', 'popq %r9', 'popq %r8', 'popq %rcx',
                             'popq %rdx', 'popq %rsi', 'popq %rdi', 'popq %rax']
                if prefix == 'bcmSkyCallback':
                    assembly += ['pushq %r10', 'callq *%r11', 'pushq %rax', 'pushq %rdx',
                                 'movq 16(%rsp), %rdi', 'callq _bcmReleaseNativeReceiver',
                                 'popq %rdx', 'popq %rax', 'addq $8, %rsp', 'retq']
                else:
                    assembly += ['jmpq *%r11']
        return cpp, assembly

    @staticmethod
    def emit_rows(cpp, kind, name, rows):
        cpp.append(f'const {kind} {name}[] = {{' +
                   ','.join('{' + ','.join(map(str, row)) + '}' for row in rows) + '};')

    def manifest(self):
        return {
            'system': self.system,
            'kernel': self.profile['kernel'],
            'build': self.profile['build'],
            'nativeUUID': self.native.uuid,
            'wirelessUUID': self.wireless.uuid,
            'ethernetSize': self.profile['ethernetSize'],
            'poolSize': self.profile['poolSize'],
            'nativeSlotCount': len(self.model.new_tables['IOSkywalkEthernetInterface']),
            'ethernetLinkSymbol': self.link_symbol,
            'ethernetLinkSlot': self.link_slot,
            'airPortPayloadIndex': 2 if self.profile['kernel'] == 25 else 1,
            'classNamespace': self.namespace,
            'wirelessControllerIdentity': 'AirPortDriver',
            'userClientStrategy': 'native-class-with-delegated-control',
            'interfaceStrategy': 'native-interface-adapter',
            'packetStrategy': 'native-packets-with-preserved-private-fields',
            'queueStrategy': 'native-array-callbacks',
            'packetCallPatches': self.packet_calls,
            'packetVptrSites': self.vptr_sites,
            'poolMetaSizeSite': self.pool_meta,
            'compatibilityImports': self.compat_names,
            'compatibilityTargets': [self.compat[name] for name in self.compat_names],
            'powerDomain': {'strategy': 'pci-provider', 'template': self.power_template,
                            'airPortTablePreserved': True, 'joinPMtreeSlot': 0x7a0},
            'hardwareValidation': 'not-run-by-build',
        }


def prepare_native_guards(plans):
    common = set.intersection(*(p.native.defined() | p.model.kernel.defined() | p.wireless.defined() for p in plans))
    imports = set()
    for plan in plans:
        plan.vtable_guards = []
        plan.class_guards = []
        plan.unchecked_overrides = []
        for cls in (*NATIVE_CLASSES, *CLIENT_CLASSES):
            image = plan.wireless if cls in CLIENT_CLASSES else plan.native
            meta = '__ZN' + str(len(cls)) + cls + '10gMetaClassE'
            if meta not in common:
                raise ValueError('Missing common native metaclass: ' + cls)
            plan.class_guards.append((meta, class_size(image, cls)))
            imports.add(meta)
        for cls in ('IOSkywalkEthernetInterface', 'IOSkywalkNetworkPacket', 'IOSkywalkPacketBufferPool', *CLIENT_CLASSES):
            image = plan.wireless if cls in CLIENT_CLASSES else plan.native
            parent = vtable_name(cls)
            imports.add(parent)
            for slot, method in enumerate(table(image, cls, plan.model.kernel)):
                if method in common:
                    plan.vtable_guards.append((parent, (slot + 2) * 8, method))
                    imports.add(method)
                else:
                    plan.unchecked_overrides.append((cls, slot, method))
        allowed = {
            '__ZN26IOSkywalkEthernetInterface39registerNetworkInterfaceWithLogicalLinkEPKNS_16RegistrationInfoEP20IOSkywalkLogicalLinkP25IOSkywalkPacketBufferPoolS6_j',
            '__ZNK25IOSkywalkPacketBufferPool7releaseEv',
            '__ZNK25IOSkywalkPacketBufferPool13taggedReleaseEPKv',
            '__ZN25IOSkywalkNetworkInterface13willTerminateEP9IOServicej',
            '__ZN25IOSkywalkNetworkInterface17setRxFlowSteeringEjP31ifnet_traffic_descriptor_commonj',
        }
        if any(method not in allowed for _, _, method in plan.unchecked_overrides):
            raise ValueError('Unrecognized native vtable override')
        plan.link_bytes, plan.link_mask, plan.link_references = b'', b'', []
        if plan.link_slot != 0xffffffff:
            continue
        address, data = plan.native.funcbytes(plan.link_symbol)
        mask = bytearray([255] * len(data))
        for pc, length, instruction, raw in insns(data, address):
            if raw[0] not in (0xe8, 0xe9):
                if '%rip' in instruction:
                    raise ValueError('Unexpected RIP-relative access in logical-link wrapper')
                continue
            if length != 5:
                raise ValueError('Unexpected branch encoding in logical-link wrapper')
            offset = pc - address + 1
            mask[offset:offset + 4] = b'\0' * 4
            target = pc + length + struct.unpack_from('<i', raw, 1)[0]
            names = set(plan.native.byaddr.get(target, [])) & common
            if names:
                name = sorted(names)[0]
                plan.link_references.append((offset, name))
                imports.add(name)
        if [name for _, name in plan.link_references] != [API_SYMBOLS[10]]:
            raise ValueError('Logical-link wrapper must reference native Ethernet deregistration')
        plan.link_bytes, plan.link_mask = data, bytes(mask)
    return imports


def emit_system_profiles(plans, native_index):
    import json
    lines = []
    rows = []
    for index, plan in enumerate(plans):
        classes = []
        for number, (image, address, callbacks) in enumerate(plan.callbacks):
            name = f'system{index}Callbacks{number}'
            plan.emit_rows(lines, 'SkyCallback', name, callbacks)
            classes.append(f'{{{image},{address},{name},{len(callbacks)}}}')
        name = f'system{index}Classes'
        lines.append('static const SkyClass ' + name + '[] = {' + ','.join(classes) + '};')
        profile = plan.profile
        guards = f'system{index}VtableGuards'
        plan.emit_rows(lines, 'NativeVtableGuard', guards,
                       [(native_index[p], o, native_index[m]) for p, o, m in plan.vtable_guards])
        sizes = f'system{index}ClassGuards'
        plan.emit_rows(lines, 'NativeClassGuard', sizes,
                       [(native_index[m], s) for m, s in plan.class_guards])
        pattern = '{nullptr,nullptr,0,nullptr,0}'
        if plan.link_bytes:
            data, mask, refs = [f'system{index}Link{suffix}' for suffix in ('Bytes', 'Mask', 'References')]
            for symbol, values in ((data, plan.link_bytes), (mask, plan.link_mask)):
                lines.append(f'static const uint8_t {symbol}[] = ' + '{' + ','.join(map(str, values)) + '};')
            plan.emit_rows(lines, 'NativeCodeReference', refs, [(o, native_index[m]) for o, m in plan.link_references])
            pattern = '{' + f'{data},{mask},{len(plan.link_bytes)},{refs},{len(plan.link_references)}' + '}'
        fields = [str(profile['kernel']), json.dumps(plan.system), str(profile['ethernetSize']), str(profile['poolSize']),
                  str(profile['ethernetSlots']), str(2 if profile['kernel'] == 25 else 1),
                  str(plan.link_slot) + 'U', pattern, guards, str(len(plan.vtable_guards)),
                  sizes, str(len(plan.class_guards)), name]
        rows.append('{' + ','.join(fields) + '}')
    lines.append('const NativeSystemProfile nativeSystems[] = {' + ','.join(rows) + '};')
    lines.append(f'const uint32_t nativeSystemCount = {len(plans)};')
    return lines
