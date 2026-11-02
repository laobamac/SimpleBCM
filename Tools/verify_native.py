#!/usr/bin/env python3
#
#  verify_native.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/1.
#  Copyright © 2026 laobamac. All rights reserved.
#

import bisect
import json
import re
import struct
import subprocess
from pathlib import Path

from bootstrap import ROOT
from native_abi import Mach, insns, method_key, verify_model, table, class_size
from native_payload import SkywalkPlan, PACKET_CLASS, CLIENT_CLASSES
from profiles import IMAGES

HOST = r'''
//
//  ForwardingValidation.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct ForwardTarget { uintptr_t function; void *receiver; };
struct Pair { uint64_t first, second; };
struct Aggregate { uint64_t words[32]; };
alignas(16) static uint64_t oldObject;
alignas(16) static uint64_t nativeObject;
static void *expectedReceiver;
static uintptr_t selectedTarget;
static uint32_t expectedIndex;
static bool fallback;
static unsigned retained;
static unsigned released;
static unsigned calls;

extern "C" ForwardTarget bcmResolveOldSkywalk(void *self, uint32_t index) {
    assert(self == &oldObject && index == expectedIndex);
    return {selectedTarget, &nativeObject};
}

extern "C" ForwardTarget bcmResolveNativeSkywalk(void *self, uint32_t index) {
    assert(self == &nativeObject && index == expectedIndex);
    if (fallback)
        return {selectedTarget, &nativeObject};
    ++retained;
    return {selectedTarget, reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(&oldObject) | 1)};
}

extern "C" void bcmReleaseNativeReceiver(uintptr_t self) {
    if (self & 1) {
        assert((self & ~uintptr_t(1)) == reinterpret_cast<uintptr_t>(&oldObject));
        ++released;
    } else {
        assert(self == reinterpret_cast<uintptr_t>(&nativeObject));
    }
    asm volatile("xorq %%rax, %%rax; xorq %%rdx, %%rdx" ::: "rax", "rdx", "cc");
}

static uint64_t nine(void *self, uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                     uint64_t e, uint64_t f, uint64_t g, uint64_t h) {
    assert(self == expectedReceiver);
    assert(a == 11 && b == 22 && c == 33 && d == 44 && e == 55 && f == 66 && g == 77 && h == 88);
    ++calls;
    return 0xfedcba9876543210ULL;
}

static Pair six(void *self, uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    assert(self == expectedReceiver);
    assert(a == 11 && b == 22 && c == 33 && d == 44 && e == 55);
    ++calls;
    return {0x1234567812345678ULL, 0x9876543298765432ULL};
}

static uint64_t aggregate(void *self, Aggregate value, uint64_t after) {
    assert(self == expectedReceiver && after == 0x44556677);
    for (unsigned i = 0; i < 32; ++i)
        assert(value.words[i] == 0x1122334455660000ULL + i);
    ++calls;
    return 0x1122334455667788ULL;
}

static int userClient(void *self, void *task, void *token, uint32_t type, void *properties, void **output) {
    assert(self == expectedReceiver);
    assert(task == reinterpret_cast<void *>(0x1000) && token == reinterpret_cast<void *>(0x2000));
    assert(type == 0xabcdef12 && properties == reinterpret_cast<void *>(0x3000));
    *output = reinterpret_cast<void *>(0x4000);
    ++calls;
    return 0x1234abcd;
}
@DECLARATIONS@

int main() {
    using Nine = uint64_t (*)(void *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    using Six = Pair (*)(void *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
    using Large = uint64_t (*)(void *, Aggregate, uint64_t);
    using Client = int (*)(void *, void *, void *, uint32_t, void *, void **);
    const uintptr_t forwarders[] = {@FORWARDERS@};
    const uintptr_t callbacks[] = {@CALLBACKS@};
    Aggregate value {};
    for (unsigned i = 0; i < 32; ++i)
        value.words[i] = 0x1122334455660000ULL + i;
    for (uint32_t i = 0; i < sizeof(forwarders) / sizeof(forwarders[0]); ++i) {
        expectedIndex = i;
        expectedReceiver = &nativeObject;
        selectedTarget = reinterpret_cast<uintptr_t>(nine);
        auto result = reinterpret_cast<Nine>(forwarders[i])(&oldObject, 11, 22, 33, 44, 55, 66, 77, 88);
        assert(result == 0xfedcba9876543210ULL);
        selectedTarget = reinterpret_cast<uintptr_t>(aggregate);
        assert(reinterpret_cast<Large>(forwarders[i])(&oldObject, value, 0x44556677) == 0x1122334455667788ULL);
        for (unsigned inactive = 0; inactive < 2; ++inactive) {
            fallback = inactive != 0;
            expectedReceiver = fallback ? static_cast<void *>(&nativeObject) : &oldObject;
            selectedTarget = reinterpret_cast<uintptr_t>(six);
            auto pair = reinterpret_cast<Six>(callbacks[i])(&nativeObject, 11, 22, 33, 44, 55);
            assert(pair.first == 0x1234567812345678ULL && pair.second == 0x9876543298765432ULL);
            selectedTarget = reinterpret_cast<uintptr_t>(userClient);
            void *output = nullptr;
            assert(reinterpret_cast<Client>(callbacks[i])(&nativeObject, reinterpret_cast<void *>(0x1000),
                reinterpret_cast<void *>(0x2000), 0xabcdef12, reinterpret_cast<void *>(0x3000), &output) == 0x1234abcd);
            assert(output == reinterpret_cast<void *>(0x4000));
            assert(retained == released);
        }
    }
    printf("{\"forwardingCalls\":%u,\"retainedReceivers\":%u,\"releasedReceivers\":%u}\n", calls, retained, released);
}
'''

def verify_native(temporary, binary, system='Tahoe'):
    plan = SkywalkPlan(system)
    checks = verify_model(plan.model)
    manifest = json.loads((ROOT / 'build/Embedded/manifest.json').read_text())
    for payload in manifest['payloads']:
        label = payload['label']
        image = Mach(IMAGES[label])
        original = bytearray(payload['size'])
        for _, address, _, fileoff, length in image.segs:
            original[address:address + length] = image.b[image.base + fileoff:image.base + fileoff + length]
        original_size = len(original)
        renamed = plan.namespace_payload(label, original, image)
        assert len(original) == original_size
        assert renamed == payload['namespacedClassStrings']
        generated = (ROOT / ('build/Embedded/' + label + '.bin')).read_bytes()
        for section in image.sects:
            if section[0] == '__cstring':
                start, length = section[2:4]
                assert generated[start:start + length] == original[start:start + length]
                strings = set(generated[start:start + length].split(b'\0'))
                assert not strings.intersection(name.encode() for name in plan.namespace)
    checks.append('All 42 shared legacy class names are isolated in both payload CString sections')
    generated_legacy = (ROOT / 'build/Embedded/Legacy.bin').read_bytes()
    assert plan.namespace['IO80211Controller'] == 'AirPortDriver'
    assert manifest['nativeAdapter']['wirelessControllerIdentity'] == 'AirPortDriver'
    profile = next(p for p in manifest['systemProfiles'] if p['system'] == system)
    assert profile['nativeUUID'] == plan.native.uuid and profile['wirelessUUID'] == plan.wireless.uuid
    assert profile['ethernetSize'] == class_size(plan.native, 'IOSkywalkEthernetInterface')
    assert profile['poolSize'] == class_size(plan.native, 'IOSkywalkPacketBufferPool')
    assert profile['ethernetLinkSlot'] == plan.link_slot
    if plan.link_slot != 0xffffffff:
        assert plan.model.new_tables['IOSkywalkEthernetInterface'][plan.link_slot] == plan.link_symbol
    assert profile['airPortPayloadIndex'] == (2 if plan.profile['kernel'] == 25 else 1)
    assert plan.compat['__ZNK25IOSkywalkPacketBufferPool7releaseEv'] == '_bcmLegacyPoolRelease'
    guards = manifest['nativeRuntimeGuards'][system]
    for meta, size in guards['classes']:
        cls = re.fullmatch(r'__ZN\d+(.+)10gMetaClassE', meta)[1]
        image = plan.wireless if cls in CLIENT_CLASSES else plan.native
        assert class_size(image, cls) == size
    assert len(guards['classes']) == 15 and len(guards['vtables']) >= 1060
    checks.append('Major-version profile selects native layouts and a logical-link entry without a build or UUID gate')
    controller_name = 0x127239
    assert plan.legacy.read(controller_name, 18) == b'IO80211Controller\0'
    assert generated_legacy[controller_name:controller_name + 18] == b'AirPortDriver' + b'\0' * 5
    for site in (0x8d629, 0x8d707, 0x94019):
        raw = plan.legacy.read(site, 7)
        assert raw[:3] == b'\x48\x8d\x35'
        assert site + 7 + struct.unpack_from('<i', raw, 3)[0] == controller_name
    assert class_size(plan.legacy, 'IO80211Controller') == 1048
    checks.append('Both controller metaclass constructors and the module initializer use AirPortDriver with unchanged storage and class size')
    generated = (ROOT / ('build/Embedded/' + ('AirPort' if plan.profile['kernel'] == 25 else 'AirPortOriginal') + '.bin')).read_bytes()
    original_power = plan.air.read(plan.power_template, 288)
    assert generated[plan.power_template:plan.power_template + 288] == original_power
    native_states = plan.native.read(plan.native.names['__ZL13myPowerStates'][4], 192)
    required = struct.unpack_from('<Q', native_states, 96 + 24)[0]
    assert required == 2
    states = [struct.unpack_from('<12Q', original_power, i * 96) for i in range(3)]
    assert [state[2] for state in states] == [0, 0x400, 0]
    assert not any((state[2] & required) == required for state in states)
    assert all(not payload['powerDomainPatches'] for payload in manifest['payloads'])
    assert class_size(plan.air, 'AirPort_BrcmNIC') > 6816
    assert method_key(plan.model.new_tables['IOSkywalkEthernetInterface'][0x7a0 // 8]) == 'joinPMtree(IOService*)'
    assert plan.compat['__ZN25IOSkywalkNetworkInterface10joinPMtreeEP9IOService'] == '_bcmLegacyJoinPowerTree'
    topology = manifest['nativeAdapter']['powerDomain']
    assert topology['strategy'] == 'pci-provider' and topology['airPortTablePreserved']
    checks.append('Original Broadcom power table preserved; native power joins use the verified joinPMtree slot')
    product = Mach(binary)
    assert '__ZN18BCM80211UserClient10gMetaClassE' in product.names
    assert '__ZN20IO80211APIUserClient10gMetaClassE' not in product.defined()
    assert class_size(product, 'BCMLegacyInterface') == 272
    base = table(plan.model.kernel, 'IOService', plan.model.kernel)
    legacy = table(product, 'BCMLegacyInterface')
    assert len(base) == len(legacy)
    for index, name in enumerate(legacy):
        assert method_key(name) == method_key(base[index])
    checks.append('Compiled legacy facade has the native IOService slot layout and 272-byte allocation')
    source = (ROOT / 'SimpleBCM/NativeUserClient.cpp').read_text()
    override_slots = {0, 8} | {int(value, 16) for value in re.findall(r'view\[2 \+ (0x[0-9a-f]+) / 8\]', source)}
    expected = {0x90: 'free()', 0x5c0: 'start(IOService*)', 0x5c8: 'stop(IOService*)',
                0x850: 'externalMethod(', 0x858: 'registerNotificationPort(',
                0x8e0: 'initWithTask(', 0x8f0: 'clientClose()', 0x8f8: 'clientDied()',
                0x900: 'getService()', 0x908: 'registerNotificationPort(', 0x920: 'clientMemoryForType('}
    for cls, native_table in zip(CLIENT_CLASSES, plan.client_tables):
        assert len(native_table) == 300 and class_size(plan.wireless, cls) == 224
        for offset, prefix in expected.items():
            assert method_key(native_table[offset // 8]).startswith(prefix)
        for index, name in enumerate(native_table):
            if cls in name and index * 8 != 0x38:
                assert index * 8 in override_slots, ('Unadapted native client operation', name)
        address, code = plan.wireless.funcbytes('__ZN' + str(len(cls)) + cls + '4freeEv')
        decoded = list(insns(code, address))
        assert any('216(' in text for _, _, text, _ in decoded)
    assert 0x38 not in override_slots
    assert 'meta->instanceConstructed()' in source
    checks.append('Native client slots, sizes, complete override coverage and genuine metaclass identity verified')
    product.close()
    allowed = {'bool' , 'unsigned int', 'int', 'unsigned long', 'unsigned long long'}
    for _, _, bindings in plan.callbacks:
        for native_slot, index in bindings:
            signature = method_key(plan.methods[index])
            arguments = signature[signature.index('(') + 1:signature.rindex(')')]
            parameters = arguments.split(', ') if arguments else []
            if len(parameters) > 5 or any('*' not in p and p not in allowed for p in parameters):
                raise AssertionError('Callback requires a different calling convention: ' + signature)
            assert native_slot < len(plan.model.new_tables['IOSkywalkEthernetInterface'])
    checks.append('All native callbacks fit the verified six-register ABI')
    new_slots = {method_key(name): i * 8 for i, name in enumerate(plan.model.new_tables[PACKET_CLASS])}
    for offset, old_slot, new_slot in plan.packet_calls:
        name = plan.model.old_tables[PACKET_CLASS][old_slot // 8]
        assert new_slots[method_key(name)] == new_slot
        assert struct.unpack('<I', plan.air.read(offset, 4))[0] == old_slot
    checks.append('Every packet call preserves its method identity')
    functions = plan.air.funcs()
    starts = [address for address, _ in functions]
    for address in plan.vptr_sites:
        start, name = functions[bisect.bisect_right(starts, address) - 1]
        assert 'AirPort_Brcm43xxSkywalkPacket' in name
        decoded = list(insns(plan.air.read(start, address + 7 - start), start))
        assert decoded[-1][0] == address and decoded[-1][1] == 7
    checks.append('All packet vptr replacements are complete constructor instructions')
    expected_sizes = []
    for address, relocation in plan.air.relocs().items():
        if relocation[0] == '__ZN11OSMetaClassC2EPKcPKS_j' and plan.air.read(address - 6, 5) == bytes.fromhex('b9b8000000'):
            expected_sizes.append(address - 5)
    assert sorted(expected_sizes) == sorted(plan.pool_meta)
    checks.append('Both pool metaclass constructors and the global initializer are covered')
    forwarders = (ROOT / 'build/Embedded/Payloads.S').read_text().split('.section __TEXT,__text', 1)[1]
    folder = Path(temporary)
    assembly = folder / 'Forwarding.S'
    assembly.write_text('.section __TEXT,__text\n' + forwarders)
    declarations = []
    old_entries, new_entries = [], []
    for i in range(len(plan.methods)):
        declarations.extend((f'extern "C" void bcmSkyForward{i}();', f'extern "C" void bcmSkyCallback{i}();'))
        old_entries.append(f'reinterpret_cast<uintptr_t>(bcmSkyForward{i})')
        new_entries.append(f'reinterpret_cast<uintptr_t>(bcmSkyCallback{i})')
    source = HOST.replace('@DECLARATIONS@', '\n'.join(declarations)).replace('@FORWARDERS@', ','.join(old_entries)).replace('@CALLBACKS@', ','.join(new_entries))
    host = folder / 'ForwardingValidation.cpp'
    host.write_text(source)
    executable = folder / 'forwarding'
    subprocess.run(['xcrun', 'clang++', '-std=c++14', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    str(host), str(assembly), '-o', str(executable)], check=True)
    forwarding = json.loads(subprocess.check_output([str(executable)], text=True))
    blob = Path(binary).read_bytes()
    old_code = next(section for section in plan.old.sects if section[0] == '__text')
    assert plan.old.read(old_code[2], min(old_code[3], 4096)) not in blob
    checks.append('The old IOSkywalk executable text is absent from the product')
    result = {'checks': checks, 'forwarding': forwarding, 'packetCallSites': len(plan.packet_calls),
              'packetConstructors': len(plan.vptr_sites), 'poolSizeSites': len(plan.pool_meta),
              'nativeInterfaceCallbacks': [len(row[2]) for row in plan.callbacks],
              'kernelExecution': False, 'hardwareValidation': 'not-run-by-build'}
    plan.wireless.close()
    plan.model.close()
    return result
