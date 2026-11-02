#!/usr/bin/env python3
#
#  native_abi.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/1.
#  Copyright © 2026 laobamac. All rights reserved.
#

import collections
import ctypes
import functools
import hashlib
import mmap
import re
import struct
import subprocess
import uuid
from pathlib import Path

from profiles import IMAGES
from system_profiles import SYSTEMS
from native_references import ReferenceImage, reference_paths


EXPECTED_SOURCES = {
    'OldSky': '0484ecd97d1bdb8759aef72661c196cda4309697eea1945a4a3c4d5e6d7e5e5b',
    'Legacy': 'ac2dc15b77f8eaf97b71b34c5d0e1b59f862bfeac618396449306e1837e73894',
    'BrcmTahoe': '0b6cf936e594d1372960a60c8f17b6cbf68e3535a191574bd91498da49713775',
    'BrcmOriginal': '884e90b27cff151e432bb36275936f57b43e72419e95b51b3ac067d3f2ccd331',
}
PATHS = {key: IMAGES[label] for key, label in (
    ('OldSky', 'Skywalk'), ('Legacy', 'Legacy'), ('BrcmTahoe', 'AirPort'), ('BrcmOriginal', 'AirPortOriginal'))}

class Mach:

    def __new__(cls, path, entry=None):
        if Path(path).suffix == '.json':
            return ReferenceImage(path, entry)
        return super().__new__(cls)

    def __init__(self, path, entry=None):
        self.path = str(path)
        self.f = open(path, 'rb')
        self.b = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        self.base = 0
        if self.b[:4] == b'\xca\xfe\xba\xbe':
            for i in range(struct.unpack_from('>I', self.b, 4)[0]):
                cpu, sub, off, size, al = struct.unpack_from('>IIIII', self.b, 8 + 20 * i)
                if cpu == 16777223:
                    self.base = off
                    break
        self.h = self.base
        self.parse()
        self.fixup_base = min((v for n, v, s, o, fs in self.segs if v and s))
        if entry:
            self.h = self.base + self.entries[entry][1]
            self.parse()

    def parse(self):
        b = self.b
        h = self.h
        magic, cpu, sub, typ, n, sz, flags, res = struct.unpack_from('<8I', b, h)
        if magic != 4277009103 or cpu != 16777223:
            raise ValueError('Expected an x86_64 Mach-O image')
        if h + 32 + sz > len(b):
            raise ValueError('Truncated load commands')
        self.typ = typ
        self.segs = []
        self.sects = []
        self.entries = {}
        self.syms = []
        self.symtab = None
        self.dysym = None
        self.uuid = None
        p = h + 32
        for i in range(n):
            c, s = struct.unpack_from('<II', b, p)
            if s < 8 or p + s > h + 32 + sz:
                raise ValueError('Invalid load command size')
            if c == 25:
                sn, va, vs, fo, fs, mp, ip, ns, fl = struct.unpack_from('<16sQQQQiiII', b, p + 8)
                sn = sn.rstrip(b'\x00').decode()
                self.segs.append((sn, va, vs, fo, fs))
                for j in range(ns):
                    d = struct.unpack_from('<16s16sQQIIIIIIII', b, p + 72 + 80 * j)
                    self.sects.append((d[0].rstrip(b'\x00').decode(), d[1].rstrip(b'\x00').decode(), *d[2:]))
            elif c == 2:
                self.symtab = struct.unpack_from('<IIII', b, p + 8)
            elif c == 11:
                self.dysym = struct.unpack_from('<18I', b, p + 8)
            elif c == 27:
                self.uuid = str(uuid.UUID(bytes=b[p + 8:p + 24])).upper()
            elif c == 2147483701:
                va, fo, so, rv = struct.unpack_from('<QQII', b, p + 8)
                name = b[p + so:p + s].split(b'\x00')[0].decode()
                self.entries[name] = (va, fo)
            p += s
        if self.symtab:
            so, ns, st, ss = self.symtab
            for i in range(ns):
                si, t, se, d, v = struct.unpack_from('<IBBHQ', b, self.base + so + 16 * i)
                name = b[self.base + st + si:b.find(b'\x00', self.base + st + si, self.base + st + ss)].decode(errors='replace') if si else ''
                self.syms.append((name, t, se, d, v))
        self.names = {s[0]: s for s in self.syms if not s[1] & 224}
        self.byaddr = collections.defaultdict(list)
        for s in self.syms:
            if s[4] and s[0] and (not s[1] & 224):
                self.byaddr[s[4]].append(s[0])

    def off(self, va):
        for n, v, s, o, fs in self.segs:
            if v <= va < v + fs:
                return self.base + o + va - v
        raise ValueError(hex(va))

    def read(self, va, n):
        for name, v, s, o, fs in self.segs:
            if n >= 0 and v <= va and (va + n <= v + fs):
                offset = self.base + o + va - v
                if offset + n > len(self.b):
                    raise ValueError('Truncated segment')
                return self.b[offset:offset + n]
        raise ValueError(f'Unmapped range {va:#x}+{n:#x}')

    def close(self):
        self.b.close()
        self.f.close()

    def defined(self):
        return {n for n, t, se, d, v in self.syms if t & 1 and t & 14 in [2, 14] and (not t & 224)}

    def undef(self):
        return {n for n, t, se, d, v in self.syms if t & 14 == 0 and (not t & 224)}

    def relocs(self):
        r = {}
        if self.dysym:
            o, n = self.dysym[14:16]
            for i in range(n):
                a, w = struct.unpack_from('<iI', self.b, self.base + o + 8 * i)
                ix = w & 16777215
                r[a] = (self.syms[ix][0] if w >> 27 & 1 else 'LOCAL', w >> 28, w >> 24 & 1, w >> 25 & 3)
        for sec in self.sects:
            o, n = sec[6:8]
            for i in range(n):
                a, w = struct.unpack_from('<iI', self.b, self.base + o + 8 * i)
                ix = w & 16777215
                r[sec[2] + a] = (self.syms[ix][0] if w >> 27 & 1 else 'LOCAL', w >> 28, w >> 24 & 1, w >> 25 & 3)
        return r

    def funcs(self):
        return sorted(((s[4], s[0]) for s in self.syms if s[2] and s[2] <= len(self.sects) and (self.sects[s[2] - 1][0] == '__text') and (not s[1] & 224)))

    def funcbytes(self, name):
        a = self.names[name][4]
        ends = [x for x, n in self.funcs() if x > a]
        e = min(ends) if ends else a + 512
        return (a, self.read(a, e - a))

def sky(ver):
    return Mach(reference_paths()[ver], 'com.apple.iokit.IOSkywalkFamily')

def dem(names):
    s = list(names)
    return subprocess.check_output(['c++filt'], input='\n'.join(s) + '\n', text=True).splitlines()

@functools.lru_cache(maxsize=1)
def disassembler():
    toolchain = Path(subprocess.check_output(['xcrun', '--find', 'llvm-objdump'], text=True).strip()).parent.parent
    library = ctypes.CDLL(str(toolchain / 'lib/libLTO.dylib'))
    library.LLVMCreateDisasm.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    library.LLVMCreateDisasm.restype = ctypes.c_void_p
    library.LLVMDisasmInstruction.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_size_t]
    library.LLVMDisasmInstruction.restype = ctypes.c_size_t
    library.lto_initialize_disassembler()
    context = library.LLVMCreateDisasm(b'x86_64-apple-darwin', None, 0, None, None)
    if not context:
        raise RuntimeError('Unable to initialize the x86_64 disassembler')
    return library, context

def insns(data, addr):
    library, context = disassembler()
    buf = ctypes.create_string_buffer(data)
    o = 0
    while o < len(data):
        out = ctypes.create_string_buffer(512)
        l = library.LLVMDisasmInstruction(context, ctypes.byref(buf, o), len(data) - o, addr + o, out, 512)
        if not l:
            raise ValueError(f'Undecodable instruction at {addr + o:#x}')
        yield (addr + o, l, out.value.decode().strip(), data[o:o + l])
        o += l

NATIVE_CLASSES = ('IOSkywalkInterface', 'IOSkywalkNetworkInterface', 'IOSkywalkEthernetInterface', 'IOSkywalkPacket', 'IOSkywalkNetworkPacket', 'IOSkywalkPacketBufferPool', 'IOSkywalkPacketQueue', 'IOSkywalkTxSubmissionQueue', 'IOSkywalkRxSubmissionQueue', 'IOSkywalkTxCompletionQueue', 'IOSkywalkRxCompletionQueue', 'IOSkywalkPacketBuffer', 'IOSkywalkMemorySegment')
LEGACY_CLASSES = (('Legacy', 'IO80211SkywalkInterface', 'IOSkywalkEthernetInterface'), ('Legacy', 'IO80211InfraInterface', 'IO80211SkywalkInterface'), ('BrcmTahoe', 'AirPort_Brcm43xxLLSkywalkInterface', 'IO80211InfraInterface'), ('BrcmTahoe', 'AirPort_Brcm43xxSkywalkPacket', 'IOSkywalkNetworkPacket'), ('BrcmTahoe', 'AirPort_Brcm43xxSkywalkPacketBufferPool', 'IOSkywalkPacketBufferPool'))

def vtable_name(cls):
    return '__ZTV' + str(len(cls)) + cls
METHOD_KEYS = {}

def prime_method_keys(names):
    names = sorted(set(names) - METHOD_KEYS.keys())
    if not names:
        return
    for name, readable in zip(names, dem(names)):
        key = readable.split('::', 1)[-1].replace('ether_addr_t', 'ether_addr')
        destructor = re.search('D([012])Ev$', name)
        METHOD_KEYS[name] = 'destructor' + destructor[1] if destructor else key

def method_key(name):
    if name not in METHOD_KEYS:
        prime_method_keys([name])
    return METHOD_KEYS[name]

def table(image, cls, kernel=None):
    if isinstance(image, ReferenceImage):
        return list(image.tables[cls])
    sym = image.names[vtable_name(cls)]
    start = sym[4]
    end = min((s[4] for s in image.syms if s[2] == sym[2] and s[4] > start))
    relocs = image.relocs()
    result = []
    for address in range(start + 16, end, 8):
        raw = struct.unpack('<Q', image.read(address, 8))[0]
        if address in relocs and relocs[address][0] != 'LOCAL':
            name = relocs[address][0]
        elif raw:
            if kernel and raw >> 48 != 65535:
                if raw >> 30 & 3 or raw >> 63:
                    raise ValueError('Unsupported kernel collection fixup')
                target = (raw & 1073741823) + kernel.fixup_base
            else:
                target = raw
            names = image.byaddr.get(target, []) or (kernel.byaddr.get(target, []) if kernel else [])
            if not names:
                raise ValueError(f'Unnamed vtable entry {cls}: {address:#x} -> {target:#x}')
            name = names[0]
        else:
            break
        result.append(name)
    if not result:
        raise ValueError(f'Empty vtable: {cls}')
    return result

class NativeModel:

    def __init__(self, system='Tahoe'):
        self.system = system
        self.profile = SYSTEMS[system]
        for key, expected in EXPECTED_SOURCES.items():
            if hashlib.sha256(PATHS[key].read_bytes()).hexdigest() != expected:
                raise ValueError(f'Unsupported source payload: {key}')
        self.old = Mach(PATHS['OldSky'])
        self.native = sky(system)
        self.kernel = Mach(self.native.path, 'com.apple.kernel')
        major = self.kernel.names['_version_major'][4]
        if struct.unpack('<I', self.kernel.read(major, 4))[0] != self.profile['kernel']:
            raise ValueError('Reference system kernel does not match its profile')
        if self.native.uuid != self.profile['skywalk']:
            raise ValueError('Reference Skywalk UUID does not match its profile')
        self.airport_source = 'BrcmTahoe' if self.profile['kernel'] == 25 else 'BrcmOriginal'
        self.images = {'Legacy': Mach(PATHS['Legacy']), 'BrcmTahoe': Mach(PATHS[self.airport_source])}
        self.old_tables = {}
        self.new_tables = {}
        self.old_views = {}
        self.tables = {}
        self.holes = []
        all_names = []
        for cls in NATIVE_CLASSES:
            all_names.extend(table(self.old, cls))
            all_names.extend(table(self.native, cls, self.kernel))
        for label, cls, parent in LEGACY_CLASSES:
            all_names.extend(table(self.images[label], cls))
        prime_method_keys(all_names)
        for cls in NATIVE_CLASSES:
            old = table(self.old, cls)
            new = table(self.native, cls, self.kernel)
            self.old_tables[cls] = old
            self.new_tables[cls] = new
            keyed = {method_key(n): i for i, n in enumerate(new)}
            entries = []
            for offset, name in enumerate(old):
                key = method_key(name)
                if key in keyed:
                    entries.append(('native', cls, keyed[key] * 8))
                else:
                    entries.append(('absent', name, 0))
                    self.holes.append((cls, offset * 8, name))
            self.old_views[cls] = entries
            self.tables[cls] = [('native', cls, i * 8) for i in range(len(new))]
        for label, cls, parent in LEGACY_CLASSES:
            image = self.images[label]
            old = table(image, cls)
            self.old_tables[cls] = old
            parent_old = self.old_tables[parent]
            parent_new = self.new_tables[parent]
            keyed = {method_key(n): i for i, n in enumerate(parent_new)}
            new = list(parent_new)
            physical = list(self.tables[parent])
            logical = []
            for i, name in enumerate(old):
                key = method_key(name)
                if i < len(parent_old) and name == parent_old[i]:
                    logical.append(self.old_views[parent][i])
                    continue
                if name in image.defined():
                    entry = (label, name, image.names[name][4])
                elif name in self.images['Legacy'].defined():
                    entry = ('Legacy', name, self.images['Legacy'].names[name][4])
                elif key in keyed:
                    entry = self.tables[parent][keyed[key]]
                else:
                    entry = ('absent', name, 0)
                logical.append(entry)
                if i < len(parent_old) and key in keyed:
                    slot = keyed[key]
                    new[slot] = name
                    physical[slot] = entry
                elif i >= len(parent_old):
                    new.append(name)
                    physical.append(entry)
                elif entry[0] != 'absent':
                    raise ValueError(f'Unmapped override: {cls} {name}')
            self.new_tables[cls] = new
            self.old_views[cls] = logical
            self.tables[cls] = physical

    def describe(self):
        sources = {'OldSky': PATHS['OldSky'], 'Legacy': PATHS['Legacy'], 'AirPort': PATHS[self.airport_source]}
        classes = {cls: {
            'oldSlotCount': len(self.old_tables[cls]), 'nativeSlotCount': len(self.new_tables[cls]),
            'oldMethods': self.old_tables[cls], 'nativeMethods': self.new_tables[cls],
            'legacyView': self.old_views[cls], 'nativeView': self.tables[cls],
        } for cls in self.tables}
        return {
            'copyright': 'Copyright © 2026 laobamac. All rights reserved.',
            'purpose': 'Raw ABI evidence used by native_payload.py; build.py validates the executable adapter',
            'implementationStatus': 'implemented', 'hardwareValidation': 'not-run-by-build',
            'system': self.system, 'nativeUUID': self.native.uuid, 'airPortSource': self.airport_source,
            'sourceSHA256': {key: hashlib.sha256(path.read_bytes()).hexdigest() for key, path in sources.items()},
            'classes': classes, 'removedMethods': self.holes, 'layouts': self.layouts(), 'imports': self.imports(),
        }

    def layouts(self):
        result = {}
        for cls in NATIVE_CLASSES:
            result[cls] = {'old': class_size(self.old, cls), 'native': class_size(self.native, cls)}
        for label, cls, parent in LEGACY_CLASSES:
            image = self.images[label]
            ktv = '__ZL' + str(len(cls) + 4) + cls + '_ktv'
            result[cls] = {'old': class_size(image, cls), 'parent': parent, 'allocationTypeView': image.names[ktv][4], 'allocationTypeSize': struct.unpack('<I', image.read(image.names[ktv][4] + 44, 4))[0]}
        return result

    def imports(self):
        result = {}
        for label, image in self.images.items():
            references = image.undef() & self.old.defined()
            absent = references - self.native.defined()
            result[label] = {'oldSkywalkImports': len(references), 'missingInNative': sorted(absent), 'relocations': {name: [address for address, entry in image.relocs().items() if entry[0] == name] for name in sorted(absent)}}
        return result

    def close(self):
        for image in [self.old, self.native, self.kernel, *self.images.values()]:
            image.close()

def class_size(image, cls):
    name = '__ZN' + str(len(cls)) + cls + '9MetaClassC2Ev'
    address, data = image.funcbytes(name)
    sizes = [int(match[1]) for _, _, text, _ in insns(data, address) if (match := re.fullmatch('movl\\s+\\$(\\d+), %ecx', text))]
    if len(sizes) != 1:
        raise ValueError(f'Ambiguous class-size initializer: {cls}')
    return sizes[0]

def verify_model(model):
    checks = []

    def require(condition, name):
        if not condition:
            raise ValueError('ABI verification failed: ' + name)
        checks.append(name)
    require(model.native.uuid == model.profile['skywalk'], model.system + ' native UUID')
    require(len(model.tables) == 18, '18 class tables decoded')
    for cls, old_size, native_size in [('IOSkywalkInterface', 184, 176), ('IOSkywalkNetworkInterface', 208, 224 if model.profile['kernel'] == 25 else 208), ('IOSkywalkEthernetInterface', 272, model.profile['ethernetSize']), ('IOSkywalkPacketBufferPool', 184, model.profile['poolSize']), ('IOSkywalkPacket', 120, 112), ('IOSkywalkNetworkPacket', 128, 120)]:
        require(class_size(model.old, cls) == old_size and class_size(model.native, cls) == native_size, cls + ' class sizes')
    cls = 'IOSkywalkEthernetInterface'
    require(len(model.new_tables[cls]) == model.profile['ethernetSlots'], 'Native Ethernet vtable length')
    if model.profile['kernel'] == 25:
        require('initBSDInterfaceParameters' in model.old_tables[cls][2256 // 8] and 'registerNetworkInterfaceWithLogicalLink' in model.new_tables[cls][2256 // 8], 'Ethernet vtable collision at 0x8d0')
        require('hwConfigNicProxyData' in model.old_tables[cls][2736 // 8] and '_RESERVEDIOSkywalkEthernetInterface0' in model.new_tables[cls][2736 // 8], 'Ethernet reserved-slot collision at 0xab0')
    old = model.images['Legacy']
    require(old.read(683934, 7) == bytes.fromhex('48898318010000'), 'Legacy controller pointer store at this+0x118')
    name = '__ZN26IOSkywalkEthernetInterface4initEP12OSDictionary'
    address = model.native.names[name][4]
    offset = model.profile['ethernetSize'] - 8
    require(model.native.read(address + 38, 7) == b'\x48\x89\x83' + struct.pack('<I', offset), f'Native expansion pointer store at this+{offset:#x}')
    refs = model.imports()
    require(refs['Legacy']['oldSkywalkImports'] == 113 and refs['BrcmTahoe']['oldSkywalkImports'] == 148, 'Skywalk dependency counts')
    counts = {23: (1, 2), 24: (2, 3), 25: (2, 4)}[model.profile['kernel']]
    require((len(refs['Legacy']['missingInNative']), len(refs['BrcmTahoe']['missingInNative'])) == counts, 'Skywalk missing-entry counts')
    layouts = model.layouts()
    for label, cls, parent in LEGACY_CLASSES:
        require(layouts[cls]['old'] == layouts[cls]['allocationTypeSize'], cls + ' original allocation metadata')
    return checks

def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description='Read-only native ABI audit; does not produce a bootable driver')
    parser.add_argument('action', choices=['audit', 'verify'])
    parser.add_argument('--output', type=Path)
    parser.add_argument('--system', choices=list(SYSTEMS), default='Tahoe')
    args = parser.parse_args()
    model = NativeModel(args.system)
    try:
        result = model.describe()
        checks = verify_model(model) if args.action == 'verify' else []
        result['auditChecks'] = checks
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'nativeUUID': model.native.uuid, 'classes': len(model.tables), 'removedSlots': len(model.holes), 'auditChecksPassed': len(checks), 'outputKind': 'abi-audit'}, indent=2))
    finally:
        model.close()
if __name__ == '__main__':
    main()
