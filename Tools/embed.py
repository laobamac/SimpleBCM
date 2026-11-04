#!/usr/bin/env python3
#
#  embed.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/1.
#  Copyright © 2026 laobamac. All rights reserved.
#

import hashlib
import json
import plistlib
import re
import struct
import subprocess

from bootstrap import ROOT, validate_payloads
from macho import Image
from profiles import IMAGES, SYMBOLS, HARDWARE_VERSION_SYMBOL, ROUTE_SYMBOLS
from native_payload import SkywalkPlan, emit_system_profiles, prepare_native_guards
from system_profiles import SYSTEMS


OUTPUT = ROOT / 'build/Embedded'
LABELS = ['Legacy', 'AirPortOriginal', 'AirPort']
VERSION = '1.2.0'
ALIASES = {
    '__ZN26IOSkywalkEthernetInterface18getHardwareAddressEP12ether_addr_t':
        '__ZN26IOSkywalkEthernetInterface18getHardwareAddressEP10ether_addr',
    '__ZN26IOSkywalkEthernetInterface19setLinkLayerAddressEP12ether_addr_t':
        '__ZN26IOSkywalkEthernetInterface19setLinkLayerAddressEP10ether_addr',
    '__ZN26IOSkywalkEthernetInterface21setMulticastAddressesEPK12ether_addr_tj':
        '__ZN26IOSkywalkEthernetInterface21setMulticastAddressesEPK10ether_addrj',
}


def header(name):
    return f'//\n//  {name}\n//  SimpleBCM\n//\n//  Created by laobamac on 2026/11/1.\n//  Copyright © 2026 laobamac. All rights reserved.\n//\n'


def align(value, alignment=4096):
    return (value + alignment - 1) & -alignment


def checksum(data):
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & 0xffffffffffffffff
    return value


def payload_delta(base, target):
    if not target or len(target) > len(base):
        raise ValueError('Payload delta requires a base at least as large as its target')
    ranges = []
    for offset, (before, after) in enumerate(zip(base, target)):
        if before == after:
            continue
        if ranges and offset - ranges[-1][1] <= 8:
            ranges[-1][1] = offset + 1
        else:
            ranges.append([offset, offset + 1])
    encoded = b''.join(struct.pack('<II', start, end - start) + target[start:end] for start, end in ranges)
    restored = bytearray(base[:len(target)])
    position = 0
    while position < len(encoded):
        offset, length = struct.unpack_from('<II', encoded, position)
        position += 8
        restored[offset:offset + length] = encoded[position:position + length]
        position += length
    if restored != target:
        raise ValueError('Payload delta does not reconstruct the target')
    return encoded, len(ranges)


def parse(image):
    commands = []
    position = 32
    for _ in range(struct.unpack_from('<I', image.data, 16)[0]):
        command, size = struct.unpack_from('<II', image.data, position)
        commands.append((command, bytearray(image.data[position:position + size])))
        position += size
    sym = next(data for cmd, data in commands if cmd == 2)
    off, count, strings, length = struct.unpack_from('<4I', sym, 8)
    symbols = []
    for i in range(count):
        no, kind, sect, desc, value = struct.unpack_from('<IBBHQ', image.data, off + i * 16)
        assert no < length
        name = image.data[strings + no:strings + length].split(b'\0', 1)[0].decode()
        symbols.append((name, kind, sect, desc, value))
    return commands, symbols


def route_prefixes(image, label):
    names = ROUTE_SYMBOLS[label]
    result = []
    for name in names:
        text = subprocess.check_output(['xcrun', 'llvm-objdump', '--arch=x86_64', '-d',
                                       '--disassemble-symbols=' + name, str(image.path)], text=True)
        start = image.symbols[name]
        end = start
        for line in text.splitlines():
            match = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(.*)', line)
            if not match:
                continue
            address = int(match[1], 16)
            if address != end:
                raise RuntimeError(f'Non-contiguous route prefix: {name}')
            instruction = match[3]
            if '%rip' in instruction or re.match(r'(j\w*|call\w*|ret\w*|loop\w*)\b', instruction):
                raise RuntimeError(f'Non-relocatable route prefix: {name}: {instruction}')
            end += len(match[2].split())
            if end - start >= 14:
                break
        if not 14 <= end - start <= 32:
            raise RuntimeError(f'Invalid route prefix: {name}')
        result.append((start, end - start))
    return result


def generate():
    validate_payloads()
    plans = [SkywalkPlan(system) for system in SYSTEMS]
    plan = plans[-1]
    for candidate in plans:
        for field in ('namespace', 'compat', 'methods', 'method_slots', 'native_names', 'client_symbols',
                      'packet_calls', 'vptr_sites', 'pool_meta', 'pool_type', 'power_template', 'power_states'):
            if getattr(candidate, field) != getattr(plan, field):
                raise ValueError(f'Profiles require distinct {field}: {candidate.system}')
        for cls in ('IOSkywalkNetworkPacket', 'AirPort_Brcm43xxSkywalkPacket'):
            if candidate.model.tables[cls] != plan.model.tables[cls]:
                raise ValueError('Packet implementation differs across systems: ' + cls)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    images = [Image(IMAGES[label]) for label in LABELS]
    parsed = [parse(image) for image in images]
    exports = [{name: value for name, kind, _, _, value in symbols if kind & 0xf == 0xf}
               for _, symbols in parsed]
    native = set(plan.native_names) | prepare_native_guards(plans)
    vtable_guards = set()
    for index, (image, (commands, symbols)) in enumerate(zip(images, parsed)):
        fields = struct.unpack_from('<18I', next(data for cmd, data in commands if cmd == 11), 8)
        references = {}
        for n in range(fields[15]):
            offset, bits = struct.unpack_from('<iI', image.data, fields[14] + n * 8)
            if bits >> 28 == 0:
                references[offset] = symbols[bits & 0xffffff]
        boundaries = sorted(set(image.symbols.values()))
        internal = set(exports[index]) | (set(exports[0]) if index else set())
        for name, address in image.symbols.items():
            child = re.fullmatch(r'__ZN(\d+)(.*)10superClassE', name)
            if not child or len(child[2]) != int(child[1]) or address not in references:
                continue
            parent = re.fullmatch(r'__ZN(\d+)(.*)10gMetaClassE', references[address][0])
            if not parent or len(parent[2]) != int(parent[1]):
                continue
            child_name = '__ZTV' + child[1] + child[2]
            parent_name = '__ZTV' + parent[1] + parent[2]
            if child_name not in image.symbols or parent_name in internal or 'IOSkywalk' in parent_name:
                continue
            start = image.symbols[child_name]
            end = min(value for value in boundaries if value > start)
            for slot in range(start + 16, end, 8):
                if slot not in references:
                    continue
                method, kind, _, _, _ = references[slot]
                if kind & 14 == 0 and method.startswith(('__ZN', '__ZNK')):
                    vtable_guards.add((parent_name, slot - start, method))
                    native.update((parent_name, method))
    for index, (_, symbols) in enumerate(parsed):
        for name, kind, _, _, _ in symbols:
            if kind & 0xf != 1:
                continue
            name = ALIASES.get(name, name)
            if plan.resolve(name) is None and not (index and name in exports[0]):
                native.add(name)
    native = sorted(native)
    native_index = {name: i for i, name in enumerate(native)}
    cpp = [header('Payloads.cpp'), '#include "Payload.hpp"', '#include "NativeProfile.hpp"', 'namespace bcm {']
    assembly = [header('Payloads.S'), '.section __TEXT,__const', '.p2align 3']
    descriptors = []
    expanded_images = []
    tables = {}

    def emit_table(kind, name, rows):
        rows = tuple(rows)
        key = (kind, rows)
        if key not in tables:
            cpp.append(f'static const {kind} {name}[] = {{')
            cpp.extend(row + ',' for row in rows)
            cpp.append('};')
            tables[key] = name
        return tables[key]

    manifest = {'version': VERSION, 'nativeImports': native, 'payloads': [], 'driverLoading': 'embedded',
                'hardwareValidation': 'not-run-by-build', 'skywalkBackend': 'native', 'nativeAdapter': plan.manifest(),
                'systemProfiles': [candidate.manifest() for candidate in plans]}
    for field in ('system', 'kernel', 'build', 'nativeUUID', 'wirelessUUID', 'ethernetSize', 'poolSize',
                  'nativeSlotCount', 'ethernetLinkSymbol', 'ethernetLinkSlot', 'airPortPayloadIndex'):
        del manifest['nativeAdapter'][field]
    library_versions = {}
    library_ids = set()
    for index, (label, image, (commands, symbols)) in enumerate(zip(LABELS, images, parsed)):
        logical_index = int(index != 0)
        image_plan = plans[0] if label == 'AirPortOriginal' else plan
        info = plistlib.loads((image.path.parent.parent / 'Info.plist').read_bytes())
        library_ids.add(info['CFBundleIdentifier'])
        for library, version in info['OSBundleLibraries'].items():
            library_versions.setdefault(library, set()).add(version)
        branches = 0
        relocations = []
        ds = next(data for cmd, data in commands if cmd == 11)
        dsfields = struct.unpack_from('<18I', ds, 8)
        for external, field in [(True, 14), (False, 16)]:
            for n in range(dsfields[field + 1]):
                address, bits = struct.unpack_from('<iI', image.data, dsfields[field] + n * 8)
                kind, width, pcrel, ext = bits >> 28, 1 << ((bits >> 25) & 3), (bits >> 24) & 1, (bits >> 27) & 1
                assert address >= 0 and bool(ext) == external
                assert (kind, width, pcrel) in [(0, 8, 0), (2, 4, 1)]
                addend = struct.unpack('<q' if width == 8 else '<i', image.read(address, width))[0]
                if ext:
                    name, stype, _, _, value = symbols[bits & 0xffffff]
                    if stype & 0xe == 0xe:
                        provider, target = logical_index, value
                    else:
                        assert stype & 0xe == 0 and value == 0
                        if name in ALIASES:
                            alias_index = list(ALIASES).index(name)
                            expected = image.symbols['__ZTV34AirPort_Brcm43xxLLSkywalkInterface'] + 16 + 0xa70 + alias_index * 16
                            assert address == expected and width == 8 and addend == 0
                            name = ALIASES[name]
                        candidates = [(0, exports[0][name])] if index and name in exports[0] else []
                        compatibility = plan.resolve(name)
                        if candidates:
                            provider, target = candidates[0]
                        elif compatibility is not None:
                            provider, target = 254, compatibility
                        else:
                            provider, target = 255, native_index[name]
                else:
                    assert kind == 0 and 0 < (bits & 0xffffff) <= len(image.sections)
                    provider, target, addend = logical_index, addend, 0
                assert provider in (254, 255) or 0 <= target < max(a + s for _, a, s, _, _ in image.segments)
                relocations.append((address, target, addend, provider, width))
                branches += width == 4

        def remap(offset):
            for _, address, _, start, size in image.segments:
                if start <= offset < start + size:
                    return address + offset - start
            raise RuntimeError(f'Unmapped file offset {offset:#x}')

        size = align(max(a + n for _, a, n, _, _ in image.segments))
        stub_size = align(branches * 16 + 4096)
        expanded = bytearray(size)
        for _, address, _, fileoff, length in image.segments:
            expanded[address:address + length] = image.data[fileoff:fileoff + length]
        symbol_values = []
        new_commands = []
        for cmd, data in commands:
            if cmd in (0x1d, 0x1e, 0x2b):
                continue
            if cmd == 0x19:
                address = struct.unpack_from('<Q', data, 24)[0]
                struct.pack_into('<Q', data, 40, address)
                count = struct.unpack_from('<I', data, 64)[0]
                for n in range(count):
                    pos = 72 + n * 80
                    off, _, _, nrel = struct.unpack_from('<4I', data, pos + 48)
                    assert nrel == 0
                    if off:
                        struct.pack_into('<I', data, pos + 48, remap(off))
            elif cmd == 2:
                off, _, strings, _ = struct.unpack_from('<4I', data, 8)
                struct.pack_into('<I', data, 8, remap(off))
                struct.pack_into('<I', data, 16, remap(strings))
                symbol_values = [remap(off + i * 16) + 8 for i, (_, kind, _, _, _) in enumerate(symbols)
                                 if not kind & 0xe0 and kind & 0xe == 0xe]
            elif cmd == 11:
                fields = list(struct.unpack_from('<18I', data, 8))
                for pos in [6, 8, 10, 12]:
                    if fields[pos + 1]:
                        fields[pos] = remap(fields[pos])
                fields[14:] = [0, 0, 0, 0]
                struct.pack_into('<18I', data, 8, *fields)
            new_commands.append(data)
        new_commands.append(struct.pack('<II16sQQQQiiII', 0x19, 72, b'__BCM_EXEC', size, stub_size,
                                        size, stub_size, 7, 5, 0, 0))
        load_commands = b''.join(new_commands)
        first_section = min(off for _, _, _, n, off in image.sections if n and off)
        assert 32 + len(load_commands) <= first_section
        expanded[32:first_section] = b'\0' * (first_section - 32)
        expanded[32:32 + len(load_commands)] = load_commands
        struct.pack_into('<II', expanded, 16, len(new_commands), len(load_commands))
        struct.pack_into('<I', expanded, 24, struct.unpack_from('<I', expanded, 24)[0] & ~0x80000000)
        kmod = image.symbols['_kmod_info']
        assert kmod + 196 <= size
        renamed = image_plan.namespace_payload(label, expanded)
        routes = route_prefixes(image, label)
        blob = OUTPUT / (label + '.bin')
        blob.write_bytes(expanded)
        expanded_images.append(bytes(expanded))
        base_index = 1 if label == 'AirPort' else index
        delta, delta_count = payload_delta(expanded_images[base_index], expanded) if label == 'AirPort' else (b'', 0)
        stored = delta if label == 'AirPort' else expanded
        stored_blob = OUTPUT / (label + '.delta') if label == 'AirPort' else blob
        if label == 'AirPort':
            stored_blob.write_bytes(stored)
        assembly += [f'.globl _bcmPayload{index}', f'_bcmPayload{index}:', f'.incbin "{stored_blob}"', '.p2align 3']
        cpp.append(f'extern "C" const uint8_t bcmPayload{index}[];')
        relocation_table = emit_table('Relocation', f'relocs{index}',
            (f'{{{a}, {t}, {v}LL, {p}, {w}, {{}}}}' for a, t, v, p, w in relocations))
        value_table = emit_table('uint32_t', f'values{index}', map(str, symbol_values))
        wanted = set(SYMBOLS[label]) | {'_kmod_info'}
        if label != 'Legacy':
            wanted.add(HARDWARE_VERSION_SYMBOL)
        named = sorted((n, image.symbols[n]) for n in wanted)
        symbol_table = emit_table('Symbol', f'symbols{index}', (f'{{{json.dumps(n)}, {v}}}' for n, v in named))
        route_table = emit_table('RoutePrefix', f'routes{index}', (f'{{{a}, {n}}}' for a, n in routes or [(0, 0)]))
        info['OSBundleLibraries']['cn.laobamac.SimpleBCM'] = VERSION
        info['OSBundleRequired'] = 'Root'
        if label == 'Legacy':
            info['IOKitPersonalities'] = {}
        plist = plistlib.dumps(info, sort_keys=False).decode()
        literal = json.dumps(plist).replace('?', '\\?')
        cpp.append(f'static const char plist{index}[] = {literal};')
        sha = hashlib.sha256(image.path.read_bytes()).hexdigest()
        delta_pointer = f'bcmPayload{index}' if delta else 'nullptr'
        descriptors.append(f'{{{json.dumps(info["CFBundleIdentifier"])}, "{sha}", bcmPayload{base_index}, {len(expanded_images[base_index])}, {delta_pointer}, {len(delta)}, {size}, {size + stub_size}, {size}, {stub_size}, {kmod}, plist{index}, {relocation_table}, {len(relocations)}, {value_table}, {len(symbol_values)}, {symbol_table}, {len(named)}, {route_table}, {len(routes)}, {checksum(expanded)}ULL}}')
        manifest['payloads'].append({'label': label, 'identifier': info['CFBundleIdentifier'], 'sourceSHA256': sha,
                                    'expandedSHA256': hashlib.sha256(expanded).hexdigest(), 'size': size,
                                    'mappedSize': size + stub_size, 'relocations': len(relocations), 'routes': routes,
                                    'kmodOffset': kmod, 'namespacedClassStrings': renamed, 'powerDomainPatches': [],
                                    'storage': {'kind': 'delta' if label == 'AirPort' else 'full', 'base': LABELS[base_index],
                                                'file': stored_blob.name, 'storedSize': len(stored), 'deltaRecords': delta_count,
                                                'storedSHA256': hashlib.sha256(stored).hexdigest(),
                                                'tables': [relocation_table, value_table, symbol_table, route_table]}})
    expanded_size = sum(len(data) for data in expanded_images)
    stored_size = sum(p['storage']['storedSize'] for p in manifest['payloads'])
    manifest['payloadStorage'] = {'format': 'shared-base-delta-v1', 'expandedBytes': expanded_size,
                                  'storedBytes': stored_size, 'savedBytes': expanded_size - stored_size}
    cpp += ['const Payload payloads[3] = {', ',\n'.join(descriptors), '};',
            f'const uint32_t nativeImportCount = {len(native)};', 'const char *const nativeImportNames[] = {',
            ',\n'.join(json.dumps(n) for n in native), '};',
            'const NativeVtableGuard nativeVtableGuards[] = {',
            ',\n'.join(f'{{{native_index[p]}, {o}, {native_index[m]}}}' for p, o, m in sorted(vtable_guards)),
            '};', f'const uint32_t nativeVtableGuardCount = {len(vtable_guards)};']
    sky_cpp, sky_assembly = plan.emit(native_index)
    cpp += sky_cpp + emit_system_profiles(plans, native_index) + ['}']
    assembly += ['.section __DATA_CONST,__const', '.p2align 3', '.globl _bcmNativeImports', '_bcmNativeImports:']
    assembly.extend('.quad ' + name for name in native)
    assembly += sky_assembly
    (OUTPUT / 'Payloads.cpp').write_text('\n'.join(cpp) + '\n')
    (OUTPUT / 'Payloads.S').write_text('\n'.join(assembly) + '\n')
    manifest['nativeLibraries'] = {name: sorted(versions) for name, versions in library_versions.items() if name not in library_ids}
    manifest['nativeVtableGuards'] = sorted(vtable_guards)
    manifest['nativeRuntimeGuards'] = {p.system: {
        'vtables': p.vtable_guards, 'classes': p.class_guards,
        'nativeOverrides': p.unchecked_overrides,
        'linkBytes': p.link_bytes.hex(), 'linkMask': p.link_mask.hex(), 'linkReferences': p.link_references,
    } for p in plans}
    (OUTPUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Embedded {len(images)} payloads, {len(native)} native imports; output: {OUTPUT}')


if __name__ == '__main__':
    generate()
