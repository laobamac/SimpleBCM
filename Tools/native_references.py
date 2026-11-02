#!/usr/bin/env python3
#
#  native_references.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/3.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import collections
import functools
import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

from bootstrap import ROOT
from system_profiles import SYSTEMS, system_volumes


DIRECTORY = ROOT / 'Resources/NativeABI'
KERNEL = 'com.apple.kernel'
SKYWALK = 'com.apple.iokit.IOSkywalkFamily'
WIRELESS = 'com.apple.iokit.IO80211Family'


@functools.lru_cache(maxsize=None)
def load_reference(path):
    path = Path(path)
    index = json.loads((DIRECTORY / 'manifest.json').read_text())
    expected = index['files'][path.name]
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('Native ABI reference checksum mismatch: ' + path.name)
    reference = json.loads(data)
    if reference['schemaVersion'] != 1 or reference['profile'] != SYSTEMS[reference['system']]:
        raise ValueError('Native ABI reference profile mismatch: ' + path.name)
    return reference


def reference_paths():
    source = os.environ.get('SIMPLEBCM_NATIVE_SOURCE', 'snapshot')
    if source == 'snapshot':
        return {name: DIRECTORY / (name + '.json') for name in SYSTEMS}
    if source != 'system':
        raise ValueError('SIMPLEBCM_NATIVE_SOURCE must be snapshot or system')
    volumes = system_volumes()
    if set(volumes) != set(SYSTEMS):
        raise ValueError('All three reference system volumes are required for system mode')
    return {name: volumes[name] / 'System/Library/KernelCollections/BootKernelExtensions.kc' for name in SYSTEMS}


class ReferenceImage:
    def __init__(self, path, entry):
        self.path = str(path)
        self.reference = load_reference(self.path)['images'][entry]
        self.uuid = self.reference['uuid']
        exports = set(self.reference['exports'])
        self.names = {name: (name, 15 if name in exports else 14, 1, 0, address)
                      for name, address in self.reference['symbols'].items()}
        self.byaddr = collections.defaultdict(list)
        for name, symbol in self.names.items():
            self.byaddr[symbol[4]].append(name)
        self.tables = self.reference['tables']
        self.ranges = [(address, bytes.fromhex(data)) for address, data in self.reference['ranges']]

    def defined(self):
        return set(self.reference['exports'])

    def read(self, address, size):
        for start, data in self.ranges:
            if size >= 0 and start <= address and address + size <= start + len(data):
                return data[address - start:address - start + size]
        raise ValueError(f'Native ABI reference range missing: {address:#x}+{size:#x}')

    def funcbytes(self, name):
        address, data = self.reference['functions'][name]
        return address, bytes.fromhex(data)

    def close(self):
        pass


class ReferenceCollection:
    def __init__(self, path):
        self.path = Path(path)
        reference = load_reference(self.path)
        self.reference = reference
        self.root = SimpleNamespace(uuid=reference['collectionUUID'])
        self.images = {name: SimpleNamespace(symbols=image['symbols'], exports=set(image['exports']), uuid=image['uuid'])
                       for name, image in reference['libraries'].items()}
        self.kernel = self.images[KERNEL]

    def pointer(self, address):
        return self.reference['pointers'][str(address)]

    def version(self):
        return self.reference['kernelVersion']

    def close(self):
        pass


def export_references(binary):
    from embed import generate, OUTPUT
    from kernel_collection import KernelCollection
    from native_abi import NATIVE_CLASSES, table
    from native_payload import CLIENT_CLASSES, SkywalkPlan, prepare_native_guards

    os.environ['SIMPLEBCM_NATIVE_SOURCE'] = 'system'
    generate()
    manifest = json.loads((OUTPUT / 'manifest.json').read_text())
    required = set(manifest['nativeImports'])
    required.update(subprocess.check_output(['nm', '-u', '-j', str(binary)], text=True).splitlines())
    plans = [SkywalkPlan(name) for name in SYSTEMS]
    prepare_native_guards(plans)
    DIRECTORY.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for plan in plans:
        collection = KernelCollection(plan.native.path)
        images = {}
        for identifier, image, classes in (
            (KERNEL, plan.model.kernel, ('IOService',)),
            (SKYWALK, plan.native, NATIVE_CLASSES),
            (WIRELESS, plan.wireless, CLIENT_CLASSES),
        ):
            tables = {cls: table(image, cls, plan.model.kernel) for cls in classes}
            functions = {}
            ranges = []
            names = required | {n for methods in tables.values() for n in methods}
            names |= {name for name in image.defined() if name.endswith('10gMetaClassE')}
            if identifier == SKYWALK:
                names |= image.defined()
            if identifier != KERNEL:
                for cls in classes:
                    name = '__ZN' + str(len(cls)) + cls + '9MetaClassC2Ev'
                    address, data = image.funcbytes(name)
                    functions[name] = [address, data.hex()]
                    names.add(name)
            if identifier == KERNEL:
                for name in ('_version_major', '_version_minor', '_version_revision'):
                    address = image.names[name][4]
                    ranges.append([address, image.read(address, 4).hex()])
                    names.add(name)
            if identifier == SKYWALK:
                name = '__ZN26IOSkywalkEthernetInterface4initEP12OSDictionary'
                address = image.names[name][4] + 38
                ranges.append([address, image.read(address, 7).hex()])
                name = '__ZL13myPowerStates'
                address = image.names[name][4]
                ranges.append([address, image.read(address, 192).hex()])
                names.add(name)
                address, data = image.funcbytes(plan.link_symbol)
                functions[plan.link_symbol] = [address, data.hex()]
            if identifier == WIRELESS:
                for cls in CLIENT_CLASSES:
                    name = '__ZN' + str(len(cls)) + cls + '4freeEv'
                    address, data = image.funcbytes(name)
                    functions[name] = [address, data.hex()]
                    names.add(name)
            names |= set(functions)
            images[identifier] = {
                'uuid': image.uuid, 'symbols': {n: image.names[n][4] for n in sorted(names & image.names.keys())},
                'exports': sorted(names & image.defined()), 'tables': tables,
                'functions': functions, 'ranges': ranges,
            }
        libraries = {}
        for identifier in dict.fromkeys((KERNEL, *manifest['nativeLibraries'], WIRELESS)):
            if identifier not in collection.images:
                continue
            image = collection.images[identifier]
            libraries[identifier] = {
                'uuid': image.uuid,
                'symbols': {n: image.symbols[n] for n in sorted(required & image.symbols.keys())},
                'exports': sorted(required & image.exports),
            }
        pointers = {}
        for parent, offset, method in (*manifest['nativeVtableGuards'], *plan.vtable_guards):
            candidates = [image for image in collection.images.values() if parent in image.symbols]
            if len(candidates) != 1:
                raise ValueError('Ambiguous reference vtable: ' + parent)
            address = candidates[0].symbols[parent] + offset
            pointers[str(address)] = collection.pointer(address)
        section = next(s for s in plan.native.sects if s[0] == '__text')
        address, length = section[2:4]
        text = plan.native.read(address, length)
        matches = []
        if plan.link_bytes:
            for offset in range(len(text) - len(plan.link_bytes) + 1):
                if all((a & m) == (b & m) for a, b, m in zip(text[offset:offset + len(plan.link_bytes)], plan.link_bytes, plan.link_mask)):
                    matches.append(address + offset)
            if matches != [plan.native.names[plan.link_symbol][4]]:
                raise ValueError('Native logical-link pattern is not unique')
        reference = {
            'file': plan.system + '.json', 'project': 'SimpleBCM', 'createdBy': 'laobamac', 'createdOn': '2026/11/3',
            'copyright': 'Copyright © 2026 laobamac. All rights reserved.', 'schemaVersion': 1,
            'system': plan.system, 'profile': SYSTEMS[plan.system],
            'collectionUUID': collection.root.uuid, 'kernelVersion': collection.version(),
            'images': images, 'libraries': libraries, 'pointers': pointers,
            'linkSearch': {'textSHA256': hashlib.sha256(text).hexdigest(), 'matches': matches},
        }
        path = DIRECTORY / (plan.system + '.json')
        data = (json.dumps(reference, indent=2, ensure_ascii=False) + '\n').encode()
        path.write_bytes(data)
        hashes[path.name] = hashlib.sha256(data).hexdigest()
        collection.close()
        plan.wireless.close()
        plan.model.close()
    index = {'file': 'manifest.json', 'project': 'SimpleBCM', 'createdBy': 'laobamac', 'createdOn': '2026/11/3',
             'copyright': 'Copyright © 2026 laobamac. All rights reserved.', 'schemaVersion': 1, 'files': hashes}
    (DIRECTORY / 'manifest.json').write_text(json.dumps(index, indent=2) + '\n')
    load_reference.cache_clear()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('export', 'verify'))
    parser.add_argument('--binary', type=Path, default=ROOT / 'build/DerivedData/Build/Products/Release/SimpleBCM.kext/Contents/MacOS/SimpleBCM')
    args = parser.parse_args()
    if args.action == 'export':
        export_references(args.binary)
    for name in SYSTEMS:
        load_reference(DIRECTORY / (name + '.json'))
    print('Native ABI references verified: ' + ', '.join(SYSTEMS))


if __name__ == '__main__':
    main()
