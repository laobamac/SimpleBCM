#!/usr/bin/env python3
#
#  system_profiles.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/2.
#  Copyright © 2026 laobamac. All rights reserved.
#

import json
import os
import platform
import plistlib
from pathlib import Path


SYSTEMS = {
    'Sonoma': {'kernel': 23, 'version': '14.8.8', 'build': '23J620',
               'skywalk': '9F5908B5-BA4B-37E3-AC31-62E1D45F1589',
               'wireless': 'EC4BA672-6E08-3AD2-B882-01690A960FF4',
               'ethernetSize': 272, 'poolSize': 184, 'ethernetSlots': 353},
    'Sequoia': {'kernel': 24, 'version': '15.8', 'build': '24H23',
                'skywalk': '70DFAA8E-E369-3417-B6FD-B19FB6D5D49B',
                'wireless': '13D3592A-A6BE-35E7-984C-0ACD90A76356',
                'ethernetSize': 272, 'poolSize': 184, 'ethernetSlots': 352},
    'Tahoe': {'kernel': 25, 'version': '26.7.3', 'build': '25G416',
              'skywalk': 'A6EDB8DB-175B-3A49-8919-5769FCDB6BED',
              'wireless': '33F057C9-BB1A-3FB7-8033-1FA2A0DD3601',
              'ethernetSize': 288, 'poolSize': 192, 'ethernetSlots': 353},
    'GoldenGate': {'kernel': 27, 'version': '27.2', 'build': '26B123',
                   'skywalk': 'BAC5AA66-9C9C-356A-AC86-A25F04A07E27',
                   'wireless': 'FCFF2E2C-C353-3ED2-90CA-A7776A68E892',
                   'ethernetSize': 288, 'poolSize': 192, 'ethernetSlots': 358},
}


def system_volumes():
    found = {}
    reference_root = os.environ.get('SIMPLEBCM_REFERENCE_ROOT')
    candidates = ([Path(reference_root) / name for name in SYSTEMS] if reference_root else
                  [Path('/'), Path('/Volumes/Macintosh HD 1'), Path('/Volumes/Macintosh HD 2'),
                   Path('/Volumes/macOS GoldenGate')])
    for volume in candidates:
        path = volume / 'System/Library/CoreServices/SystemVersion.plist'
        if not path.is_file():
            continue
        info = plistlib.loads(path.read_bytes())
        for name, profile in SYSTEMS.items():
            if (info.get('ProductVersion'), info.get('ProductBuildVersion')) == (profile['version'], profile['build']):
                found.setdefault(name, volume)
    return found


def system_volume(name):
    result = system_volumes().get(name)
    if result is None:
        raise ValueError(f'Missing reference system: {name} {SYSTEMS[name]["build"]}')
    return result


def validate_reference_systems():
    from kernel_collection import KernelCollection
    from native_references import reference_paths

    if platform.system() != 'Darwin' or platform.machine() != 'x86_64':
        raise RuntimeError('Build validation requires an Intel Mac')
    references = reference_paths()
    report = {}
    for name, profile in SYSTEMS.items():
        path = references[name]
        collection = KernelCollection(path)
        try:
            if int(collection.version().split('.')[0]) != profile['kernel']:
                raise RuntimeError(f'{name}: kernel version differs from the reference profile')
            for field, identifier in [('skywalk', 'com.apple.iokit.IOSkywalkFamily'),
                                      ('wireless', 'com.apple.iokit.IO80211Family')]:
                image = collection.images.get(identifier)
                if image is None or image.uuid != profile[field].replace('-', '').lower():
                    raise RuntimeError(f'{name}: {identifier} UUID differs from the reference profile')
            report[name] = {'reference': str(path), 'build': profile['build'],
                            'kernel': collection.version(), 'skywalkUUID': profile['skywalk'],
                            'wirelessUUID': profile['wireless']}
        finally:
            collection.close()
    return report


if __name__ == '__main__':
    print(json.dumps(validate_reference_systems(), indent=2))
