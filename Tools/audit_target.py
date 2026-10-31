#!/usr/bin/env python3
#
#  audit_target.py
#  SimpleBCM
#
#  Created by laobamac on 2026/10/30.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import json
from pathlib import Path

from audit_dependencies import audit
from kernel_collection import KernelCollection, system_version
from configure import SYSTEMS


ROOT = Path(__file__).resolve().parent.parent
SEQUOIA_GUARDS = [
    (0x1BB156, 'be84030000', 'Associate request: 900 bytes'),
    (0xF9274, 'becc010000', 'AssociationDone event: 460 bytes'),
    (0x122761, '894b0c894b08', 'Join status fields at 12 and 8'),
    (0x12276B, '8983c8010000', 'Raw extended status at 456'),
    (0x122774, '4889de', 'Joined BSSID at the start of the event'),
]
SONOMA_GUARDS = [
    (0x17C25F, 'be58030000', 'Associate buffer: 856 bytes'),
    (0x17C288, 'b958030000', 'Associate request limit: 856 bytes'),
    (0x14A4F9, '817918cc040000', 'Scan result: 1228 bytes'),
    (0x14A604, '83f810b910000000', 'Capabilities: 16 bytes'),
    (0x17E6FB, '41817c2418e0140000', 'Scan multiple: 5344 bytes'),
    (0x14F5BF, '8379187c', 'Roam profile: 124 bytes'),
    (0x1BDE34, '4881fab8000000', 'DriverAvailable: 184 bytes'),
    (0x17881E, '483d303c0000', 'Command packet: 15408 bytes'),
    (0x17994C, '483d30c00300', 'Large command packet: 245808 bytes'),
]
TARGETS = {
    '23J620': ('Sonoma', 'ec4ba6726e083ad2b88201690a960ff4', SONOMA_GUARDS),
    '24H23': ('Sequoia', '13d3592aa6be35e7984c0acd90a76356', SEQUOIA_GUARDS),
}


def validate(volume, configuration):
    from verify import source_fingerprint

    build, kernel = system_version(volume)
    if build not in TARGETS:
        raise RuntimeError(f'No analyzed native ABI profile for target build {build}')
    system, uuid, instructions = TARGETS[build]
    if int(kernel.split('.')[0]) != SYSTEMS[system]:
        raise RuntimeError('Target system and kernel versions differ')
    dependency_path = ROOT / f'build/DependencySymbols-{system}-{configuration}.json'
    dependencies = audit(configuration, volume, dependency_path)
    collection = KernelCollection(Path(volume) / 'System/Library/KernelCollections/BootKernelExtensions.kc')
    try:
        native = collection.images['com.apple.iokit.IO80211Family']
        if dependencies['OSBuild'] != build or native.uuid != uuid:
            raise RuntimeError(f'This offline ABI audit requires the analyzed {system} {build} IO80211Family image')
        guards = []
        for offset, value, meaning in instructions:
            expected = bytes.fromhex(value)
            if native.read(native.base + offset, len(expected)) != expected:
                raise RuntimeError(f'{system} ABI instruction differs at {offset:#x}')
            guards.append({'offset': hex(offset), 'bytes': value, 'meaning': meaning})
        report = {
            'copyright': 'Copyright © 2026 laobamac. All rights reserved.',
            'configuration': configuration,
            'system': system,
            'sourceFingerprint': source_fingerprint()[0],
            'OSBuild': dependencies['OSBuild'],
            'kernel': collection.version(),
            'nativeIO80211UUID': native.uuid,
            'validatedInstructions': guards,
            'validationMode': 'target-volume-static',
            'dependencySymbols': dependency_path.name,
            'binarySHA256': dependencies['images']['SimpleBCM']['sha256'],
            'airPortSHA256': dependencies['images']['AirPort']['sha256'],
            'nativeConsumerExecuted': False,
            'openCoreLinkExecuted': False,
            'hardwareValidation': 'pending',
        }
    finally:
        collection.close()
    (ROOT / f'build/Validation-{system}-{configuration}.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target-volume', required=True, type=Path)
    parser.add_argument('--configuration', choices=['Debug', 'Release'], default='Release')
    args = parser.parse_args()
    print(json.dumps(validate(args.target_volume, args.configuration), indent=2))
