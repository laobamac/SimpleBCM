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
from kernel_collection import KernelCollection


ROOT = Path(__file__).resolve().parent.parent
SEQUOIA_GUARDS = [
    (0x1BB156, 'be84030000', 'Associate request: 900 bytes'),
    (0xF9274, 'becc010000', 'AssociationDone event: 460 bytes'),
    (0x122761, '894b0c894b08', 'Join status fields at 12 and 8'),
    (0x12276B, '8983c8010000', 'Raw extended status at 456'),
    (0x122774, '4889de', 'Joined BSSID at the start of the event'),
]


def validate(volume, configuration):
    from verify import source_fingerprint

    dependency_path = ROOT / f'build/DependencySymbols-Sequoia-{configuration}.json'
    dependencies = audit(configuration, volume, dependency_path)
    collection = KernelCollection(Path(volume) / 'System/Library/KernelCollections/BootKernelExtensions.kc')
    try:
        native = collection.images['com.apple.iokit.IO80211Family']
        if dependencies['OSBuild'] != '24H23' or native.uuid != '13d3592aa6be35e7984c0acd90a76356':
            raise RuntimeError('This offline ABI audit requires the analyzed Sequoia 24H23 IO80211Family image')
        guards = []
        for offset, value, meaning in SEQUOIA_GUARDS:
            expected = bytes.fromhex(value)
            if native.read(native.base + offset, len(expected)) != expected:
                raise RuntimeError(f'Sequoia ABI instruction differs at {offset:#x}')
            guards.append({'offset': hex(offset), 'bytes': value, 'meaning': meaning})
        report = {
            'copyright': 'Copyright © 2026 laobamac. All rights reserved.',
            'configuration': configuration,
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
    (ROOT / f'build/Validation-Sequoia-{configuration}.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target-volume', required=True, type=Path)
    parser.add_argument('--configuration', choices=['Debug', 'Release'], default='Release')
    args = parser.parse_args()
    print(json.dumps(validate(args.target_volume, args.configuration), indent=2))
