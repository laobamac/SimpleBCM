#!/usr/bin/env python3
#
#  check.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/2.
#  Copyright © 2026 laobamac. All rights reserved.
#

import ast
import json
import plistlib
import re
import xml.etree.ElementTree as ET

from bootstrap import ROOT
from build import VERSION, fragment, package_name
from system_profiles import SYSTEMS


def main():
    for path in (ROOT / 'Tools').glob('*.py'):
        ast.parse(path.read_text(), filename=str(path))
    for path in (ROOT / 'Docs').glob('*.json'):
        json.loads(path.read_text())
    assert {p.name for p in ROOT.glob('*.xcodeproj')} == {'SimpleBCM.xcodeproj'}
    project = ROOT / 'SimpleBCM.xcodeproj'
    for path in project.rglob('*.xcscheme'):
        for reference in ET.parse(path).iter('BuildableReference'):
            assert reference.attrib['ReferencedContainer'] == 'container:SimpleBCM.xcodeproj', path
    config = (ROOT / 'Config/Kernel.xcconfig').read_text()
    version = re.search(r'^MODULE_VERSION\s*=\s*(\S+)', config, re.M).group(1)
    assert version == VERSION, 'Driver and package versions differ'
    info = plistlib.loads((ROOT / 'SimpleBCM/Info.plist').read_bytes())
    assert info['OSBundleCompatibleVersion'] == VERSION
    assert info['CFBundleIdentifier'] == '$(PRODUCT_BUNDLE_IDENTIFIER)'
    libraries = info['OSBundleLibraries']
    assert 'as.vit9696.Lilu' not in libraries
    assert {'com.apple.iokit.IOSkywalkFamily', 'com.apple.iokit.IO80211Family'} <= libraries.keys()
    assert 'com.apple.iokit.IO80211FamilyLegacy' not in libraries
    for name in ['README.md', 'README.en.md']:
        document = (ROOT / name).read_text()
        assert f'version-{VERSION}-' in document, name
        for system in SYSTEMS:
            assert system in document, name
    for optional in (False, True):
        config = fragment(optional)
        expected = ['SimpleBCM.kext']
        if optional:
            expected = ['Lilu.kext', 'AirportBrcmFixup.kext'] + expected + [
                'AirportBrcmFixup.kext/Contents/PlugIns/AirPortBrcmNIC_Injector.kext']
        assert [entry['BundlePath'] for entry in config['Kernel']['Add']] == expected
        assert config['Kernel']['Block'] == [], 'Native frameworks must remain enabled'
        for entry in config['Kernel']['Add']:
            assert entry['Enabled'] and entry['Arch'] == 'x86_64'
            assert (entry['MinKernel'], entry['MaxKernel']) == ('23.0.0', '25.99.99')
        assert plistlib.loads(plistlib.dumps(config)) == config
    for configuration in ('Debug', 'Release'):
        assert package_name(configuration) == f'SimpleBCM-v{VERSION}-{configuration.upper()}'
        assert package_name(configuration, 'pre', 'a' * 40).endswith('-alpha-aaaaaaa')
    print('Source metadata, native configuration and version checks passed.')


if __name__ == '__main__':
    main()
