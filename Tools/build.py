#!/usr/bin/env python3
#
#  build.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/1.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import hashlib
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path

from bootstrap import ROOT, validate_payloads
from embed import ALIASES, LABELS, OUTPUT, VERSION, parse
from kernel_collection import KernelCollection
from macho import Image
from profiles import IMAGES
from system_profiles import SYSTEMS, validate_reference_systems
from native_references import reference_paths


CONFIGURATIONS = ('Debug', 'Release')


def package_name(configuration, channel='rel', sha=None):
    if configuration not in CONFIGURATIONS or channel not in ('pre', 'rel'):
        raise ValueError('Invalid package variant')
    name = f'SimpleBCM-v{VERSION}-{configuration.upper()}'
    if channel == 'rel':
        return name
    sha = sha or os.environ.get('GITHUB_SHA') or subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r'[0-9a-fA-F]{40}', sha):
        raise ValueError('Invalid commit SHA')
    return f'{name}-alpha-{sha[:7].lower()}'


HOST = r'''
//
//  RelocationValidation.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//
#include "Payload.hpp"
#include "NativeProfile.hpp"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

int main(int argc, char **argv) {
    assert(argc == 6);
    auto profile = bcm::nativeSystemForKernel(static_cast<uint32_t>(atoi(argv[4])));
    assert(profile && !bcm::nativeSystemForKernel(22) && !bcm::nativeSystemForKernel(26));
    std::vector<uintptr_t> imports(bcm::nativeImportCount);
    std::vector<uintptr_t> compatibility(bcm::compatibilityImportCount);
    FILE *f = fopen(argv[1], "rb");
    assert(f && fread(imports.data(), 8, imports.size(), f) == imports.size());
    assert(fread(compatibility.data(), 8, compatibility.size(), f) == compatibility.size());
    fclose(f);
    unsigned linkChecks = 0;
    if (profile->ethernetLinkPattern.size) {
        f = fopen(argv[5], "rb");
        uint64_t header[3];
        assert(f && fread(header, sizeof(header), 1, f) == 1);
        std::vector<uint8_t> text(header[2]);
        assert(fread(text.data(), 1, text.size(), f) == text.size());
        fclose(f);
        const auto &pattern = profile->ethernetLinkPattern;
        auto find = [&](const std::vector<uint8_t> &bytes, uintptr_t base) {
            return bcm::findNativeLink(bytes.data(), bytes.size(), base, pattern, imports.data(), imports.size());
        };
        assert(find(text, header[0]) == header[1]);
        ++linkChecks;
        constexpr uintptr_t slide = 0x20000000;
        for (auto &value : imports)
            value += slide;
        assert(find(text, header[0] + slide) == header[1] + slide);
        for (auto &value : imports)
            value -= slide;
        ++linkChecks;
        auto truncated = text;
        truncated.resize(pattern.size - 1);
        assert(!find(truncated, header[0]));
        ++linkChecks;
        auto damaged = text;
        const auto offset = header[1] - header[0];
        damaged[offset] ^= 0xff;
        assert(!find(damaged, header[0]));
        ++linkChecks;
        damaged = text;
        damaged[offset + pattern.references[0].offset] ^= 1;
        assert(!find(damaged, header[0]));
        ++linkChecks;
        auto duplicate = text;
        duplicate.insert(duplicate.end(), text.begin(), text.end());
        for (uint32_t i = 0; i < pattern.referenceCount; ++i) {
            const auto &reference = pattern.references[i];
            const auto position = text.size() + offset + reference.offset;
            const auto delta = imports[reference.target] - (header[0] + position + 4);
            const auto displacement = static_cast<int32_t>(delta);
            memcpy(duplicate.data() + position, &displacement, sizeof(displacement));
        }
        assert(!find(duplicate, header[0]));
        ++linkChecks;
    }
    const bool far = atoi(argv[3]) != 0;
    bcm::LinkedImage images[2] {};
    for (unsigned i = 0; i < 2; ++i) {
        auto &p = bcm::payloads[i ? profile->airPortPayloadIndex : 0];
        images[i] = {&p, static_cast<uint8_t *>(calloc(1, p.mappedSize)),
                     (far ? 0xffffff9000000000ULL : 0xffffff8010000000ULL) + i * 0x2000000ULL,
                     0, false, true};
        assert(images[i].memory);
        memcpy(images[i].memory, p.bytes, p.size);
    }
    unsigned long total = 0;
    for (unsigned i = 0; i < 2; ++i) {
        assert(bcm::relocateImage(images[i], images, 2, imports.data(), imports.size(), compatibility.data(), compatibility.size()));
        total += images[i].payload->relocationCount;
        char path[4096];
        snprintf(path, sizeof(path), "%s/%u.bin", argv[2], i);
        f = fopen(path, "wb");
        assert(f && fwrite(images[i].memory, 1, images[i].payload->mappedSize, f) == images[i].payload->mappedSize);
        fclose(f);
    }
    auto &image = images[0];
    const auto original = *image.payload;
    bcm::Payload altered = original;
    image.payload = &altered;
    auto reset = [&]() {
        altered = original;
        image.stubUsed = 0;
        memcpy(image.memory, original.bytes, original.size);
    };
    reset();
    image.memory[0] ^= 1;
    assert(!bcm::relocateImage(image, images, 2, imports.data(), imports.size(), compatibility.data(), compatibility.size()));
    reset();
    bcm::Relocation bad {original.size, 0, 0, 0, 8, {}};
    altered.relocations = &bad;
    altered.relocationCount = 1;
    assert(!bcm::relocateImage(image, images, 2, imports.data(), imports.size(), compatibility.data(), compatibility.size()));
    reset();
    bad = {0, bcm::nativeImportCount, 0, 255, 8, {}};
    altered.relocations = &bad;
    altered.relocationCount = 1;
    assert(!bcm::relocateImage(image, images, 2, imports.data(), imports.size(), compatibility.data(), compatibility.size()));
    reset();
    bad = {0, 0, 0, 253, 8, {}};
    altered.relocations = &bad;
    altered.relocationCount = 1;
    assert(!bcm::relocateImage(image, images, 2, imports.data(), imports.size(), compatibility.data(), compatibility.size()));
    reset();
    altered.stubSize = 0;
    assert(!bcm::allocateStub(image, 1));
    reset();
    image.editable = false;
    assert(!bcm::relocateImage(image, images, 2, imports.data(), imports.size(), compatibility.data(), compatibility.size()));
    for (auto &entry : images)
        free(entry.memory);
    printf("{\"relocations\":%lu,\"negativeCases\":6,\"nativeLinkChecks\":%u,\"farBranches\":%s}\n", total, linkChecks, far ? "true" : "false");
}
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fingerprint():
    files = [ROOT / name for name in ('README.md', 'README.en.md', 'NOTICE.md')]
    for folder in ['SimpleBCM', 'SimpleBCM.xcodeproj', 'Config', 'Tools', 'Probe', 'Docs', 'Resources', '.github']:
        files.extend(p for p in (ROOT / folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts and 'xcuserdata' not in p.parts and p.name != '.DS_Store')
    hashes = {str(p.relative_to(ROOT)): digest(p) for p in sorted(files)}
    return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()


def fragment(optional=False):
    entries = [('SimpleBCM.kext', 'SimpleBCM')]
    if optional:
        entries = [('Lilu.kext', 'Lilu'), ('AirportBrcmFixup.kext', 'AirportBrcmFixup')] + entries + [
            ('AirportBrcmFixup.kext/Contents/PlugIns/AirPortBrcmNIC_Injector.kext', '')]
    add = [dict(Arch='x86_64', BundlePath=path, Comment='SimpleBCM embedded stack' if exe == 'SimpleBCM' else 'User-supplied optional dependency',
                Enabled=True, ExecutablePath='Contents/MacOS/' + exe if exe else '', PlistPath='Contents/Info.plist',
                MinKernel='23.0.0', MaxKernel='25.99.99') for path, exe in entries]
    return {'Kernel': {'Add': add, 'Block': []}}


def save_plist(path, value):
    data = plistlib.dumps(value, sort_keys=False).decode()
    header = (f'<!--\n  {path.name}\n  SimpleBCM\n\n  Created by laobamac on 2026/11/1.\n'
              '  Copyright © 2026 laobamac. All rights reserved.\n-->\n')
    path.write_text(data.replace('<!DOCTYPE', header + '<!DOCTYPE', 1))


def native_addresses(collection, libraries):
    available = dict(collection.kernel.symbols)
    for name in libraries:
        if name in collection.images:
            image = collection.images[name]
            available.update({n: image.symbols[n] for n in image.exports})
    return available


def check_reference(folder, addresses, compatibility, far, labels):
    exports = []
    images = [Image(IMAGES[name]) for name in labels]
    for image in images:
        _, symbols = parse(image)
        exports.append({n: v for n, t, _, _, v in symbols if t & 15 == 15})
    bases = [(0xffffff9000000000 if far else 0xffffff8010000000) + i * 0x2000000 for i in range(len(labels))]
    checked = 0
    for i, image in enumerate(images):
        actual = (folder / f'{i}.bin').read_bytes()
        commands, symbols = parse(image)
        ds = next(data for cmd, data in commands if cmd == 11)
        fields = struct.unpack_from('<18I', ds, 8)
        for external, field in [(True, 14), (False, 16)]:
            for n in range(fields[field + 1]):
                offset, bits = struct.unpack_from('<iI', image.data, fields[field] + n * 8)
                width = 1 << ((bits >> 25) & 3)
                addend = int.from_bytes(image.read(offset, width), 'little', signed=True)
                if external:
                    name, kind, _, _, value = symbols[bits & 0xffffff]
                    if kind & 14 == 14:
                        target = bases[i] + value
                    else:
                        name = ALIASES.get(name, name)
                        matches = [(j, exports[j][name]) for j in range(min(i, 2)) if name in exports[j]]
                        target = bases[matches[0][0]] + matches[0][1] if matches else (compatibility[name] if name in compatibility else addresses[name])
                    expected = (target + addend) & 0xffffffffffffffff
                else:
                    expected = (bases[i] + addend) & 0xffffffffffffffff
                if width == 8:
                    observed = struct.unpack_from('<Q', actual, offset)[0]
                else:
                    displacement = struct.unpack_from('<i', actual, offset)[0]
                    observed = (bases[i] + offset + 4 + displacement) & 0xffffffffffffffff
                    if observed != expected:
                        stub = observed - bases[i]
                        assert 0 <= stub <= len(actual) - 14
                        assert actual[stub:stub + 6] == b'\xff\x25\0\0\0\0'
                        observed = struct.unpack_from('<Q', actual, stub + 6)[0]
                assert observed == expected, (labels[i], hex(offset), hex(observed), hex(expected))
                checked += 1
        linked = Image(folder / f'{i}.bin')
        _, linked_symbols = parse(linked)
        for n, (name, kind, _, _, value) in enumerate(symbols):
            if not kind & 0xe0 and kind & 14 == 14:
                assert linked_symbols[n][4] == value + bases[i], (n, name)
    return checked


def verify(configuration, references):
    validate_payloads()
    source_fingerprint = fingerprint()
    manifest = json.loads((OUTPUT / 'manifest.json').read_text())
    product = ROOT / f'build/DerivedData/Build/Products/{configuration}/SimpleBCM.kext'
    binary = product / 'Contents/MacOS/SimpleBCM'
    evidence = json.loads((ROOT / f'build/Build-{configuration}.json').read_text())
    assert evidence['sourceFingerprint'] == source_fingerprint
    assert evidence['sha256'] == digest(binary)
    assert evidence['payloadManifestSHA256'] == digest(OUTPUT / 'manifest.json')
    image = Image(binary)
    assert struct.unpack_from('<I', image.data, 12)[0] == 11
    symbols = product.parent / 'SimpleBCM.kext.dSYM/Contents/Resources/DWARF/SimpleBCM'
    assert Image(symbols).uuid == image.uuid
    info = plistlib.loads((product / 'Contents/Info.plist').read_bytes())
    assert info['CFBundleVersion'] == VERSION
    assert info['CFBundleIdentifier'] == 'cn.laobamac.SimpleBCM'
    assert not any('Lilu' in n for n in info['OSBundleLibraries'])
    undefined = set(subprocess.check_output(['nm', '-u', '-j', str(binary)], text=True).splitlines())
    assert not any('Lilu' in n or n in ['_lilu', '_lilu_os_log'] for n in undefined)
    assert '__ZN6OSKext8copyUUIDEv' not in undefined
    targets = []
    addresses = {}
    verified_references = {}
    for reference in references:
        c = KernelCollection(reference)
        kernel = int(c.version().split('.')[0])
        profiles = [p for p in manifest['systemProfiles'] if p['kernel'] == kernel]
        assert len(profiles) == 1, ('Unsupported reference kernel', c.version())
        profile = profiles[0]
        assert c.images['com.apple.iokit.IOSkywalkFamily'].uuid == profile['nativeUUID'].replace('-', '').lower()
        assert c.images['com.apple.iokit.IO80211Family'].uuid == profile['wirelessUUID'].replace('-', '').lower()
        available = native_addresses(c, info['OSBundleLibraries'])
        missing = sorted(undefined - available.keys())
        assert not missing, (str(reference), missing)
        for parent, offset, method in manifest['nativeRuntimeGuards'][profile['system']]['vtables']:
            assert c.pointer(available[parent] + offset) == available[method]
        for parent, offset, method in manifest['nativeVtableGuards']:
            observed = c.pointer(available[parent] + offset)
            assert observed == available[method], (str(reference), parent, offset, method)
        targets.append({'system': profile['system'], 'build': profile['build'],
                        'reference': str(reference), 'referenceKind': 'snapshot' if reference.suffix == '.json' else 'kernel-collection',
                        'kernel': c.version(), 'uuid': c.root.uuid,
                        'imports': len(undefined), 'unmatchedImports': [],
                        'nativeVtableGuards': len(manifest['nativeVtableGuards']),
                        'runtimeVtableGuards': len(manifest['nativeRuntimeGuards'][profile['system']]['vtables']),
                        'runtimeClassGuards': len(manifest['nativeRuntimeGuards'][profile['system']]['classes'])})
        addresses[profile['system']] = available
        verified_references[profile['system']] = reference
        c.close()
    assert addresses
    adapter = manifest['nativeAdapter']
    assert manifest['skywalkBackend'] == 'native' and LABELS == ['Legacy', 'AirPortOriginal', 'AirPort']
    assert 'com.apple.iokit.IOSkywalkFamily' in info['OSBundleLibraries']
    assert not any(p['identifier'] == 'com.apple.iokit.IOSkywalkFamily' for p in manifest['payloads'])
    with tempfile.TemporaryDirectory(prefix='simplebcm-verify-') as temporary:
        temp = Path(temporary)
        (temp / 'main.cpp').write_text(HOST)
        assembly = (OUTPUT / 'Payloads.S').read_text().split('.section __DATA_CONST')[0]
        (temp / 'Payloads.S').write_text(assembly)
        executable = temp / 'verify'
        subprocess.run(['xcrun', 'clang++', '-std=c++14', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I', str(ROOT / 'SimpleBCM'),
                        str(ROOT / 'SimpleBCM/Relocate.cpp'), str(OUTPUT / 'Payloads.cpp'), str(temp / 'Payloads.S'),
                        str(temp / 'main.cpp'), '-o', str(executable)], check=True)
        runs = []
        native_abi = {}
        from verify_native import verify_native
        for system, current in addresses.items():
            profile = SYSTEMS[system]
            from native_abi import Mach
            reference = Mach(verified_references[system], 'com.apple.iokit.IOSkywalkFamily')
            symbol = next(p['ethernetLinkSymbol'] for p in manifest['systemProfiles'] if p['system'] == system)
            if verified_references[system].suffix == '.json':
                start, code = reference.funcbytes(symbol)
            else:
                section = next(s for s in reference.sects if s[0] == '__text')
                start, length = section[2:4]
                code = reference.read(start, length)
            length = len(code)
            (temp / 'native-link.bin').write_bytes(struct.pack('<3Q', start, reference.names[symbol][4], length) +
                                                 code)
            reference.close()
            compatibility = {name: (current[target] if target in current else 0xffffff800f000000 + image.symbols[target])
                             for name, target in zip(adapter['compatibilityImports'], adapter['compatibilityTargets'])}
            (temp / 'imports.bin').write_bytes(b''.join(struct.pack('<Q', current[name]) for name in manifest['nativeImports']) +
                                               b''.join(struct.pack('<Q', compatibility[name]) for name in adapter['compatibilityImports']))
            labels = ['Legacy', 'AirPort' if profile['kernel'] == 25 else 'AirPortOriginal']
            for far in [False, True]:
                output = subprocess.check_output([str(executable), str(temp / 'imports.bin'), str(temp),
                                                  str(int(far)), str(profile['kernel']), str(temp / 'native-link.bin')], text=True)
                run = json.loads(output)
                run['system'] = system
                run['independentReferenceChecks'] = check_reference(temp, current, compatibility, far, labels)
                runs.append(run)
            native_abi[system] = verify_native(temp, binary, system)
        from verify import verify_abi
        abi = verify_abi(temp)
    assert source_fingerprint == fingerprint()
    result = {'version': VERSION, 'configuration': configuration, 'driverLoading': 'embedded',
              'sourceFingerprint': source_fingerprint, 'sha256': digest(binary), 'uuid': image.uuid,
              'probeSHA256': digest(product.parent / 'bcmprobe'), 'nativeTargets': targets,
              'relocationValidation': runs, 'sanitizers': ['AddressSanitizer', 'UndefinedBehaviorSanitizer'],
              'abiValidation': abi,
              'nativeABIValidation': native_abi,
              'baseAddEntries': len(fragment()['Kernel']['Add']), 'payloads': manifest['payloads'],
              'skywalkBackend': 'native', 'nativeAdapter': adapter, 'systemProfiles': manifest['systemProfiles'],
              'kernelRegistrationExecuted': False, 'openCoreLinkExecuted': False, 'hardwareValidation': 'not-run-by-build'}
    destination = ROOT / f'build/Validation-{configuration}.json'
    destination.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return result


def build(configuration, analyze=False):
    source_fingerprint = fingerprint()
    action = 'analyze' if analyze else 'build'
    log = ROOT / f'build/{action}-{configuration}.log'
    log.parent.mkdir(exist_ok=True)
    command = ['xcodebuild', '-project', str(ROOT / 'SimpleBCM.xcodeproj'), '-scheme', 'SimpleBCM',
               '-configuration', configuration, '-destination', 'generic/platform=macOS',
               '-derivedDataPath', str(ROOT / 'build/DerivedData'), action]
    with log.open('w') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    diagnostics = [line for line in log.read_text().splitlines() if any(s in line for s in ['error:', 'warning:', '** BUILD', '** ANALYZE'])]
    print('\n'.join(diagnostics))
    if result.returncode or any('warning:' in line for line in diagnostics):
        raise RuntimeError(f'Build diagnostics require attention: {log}')
    assert source_fingerprint == fingerprint(), 'Source changed during the build'
    if analyze:
        (ROOT / f'build/Analysis-{configuration}.json').write_text(json.dumps({
            'passed': True, 'sourceFingerprint': source_fingerprint, 'logSHA256': digest(log)}, indent=2) + '\n')
    else:
        binary = ROOT / f'build/DerivedData/Build/Products/{configuration}/SimpleBCM.kext/Contents/MacOS/SimpleBCM'
        (ROOT / f'build/Build-{configuration}.json').write_text(json.dumps({
            'sourceFingerprint': source_fingerprint, 'sha256': digest(binary), 'logSHA256': digest(log),
            'payloadManifestSHA256': digest(OUTPUT / 'manifest.json')}, indent=2) + '\n')


def package(configuration, channel='rel'):
    report = json.loads((ROOT / f'build/Validation-{configuration}.json').read_text())
    product = ROOT / f'build/DerivedData/Build/Products/{configuration}'
    assert report['sourceFingerprint'] == fingerprint()
    assert {target['system'] for target in report['nativeTargets']} == set(SYSTEMS)
    assert report['sha256'] == digest(product / 'SimpleBCM.kext/Contents/MacOS/SimpleBCM')
    assert report['probeSHA256'] == digest(product / 'bcmprobe')
    analysis = json.loads((ROOT / 'build/Analysis-Release.json').read_text())
    assert analysis['passed'] and analysis['sourceFingerprint'] == fingerprint()
    assert analysis['logSHA256'] == digest(ROOT / 'build/analyze-Release.log')
    name = package_name(configuration, channel)
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.package-', dir=dist) as temporary:
        stage = Path(temporary) / name
        shutil.copytree(product / 'SimpleBCM.kext', stage / 'EFI/OC/Kexts/SimpleBCM.kext')
        extra = stage / 'Extra'
        extra.mkdir()
        shutil.copy2(product / 'bcmprobe', extra / 'bcmprobe')
        shutil.copytree(product / 'SimpleBCM.kext.dSYM', extra / 'SimpleBCM.kext.dSYM')
        for filename in ('README.md', 'README.en.md', 'NOTICE.md'):
            shutil.copy2(ROOT / filename, stage / filename)
        shutil.copy2(ROOT / '.research/OpenCore-Legacy-Patcher/LICENSE.txt', extra / 'OCLP-LICENSE.txt')
        shutil.copy2(ROOT / 'Tools/collect.py', extra / 'collect.py')
        (stage / 'Docs').mkdir()
        for document in (ROOT / 'Docs').glob('*.md'):
            shutil.copy2(document, stage / 'Docs' / document.name)
        (extra / 'Validation.json').write_text(json.dumps(report, indent=2) + '\n')
        save_plist(stage / 'config.fragment.plist', fragment())
        save_plist(extra / 'config.AirportBrcmFixup.fragment.plist', fragment(True))
        files = {str(p.relative_to(stage)): digest(p) for p in stage.rglob('*') if p.is_file()}
        (extra / 'manifest.json').write_text(json.dumps({'version': VERSION, 'configuration': configuration,
                'files': files, 'hardwareValidation': 'not-run-by-build', 'driverLoading': 'embedded', 'skywalkBackend': 'native'}, indent=2) + '\n')
        archive = dist / (name + '.zip')
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as output:
            for path in sorted(stage.rglob('*')):
                if path.is_file():
                    output.write(path, str(Path(name) / path.relative_to(stage)))
        with zipfile.ZipFile(archive) as output:
            assert output.testzip() is None
            assert plistlib.loads(output.read(name + '/config.fragment.plist')) == fragment()
            for path, sha in files.items():
                assert hashlib.sha256(output.read(name + '/' + path)).hexdigest() == sha
    archive.with_suffix('.zip.sha256').write_text(f'{digest(archive)}  {archive.name}\n')
    print(archive)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['build', 'verify', 'analyze', 'package'])
    parser.add_argument('--configuration', choices=['Debug', 'Release'], default='Debug')
    parser.add_argument('--channel', choices=['pre', 'rel'], default='rel')
    parser.add_argument('--target-volume', type=Path, action='append')
    args = parser.parse_args()
    if args.action in ['build', 'verify', 'analyze']:
        validate_reference_systems()
    if args.action in ['build', 'analyze']:
        build(args.configuration, args.action == 'analyze')
    if args.action in ['verify', 'build']:
        references = ([volume / 'System/Library/KernelCollections/BootKernelExtensions.kc' for volume in args.target_volume]
                      if args.target_volume else list(reference_paths().values()))
        verify(args.configuration, references)
    if args.action == 'package':
        package(args.configuration, args.channel)


if __name__ == '__main__':
    main()
