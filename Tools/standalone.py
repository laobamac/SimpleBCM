#!/usr/bin/env python3
#
#  standalone.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/1.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import hashlib
import json
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from bootstrap import ROOT, validate_payloads
from embed import ALIASES, LABELS, OUTPUT, VERSION, parse
from kernel_collection import KernelCollection
from macho import Image
from profiles import IMAGES


HOST = r'''
//
//  RelocationValidation.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//
#include "Payload.hpp"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

int main(int argc, char **argv) {
    assert(argc == 4);
    std::vector<uintptr_t> imports(bcm::nativeImportCount);
    FILE *f = fopen(argv[1], "rb");
    assert(f && fread(imports.data(), 8, imports.size(), f) == imports.size());
    fclose(f);
    const bool far = atoi(argv[3]) != 0;
    bcm::LinkedImage images[4] {};
    for (unsigned i = 0; i < 4; ++i) {
        auto &p = bcm::payloads[i];
        images[i] = {&p, static_cast<uint8_t *>(calloc(1, p.mappedSize)),
                     (far ? 0xffffff9000000000ULL : 0xffffff8010000000ULL) + i * 0x2000000ULL,
                     0, false, true};
        assert(images[i].memory);
        memcpy(images[i].memory, p.bytes, p.size);
    }
    unsigned long total = 0;
    for (unsigned i = 0; i < 4; ++i) {
        assert(bcm::relocateImage(images[i], images, 4, imports.data(), imports.size()));
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
    assert(!bcm::relocateImage(image, images, 4, imports.data(), imports.size()));
    reset();
    bcm::Relocation bad {original.size, 0, 0, 0, 8, {}};
    altered.relocations = &bad;
    altered.relocationCount = 1;
    assert(!bcm::relocateImage(image, images, 4, imports.data(), imports.size()));
    reset();
    bad = {0, bcm::nativeImportCount, 0, 255, 8, {}};
    altered.relocations = &bad;
    altered.relocationCount = 1;
    assert(!bcm::relocateImage(image, images, 4, imports.data(), imports.size()));
    reset();
    bad = {0, 0, 0, 254, 8, {}};
    altered.relocations = &bad;
    altered.relocationCount = 1;
    assert(!bcm::relocateImage(image, images, 4, imports.data(), imports.size()));
    reset();
    altered.stubSize = 0;
    assert(!bcm::allocateStub(image, 1));
    reset();
    image.editable = false;
    assert(!bcm::relocateImage(image, images, 4, imports.data(), imports.size()));
    for (auto &entry : images)
        free(entry.memory);
    printf("{\"relocations\":%lu,\"negativeCases\":6,\"farBranches\":%s}\n", total, far ? "true" : "false");
}
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fingerprint():
    files = [ROOT / name for name in ('README.md', 'README.en.md', 'NOTICE.md')]
    for folder in ['Standalone', 'SimpleBCM', 'SimpleBCMStandalone.xcodeproj', 'Config', 'Tools']:
        files.extend(p for p in (ROOT / folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts and 'xcuserdata' not in p.parts)
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
    block = dict(Arch='x86_64', Comment='Allow the embedded IOSkywalk replacement', Enabled=True,
                 Identifier='com.apple.iokit.IOSkywalkFamily', MinKernel='23.0.0', MaxKernel='25.99.99', Strategy='Exclude')
    return {'Kernel': {'Add': add, 'Block': [block]}}


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


def check_reference(folder, addresses, far):
    exports = []
    images = [Image(IMAGES[name]) for name in LABELS]
    for image in images:
        _, symbols = parse(image)
        exports.append({n: v for n, t, _, _, v in symbols if t & 15 == 15})
    bases = [(0xffffff9000000000 if far else 0xffffff8010000000) + i * 0x2000000 for i in range(4)]
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
                        target = bases[matches[0][0]] + matches[0][1] if matches else addresses[name]
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
                assert observed == expected, (LABELS[i], hex(offset), hex(observed), hex(expected))
                checked += 1
        linked = Image(folder / f'{i}.bin')
        _, linked_symbols = parse(linked)
        for n, (name, kind, _, _, value) in enumerate(symbols):
            if not kind & 0xe0 and kind & 14 == 14:
                assert linked_symbols[n][4] == value + bases[i], (n, name)
    return checked


def verify(configuration, volumes):
    validate_payloads(include_optional=False)
    source_fingerprint = fingerprint()
    manifest = json.loads((OUTPUT / 'manifest.json').read_text())
    product = ROOT / f'build/Standalone/Build/Products/{configuration}/SimpleBCM.kext'
    binary = product / 'Contents/MacOS/SimpleBCM'
    evidence = json.loads((ROOT / f'build/Standalone-Build-{configuration}.json').read_text())
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
    targets = []
    current = None
    for volume in volumes:
        c = KernelCollection(volume / 'System/Library/KernelCollections/BootKernelExtensions.kc')
        available = native_addresses(c, info['OSBundleLibraries'])
        missing = sorted(undefined - available.keys())
        assert not missing, (str(volume), missing)
        for parent, offset, method in manifest['nativeVtableGuards']:
            observed = c.pointer(available[parent] + offset)
            assert observed == available[method], (str(volume), parent, offset, method)
        targets.append({'volume': str(volume), 'kernel': c.version(), 'uuid': c.root.uuid,
                        'imports': len(undefined), 'unmatchedImports': [],
                        'nativeVtableGuards': len(manifest['nativeVtableGuards'])})
        if current is None:
            current = available
        c.close()
    assert current
    with tempfile.TemporaryDirectory(prefix='simplebcm-verify-') as temporary:
        temp = Path(temporary)
        (temp / 'main.cpp').write_text(HOST)
        assembly = (OUTPUT / 'Payloads.S').read_text().split('.section __DATA_CONST')[0]
        (temp / 'Payloads.S').write_text(assembly)
        (temp / 'imports.bin').write_bytes(b''.join(struct.pack('<Q', current[name]) for name in manifest['nativeImports']))
        executable = temp / 'verify'
        subprocess.run(['xcrun', 'clang++', '-std=c++14', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I', str(ROOT / 'Standalone'),
                        str(ROOT / 'Standalone/Relocate.cpp'), str(OUTPUT / 'Payloads.cpp'), str(temp / 'Payloads.S'),
                        str(temp / 'main.cpp'), '-o', str(executable)], check=True)
        runs = []
        for far in [False, True]:
            output = subprocess.check_output([str(executable), str(temp / 'imports.bin'), str(temp), str(int(far))], text=True)
            run = json.loads(output)
            run['independentReferenceChecks'] = check_reference(temp, current, far)
            runs.append(run)
        from verify import HOST_SOURCE
        (temp / 'ABIValidation.cpp').write_text(HOST_SOURCE)
        abi_executable = temp / 'abi'
        subprocess.run(['xcrun', 'clang++', '-std=c++14', '-O1', '-g', '-fsanitize=address,undefined',
                        '-fno-omit-frame-pointer', '-mmacosx-version-min=14.0', '-I', str(ROOT / 'SimpleBCM'),
                        str(temp / 'ABIValidation.cpp'), '-framework', 'IOKit', '-framework', 'CoreFoundation',
                        '-lobjc', '-o', str(abi_executable)], check=True)
        abi = json.loads(subprocess.check_output([str(abi_executable)], text=True, timeout=60))
    assert source_fingerprint == fingerprint()
    result = {'version': VERSION, 'configuration': configuration, 'driverLoading': 'embedded',
              'sourceFingerprint': source_fingerprint, 'sha256': digest(binary), 'uuid': image.uuid,
              'probeSHA256': digest(product.parent / 'bcmprobe'), 'nativeTargets': targets,
              'relocationValidation': runs, 'sanitizers': ['AddressSanitizer', 'UndefinedBehaviorSanitizer'],
              'abiValidation': abi,
              'baseAddEntries': len(fragment()['Kernel']['Add']), 'payloads': manifest['payloads'],
              'kernelRegistrationExecuted': False, 'openCoreLinkExecuted': False, 'hardwareValidation': 'pending'}
    destination = ROOT / f'build/Standalone-Validation-{configuration}.json'
    destination.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return result


def build(configuration, analyze=False):
    source_fingerprint = fingerprint()
    action = 'analyze' if analyze else 'build'
    log = ROOT / f'build/standalone-{action}-{configuration}.log'
    log.parent.mkdir(exist_ok=True)
    command = ['xcodebuild', '-project', str(ROOT / 'SimpleBCMStandalone.xcodeproj'), '-scheme', 'SimpleBCM',
               '-configuration', configuration, '-destination', 'generic/platform=macOS',
               '-derivedDataPath', str(ROOT / 'build/Standalone'), action]
    with log.open('w') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    diagnostics = [line for line in log.read_text().splitlines() if any(s in line for s in ['error:', 'warning:', '** BUILD', '** ANALYZE'])]
    print('\n'.join(diagnostics))
    if result.returncode or any('warning:' in line for line in diagnostics):
        raise RuntimeError(f'Build diagnostics require attention: {log}')
    assert source_fingerprint == fingerprint(), 'Source changed during the build'
    if analyze:
        (ROOT / f'build/Standalone-Analysis-{configuration}.json').write_text(json.dumps({
            'passed': True, 'sourceFingerprint': source_fingerprint, 'logSHA256': digest(log)}, indent=2) + '\n')
    else:
        binary = ROOT / f'build/Standalone/Build/Products/{configuration}/SimpleBCM.kext/Contents/MacOS/SimpleBCM'
        (ROOT / f'build/Standalone-Build-{configuration}.json').write_text(json.dumps({
            'sourceFingerprint': source_fingerprint, 'sha256': digest(binary), 'logSHA256': digest(log),
            'payloadManifestSHA256': digest(OUTPUT / 'manifest.json')}, indent=2) + '\n')


def package(configuration):
    report = json.loads((ROOT / f'build/Standalone-Validation-{configuration}.json').read_text())
    product = ROOT / f'build/Standalone/Build/Products/{configuration}'
    assert report['sourceFingerprint'] == fingerprint()
    assert report['sha256'] == digest(product / 'SimpleBCM.kext/Contents/MacOS/SimpleBCM')
    analysis = json.loads((ROOT / 'build/Standalone-Analysis-Release.json').read_text())
    assert analysis['passed'] and analysis['sourceFingerprint'] == fingerprint()
    assert analysis['logSHA256'] == digest(ROOT / 'build/standalone-analyze-Release.log')
    name = f'SimpleBCM-v{VERSION}-{configuration.upper()}'
    dist = ROOT / 'dist'
    dist.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.standalone-', dir=dist) as temporary:
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
        (extra / 'Validation.json').write_text(json.dumps(report, indent=2) + '\n')
        save_plist(stage / 'config.fragment.plist', fragment())
        save_plist(extra / 'config.AirportBrcmFixup.fragment.plist', fragment(True))
        files = {str(p.relative_to(stage)): digest(p) for p in stage.rglob('*') if p.is_file()}
        (extra / 'manifest.json').write_text(json.dumps({'version': VERSION, 'configuration': configuration,
                'files': files, 'hardwareValidation': 'pending', 'driverLoading': 'embedded'}, indent=2) + '\n')
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
    parser.add_argument('--target-volume', type=Path, action='append')
    args = parser.parse_args()
    if args.action in ['build', 'analyze']:
        build(args.configuration, args.action == 'analyze')
    if args.action in ['verify', 'build']:
        verify(args.configuration, args.target_volume or [Path('/')])
    if args.action == 'package':
        package(args.configuration)


if __name__ == '__main__':
    main()
