#
#  prepare_goldengate.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/22.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import gzip
import json
import pathlib
import plistlib
import shutil
import stat
import struct
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
EAP8021X_REVISION = '89340102f408cbac3d6703fb56e0c5ee8755b01f'
CONFIGD_REVISION = '585b7f2fca293f4642d21d15c5daf187f63c4796'
CONTROLLER = pathlib.Path('System/Library/SystemConfiguration/EAPOLController.bundle')
AWDL = pathlib.Path('System/Library/PrivateFrameworks/DeviceToDeviceManager.framework/PlugIns/awdl_d2d.bundle')
IDENTIFIER = 'com.apple.SystemConfiguration.EAPOLController'


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def output(*args):
    return run(*args, stdout=subprocess.PIPE, text=True).stdout.strip()


def header(name, project='SimpleBCM'):
    return (f'//\n//  {name}\n//  {project}\n//\n//  Created by laobamac on 2026/11/22.\n'
            '//  Copyright © 2026 laobamac. All rights reserved.\n//\n\n')


def initializer(data):
    return '\n'.join('    ' + ', '.join(f'0x{v:02x}' for v in data[i:i+24]) + ','
                     for i in range(0, len(data), 24))


def compile_controller(work, source, headers):
    sdk = pathlib.Path(output('xcrun', '--show-sdk-path'))
    sdk_args = ['-arch', 'x86_64', '-isysroot', sdk]
    flags = [*sdk_args, '-mmacosx-version-min=26.0', '-Os', '-fconstant-cfstrings']
    includes = work / 'include'
    framework = source / 'EAP8021X.fproj'
    controller = source / 'EAPOLController.bproj'
    (includes / 'EAP8021X').symlink_to(framework, target_is_directory=True)
    system_headers = includes / 'SystemConfiguration'
    system_headers.mkdir()
    for name in ('SCDPlugin.h', 'SCValidation.h'):
        (system_headers / name).write_text(output('git', '-C', headers, 'show', f'HEAD:SystemConfiguration.fproj/{name}') + '\n')
    declarations = {
        'SystemConfiguration/SCPrivate.h': '''#include <CoreFoundation/CoreFoundation.h>
#include <Security/Authorization.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <os/log.h>
#include <sys/syslog.h>

CFMachPortRef _SC_CFMachPortCreateWithPort(const char *, mach_port_t, CFMachPortCallBack, CFMachPortContext *);
os_log_type_t _SC_syslog_os_log_mapping(int);
SCPreferencesRef SCPreferencesCreateWithOptions(CFAllocatorRef, CFStringRef, CFStringRef, AuthorizationRef, CFDictionaryRef);
''',
        'os/boot_mode_private.h': '''#include <stdbool.h>
#define OS_BOOT_MODE_FVUNLOCK "fvunlock"
bool os_boot_mode_query(const char **);
''',
        'CoreFoundation/CFRuntime.h': '#include <CoreFoundation/CFBase.h>\n',
        'bootstrap_priv.h': '''#include <servers/bootstrap.h>
#define BOOTSTRAP_PRIVILEGED_SERVER (1ULL << 3)
kern_return_t bootstrap_look_up2(mach_port_t, const name_t, mach_port_t *, pid_t, uint64_t);
''',
    }
    for name, text in declarations.items():
        path = includes / name
        path.parent.mkdir(exist_ok=True)
        path.write_text(header(path.name) + '#pragma once\n\n' + text)
    server = work / 'eapolcontrollerServer.c'
    run('xcrun', 'mig', *sdk_args, '-user', '/dev/null', '-header', '/dev/null', '-server', server,
        '-sheader', work / 'eapolcontrollerServer.h', source / 'eapolcontroller.defs')
    result = work / 'EAPOLController'
    run('xcrun', 'clang', *flags, '-bundle', '-I', includes, '-I', work, '-I', framework, '-I', controller,
        '-F', sdk / 'System/Library/PrivateFrameworks', '-framework', 'CoreFoundation', '-framework',
        'SystemConfiguration', '-framework', 'EAP8021X', '-lbsm', controller / 'controller.c',
        controller / 'server.c', server, '-o', result)
    return result


def prepare_payload(system, tahoe, work, embedded, source, headers):
    (work / 'include').mkdir()
    native = compile_controller(work, source, headers)
    original = system / CONTROLLER
    bundle = work / original.name
    clean = original / 'Contents' / 'Info.plist'
    metadata = plistlib.loads(clean.read_bytes())
    if metadata.get('CFBundleIdentifier') != IDENTIFIER or metadata.get('CFBundleExecutable') != native.name:
        raise ValueError('Unexpected EAPOLController bundle identity')
    for source in sorted(original.rglob('*')):
        relative = source.relative_to(original)
        dest = bundle / relative
        if source.is_symlink():
            raise ValueError(f'Unexpected link in controller bundle: {source}')
        if '_CodeSignature' in relative.parts:
            continue
        if source.is_dir():
            dest.mkdir(parents=True, exist_ok=True)
        elif source.is_file():
            shutil.copyfile(native if relative == pathlib.Path('Contents/MacOS/EAPOLController') else source, dest)
            dest.chmod(stat.S_IMODE(source.stat().st_mode) & 0o755)
        else:
            raise ValueError(f'Unexpected controller resource: {source}')
    run('codesign', '--force', '--sign', '-', '--timestamp=none', bundle)
    run('codesign', '--verify', '--strict', bundle)
    awdl = tahoe / AWDL
    for root in (awdl, system / AWDL):
        metadata = plistlib.loads((root / 'Contents/Info.plist').read_bytes())
        if (metadata.get('CFBundleIdentifier'), metadata.get('CFBundleExecutable'),
            metadata.get('D2DTransportPlugin'), metadata.get('D2DTransportType')) != (
                'com.apple.wifi.awdl.d2d', 'awdl_d2d', 'WiFiAWDLD2DPluginInterface', 2):
            raise ValueError(f'Unexpected AWDL D2D bundle identity: {root}')
    awdl_executable = pathlib.Path('Contents/MacOS/awdl_d2d')
    run('lipo', awdl / awdl_executable, '-verify_arch', 'x86_64')
    run('codesign', '--verify', '--strict', '--arch', 'x86_64', awdl)
    data = bytearray()
    rows = []
    mounts = []
    for name, tree, location, executable in (
        ('EAPOL', bundle, CONTROLLER, pathlib.Path('Contents/MacOS/EAPOLController')),
        ('AWDL', awdl, AWDL, awdl_executable),
    ):
        first = len(rows)
        paths = [tree, *sorted(tree.rglob('*'))]
        indices = {path: index for index, path in enumerate(paths, first)}
        for path in paths:
            if path.is_symlink() or not (path.is_file() or path.is_dir()) or len(path.name.encode()) > 255:
                raise ValueError(f'Unexpected bundle resource: {path}')
            content = path.read_bytes() if path.is_file() else b''
            mode = stat.S_IMODE(path.stat().st_mode) & 0o755
            parent = first if path == tree else indices[path.parent]
            rows.append(f'    {{{json.dumps(path.name)}, {parent}, 0{mode:o}, {str(path.is_dir()).lower()}, {len(data)}, {len(content)}}},')
            data.extend(content)
        mount_path = '/' + str((system / location).resolve().relative_to(system))
        executable_path = mount_path + '/' + str(executable)
        mounts.append(f'    {{{json.dumps(mount_path)}, {json.dumps(executable_path)}, '
                      f'{json.dumps(name)}, {first}, {len(rows)}}},')
    target = embedded / 'EAPOLPayload.hpp'
    target.write_text(header(target.name) + 'static const Entry entries[] = {\n' + '\n'.join(rows) +
                      '\n};\nstatic Bundle bundles[] = {\n' + '\n'.join(mounts) +
                      '\n};\nstatic const unsigned char payload[] = {\n' + initializer(data) + '\n};\n')


def prepare_mount_abi(system, kdk, embedded):
    from kernel_collection import KernelCollection, KernelImage

    info = system / 'System/Library/KernelCollections/BootKernelExtensions.kc'
    collection = KernelCollection(info)
    kernel = collection.kernel
    version = collection.version()
    donor = KernelImage((kdk / 'kernel').read_bytes())
    if kernel.uuid != donor.uuid or version.split('.')[0] != '27':
        raise ValueError('GoldenGate kernel does not match the KDK')
    dwarf = kdk / 'kernel.dSYM/Contents/Resources/DWARF/kernel'
    lines = output('xcrun', 'nm', '-a', dwarf).splitlines()
    [private] = [int(line.split()[0], 16) for line in lines if line.endswith(' _kernel_mount')]
    donor_entry = donor.symbols['_vfs_mount_at_path']
    entry = kernel.symbols['_vfs_mount_at_path']
    delta = private - donor_entry
    if not -65536 <= delta <= 65536:
        raise ValueError('VFS helper outside the verified relative call range')
    def relative_calls(code):
        return [offset for offset in range(len(code) - 4)
                if code[offset] == 0xe8 and offset + 5 + struct.unpack_from('<i', code, offset + 1)[0] == delta]

    donor_calls = relative_calls(donor.read(donor_entry, 512))
    live_calls = relative_calls(kernel.read(entry, 512))
    if len(donor_calls) != 1 or live_calls != donor_calls:
        raise ValueError('GoldenGate VFS helper does not call the expected kernel mount routine')
    call = live_calls[0]
    caller_tail = bytes.fromhex('4c 8b 45 c8 41 56 41 57')
    flags_in_r9 = bytes.fromhex('44 89 cb 4c 89 85 28 fe ff ff')
    context_on_stack = bytes.fromhex('4c 8b 7d 18')
    flags_on_stack = bytes.fromhex('44 8b 7d 10')
    for image, wrapper in ((donor, donor_entry), (kernel, entry)):
        mount = image.read(wrapper + delta, 0xa6)
        if (image.read(wrapper + call - len(caller_tail), len(caller_tail)) != caller_tail
                or mount[0x14:0x1e] != flags_in_r9 or mount[0x2e:0x32] != context_on_stack
                or mount[0xa2:0xa6] != flags_on_stack):
            raise ValueError('GoldenGate kernel_mount does not use the verified eight-argument calling convention')
    private_code = kernel.read(entry + delta, 0xa6)
    code = kernel.read(entry, call + 5)

    def init_program_call(image):
        task = image.symbols['_bsdinit_task']
        load = image.symbols['_load_init_program']
        body = image.read(task, 0xA0)
        [offset] = [i for i in range(3, len(body) - 15)
                    if body[i - 3:i + 1] == b'\x48\x89\xdf\xe8'
                    and body[i + 5:i + 7] == b'\xc7\x05'
                    and body[i + 11:i + 15] == b'\x01\x00\x00\x00'
                    and (task + i + 1) % 4 == 0
                    and task + i + 5 + struct.unpack_from('<i', body, i + 1)[0] == load]
        return offset, load - (task + offset + 5), body[offset - 3:offset + 15]

    init_offset, init_relative, init_bytes = init_program_call(kernel)
    if (init_offset, init_relative) != init_program_call(donor)[:2]:
        raise ValueError('GoldenGate init program call differs from the KDK')
    path = embedded / 'EAPOLKernelABI.hpp'
    path.write_text(header(path.name) + f'static constexpr intptr_t kernelMountDelta = {delta};\n' +
                    'static const uint8_t mountEntryBytes[] = {\n' + initializer(code) + '\n};\n' +
                    'static const uint8_t kernelMountBytes[] = {\n' + initializer(private_code) + '\n};\n' +
                    f'static constexpr size_t initCallOffset = {init_offset};\n' +
                    f'static constexpr int32_t initCallOriginal = {init_relative};\n' +
                    'static const uint8_t initCallBytes[] = {\n' + initializer(init_bytes) + '\n};\n')
    collection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--system', type=pathlib.Path, required=True)
    parser.add_argument('--tahoe', type=pathlib.Path, default=pathlib.Path('/'))
    parser.add_argument('--kdk', type=pathlib.Path, required=True)
    parser.add_argument('--eap8021x', type=pathlib.Path, required=True)
    parser.add_argument('--configd', type=pathlib.Path, required=True)
    args = parser.parse_args()
    for checkout, revision in ((args.eap8021x, EAP8021X_REVISION), (args.configd, CONFIGD_REVISION)):
        if output('git', '-C', checkout, 'rev-parse', 'HEAD') != revision:
            raise ValueError(f'Unexpected source revision: {checkout}')
    system = args.system.resolve()
    destination = ROOT / 'Resources/GoldenGate'
    with tempfile.TemporaryDirectory(prefix='simplebcm-goldengate-') as temporary:
        work = pathlib.Path(temporary)
        prepare_mount_abi(system, args.kdk / 'System/Library/Kernels', work)
        prepare_payload(system, args.tahoe.resolve(), work, work, args.eap8021x.resolve(), args.configd.resolve())
        for name in ('EAPOLKernelABI.hpp', 'EAPOLPayload.hpp'):
            (destination / (name + '.gz')).write_bytes(gzip.compress((work / name).read_bytes(), compresslevel=9, mtime=0))
        shutil.copyfile(args.eap8021x / 'APPLE_LICENSE', destination / 'EAP8021X-APPLE_LICENSE')


if __name__ == '__main__':
    main()
