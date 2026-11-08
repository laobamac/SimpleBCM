#!/usr/bin/env python3
#
#  tahoe_dma.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/8.
#  Copyright © 2026 laobamac. All rights reserved.
#

import hashlib
import json
import struct

from native_abi import Mach, PATHS, EXPECTED_SOURCES, insns


PATCHES = ((0x2C25F0, 0x2A), (0x2C3D47, 0x3B), (0x2C4286, 8))
CHECKSUMS = ((0x1AFFB, 0x184), (0x1B35B, 0x17B), (0x2C39F9, 0x17F), (0x2C41DA, 0x130))
VALUES = {
    'Allocate': 0x1AFFB, 'PacketData': 0x2203D, 'PacketLength': 0x2204A,
    'PacketNext': 0x22092, 'PacketFree': 0x203B7,
    'Rings': 0x7E9300, 'RingCount': 0x7E9480,
    'TxResume': 0x2C261A, 'TxFail': 0x2C2649,
    'RxFillResume': 0x2C3D82, 'RxFillFail': 0x2C40B6,
    'RxCopyResume': 0x2C428E,
    'RxFirstReturn': 0x2C3A17, 'RxRetryReturn': 0x2C3B57,
    'RxContinuationReturn': 0x2C3ABA, 'RxReclaimReturn': 0x2C41BB,
    'RequiredSize': 0x7E9484,
}

ASSEMBLY = '''
.section __TEXT,__text
.p2align 4
.globl _bcmTahoeTxEntry
_bcmTahoeTxEntry:
    movq %r12, %rdi
    movq %r15, %rsi
    movzwl -0x38(%rbp), %edx
    callq _bcmTahoeTxMap
    testb %al, %al
    je 1f
    movq 0x80(%r12), %r11
    jmpq *_bcmTahoeTxResume(%rip)
1:
    jmpq *_bcmTahoeTxFail(%rip)
.p2align 4
.globl _bcmTahoeRxFillEntry
_bcmTahoeRxFillEntry:
    movq %r15, %rdi
    movq %r12, %rsi
    movzwl %r14w, %edx
    callq _bcmTahoeRxMap
    testq %rax, %rax
    je 2f
    movq %rax, %r13
    movq 0xB0(%r15), %rax
    jmpq *_bcmTahoeRxFillResume(%rip)
2:
    cmpw %r14w, 0xA8(%r15)
    jne 3f
    movq $0, -0x50(%rbp)
3:
    jmpq *_bcmTahoeRxFillFail(%rip)
.p2align 4
.globl _bcmTahoeRxCopyEntry
_bcmTahoeRxCopyEntry:
    movq %rbx, %rdi
    movq %r8, %rsi
    movzwl %r15w, %edx
    movq 8(%rbp), %rcx
    movl %r13d, %r8d
    callq _bcmTahoeRxCopy
    movq %rax, %r8
    movzwl %r15w, %esi
    movq 0x60(%rbx), %rdx
    shlq $4, %rsi
    jmpq *_bcmTahoeRxCopyResume(%rip)
'''


def checksum(data):
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & 0xffffffffffffffff
    return value


def header(name):
    return f'//\n//  {name}\n//  SimpleBCM\n//\n//  Created by laobamac on 2026/11/8.\n//  Copyright © 2026 laobamac. All rights reserved.\n//\n'


def generate_dma(output):
    image = Mach(PATHS['BrcmTahoe'])
    try:
        assert hashlib.sha256(image.b).hexdigest() == EXPECTED_SOURCES['BrcmTahoe']
        for name, key in (('_bcm_decode_anqp_nai_realm_print', 'Allocate'), ('_osl_pktdata', 'PacketData'),
                          ('_osl_pktlen', 'PacketLength'), ('_osl_pktnext', 'PacketNext'), ('_osl_pktfree', 'PacketFree')):
            assert image.names[name][4] == VALUES[key]
        relocations = image.relocs()
        guards = []
        for start, size in PATCHES:
            raw = image.read(start, size)
            assert sum(length for _, length, _, _ in insns(raw, start)) == size
            mask = bytearray([255] * size)
            for offset, (_, _, _, power) in relocations.items():
                for position in range(max(start, offset), min(start + size, offset + (1 << power))):
                    mask[position - start] = 0
            guards.append((start, size, raw, mask))
        checksums = []
        for start, size in CHECKSUMS:
            assert not any(start <= offset < start + size for offset in relocations)
            checksums.append((start, size, checksum(image.read(start, size))))
        assert image.read(0x2C260D, 5) == b'\xe8' + struct.pack('<i', 0x21674 - 0x2C2612)
        assert image.read(0x2C3D73, 5) == b'\xe8' + struct.pack('<i', 0x21674 - 0x2C3D78)
        for key in ('RxFirstReturn', 'RxRetryReturn', 'RxContinuationReturn', 'RxReclaimReturn'):
            address = VALUES[key]
            assert image.read(address - 5, 5) == b'\xe8' + struct.pack('<i', 0x2C41DA - address)
        lines = [header('TahoeDMAData.hpp'), '#ifndef SIMPLEBCM_TAHOE_DMA_DATA_HPP',
                 '#define SIMPLEBCM_TAHOE_DMA_DATA_HPP', '#include <stdint.h>', 'namespace bcm { namespace dma {',
                 f'constexpr const char *SourceSHA256 = "{EXPECTED_SOURCES["BrcmTahoe"]}";']
        lines += [f'constexpr uint32_t {key} = 0x{value:X};' for key, value in VALUES.items()]
        lines += ['struct Patch { uint32_t offset; uint32_t length; };', 'constexpr Patch Patches[] = {']
        lines += [f'    {{0x{start:X}, {size}}},' for start, size in PATCHES]
        lines += ['};', 'struct Guard { uint32_t offset; uint32_t length; uint8_t bytes[64]; uint8_t mask[64]; };',
                  'constexpr Guard Guards[] = {']
        for start, size, raw, mask in guards:
            arrays = ['{' + ','.join(f'0x{x:02X}' for x in data) + '}' for data in (raw, mask)]
            lines.append(f'    {{0x{start:X}, {size}, {arrays[0]}, {arrays[1]}}},')
        lines += ['};', 'struct Checksum { uint32_t offset; uint32_t length; uint64_t checksum; };',
                  'constexpr Checksum Checksums[] = {']
        lines += [f'    {{0x{start:X}, {size}, {value}ULL}},' for start, size, value in checksums]
        lines += ['};', '} }', '#endif', '']
        (output / 'TahoeDMAData.hpp').write_text('\n'.join(lines))
        (output / 'TahoeDMA.S').write_text(header('TahoeDMA.S') + ASSEMBLY)
        report = {'sourceSHA256': EXPECTED_SOURCES['BrcmTahoe'], 'patches': PATCHES,
                  'checksums': checksums, 'layout': VALUES, 'dmaAddressing': 'original-IODMACommand',
                  'originalMbufMappingRemovedAt': [0x2C260D, 0x2C3D73], 'txCapacity': 16384,
                  'rxCopy': 'frame-aware-with-full-copy-fallback', 'hardwareValidated': False}
        (output / 'TahoeDMA.json').write_text(json.dumps(report, indent=2) + '\n')
        return report
    finally:
        image.close()
