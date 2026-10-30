#!/usr/bin/env python3
#
#  kernel_collection.py
#  SimpleBCM
#
#  Created by laobamac on 2026/10/30.
#  Copyright © 2026 laobamac. All rights reserved.
#

import mmap
import plistlib
import struct
from pathlib import Path


class KernelImage:
    def __init__(self, data, offset=0):
        if data[offset:offset + 4] != b'\xcf\xfa\xed\xfe':
            raise ValueError('Expected a 64-bit little-endian kernel image')
        if struct.unpack_from('<I', data, offset + 4)[0] != 0x1000007:
            raise ValueError('Expected an x86_64 kernel image')
        self.data = data
        self.segments = []
        self.sections = []
        self.entries = {}
        self.symbols = {}
        self.exports = set()
        self.uuid = None
        symtab = None
        position = offset + 32
        for _ in range(struct.unpack_from('<I', data, offset + 16)[0]):
            command, size = struct.unpack_from('<II', data, position)
            if command == 0x19:
                name, address, length, file_offset, file_size, _, _, count, _ = struct.unpack_from(
                    '<16sQQQQiiII', data, position + 8)
                self.segments.append((name.rstrip(b'\0').decode(), address, length, file_offset, file_size))
                for index in range(count):
                    sec, seg, addr, length, off = struct.unpack_from('<16s16sQQI', data, position + 72 + index * 80)
                    self.sections.append((seg.rstrip(b'\0').decode(), sec.rstrip(b'\0').decode(), addr, length, off))
            elif command == 2:
                symtab = struct.unpack_from('<IIII', data, position + 8)
            elif command == 0x1B:
                self.uuid = data[position + 8:position + 24].hex()
            elif command == 0x80000035:
                address, off, name_offset, _ = struct.unpack_from('<QQII', data, position + 8)
                name = data[position + name_offset:position + size].split(b'\0', 1)[0].decode()
                self.entries[name] = (address, off)
            position += size
        self.base = next(address for name, address, *_ in self.segments if name == '__TEXT')
        if symtab:
            off, count, strings, string_size = symtab
            for index in range(count):
                no, kind, _, _, address = struct.unpack_from('<IBBHQ', data, off + index * 16)
                if not no or kind & 0xE != 0xE:
                    continue
                name = data[strings + no:strings + min(no + 2048, string_size)].split(b'\0', 1)[0].decode()
                self.symbols[name] = address
                if kind & 1:
                    self.exports.add(name)

    def read(self, address, size):
        for _, start, _, off, length in self.segments:
            if start <= address and address + size <= start + length:
                location = off + address - start
                return self.data[location:location + size]
        raise ValueError(f'Unmapped kernel range {address:#x}+{size:#x}')


class KernelCollection:
    def __init__(self, path):
        self.path = Path(path)
        with self.path.open('rb') as source:
            self.data = mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ)
        self.root = KernelImage(self.data)
        self.images = {name: KernelImage(self.data, off) for name, (_, off) in self.root.entries.items()}
        self.kernel = self.images['com.apple.kernel']
        self.fixup_base = min(address for _, address, length, *_ in self.root.segments if address and length)

    def pointer(self, address):
        value = struct.unpack('<Q', self.root.read(address, 8))[0]
        if value >> 48 == 0xFFFF:
            return value
        if (value >> 30) & 3:
            raise ValueError('Unsupported cross-collection pointer')
        return self.fixup_base + (value & 0x3FFFFFFF)

    def version(self):
        return '.'.join(str(struct.unpack('<I', self.kernel.read(self.kernel.symbols[name], 4))[0])
                        for name in ['_version_major', '_version_minor', '_version_revision'])

    def close(self):
        self.data.close()


def system_version(volume):
    volume = Path(volume)
    info = plistlib.loads((volume / 'System/Library/CoreServices/SystemVersion.plist').read_bytes())
    collection = KernelCollection(volume / 'System/Library/KernelCollections/BootKernelExtensions.kc')
    try:
        return info['ProductBuildVersion'], collection.version()
    finally:
        collection.close()
