#!/usr/bin/env python3
#
#  verify_radio_policy.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/6.
#  Copyright © 2026 laobamac. All rights reserved.
#

import ctypes
import json
import mmap
import platform
import struct
import subprocess
import sys
from pathlib import Path

from clm_policy import CLM, POLICIES


ROOT = Path(__file__).resolve().parent.parent
HEADERS = {
    'IOKit/IOService.h': r'''
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
class IOService {
public:
    bool setProperty(const char *, const char *) { return true; }
    bool setProperty(const char *, unsigned long long, unsigned) { return true; }
};
''',
}


class Runtime:
    def __init__(self, model):
        assert platform.machine() == 'x86_64'
        self.model = model
        image = model.image
        end = max(address + size for _, address, size, _, _ in image.segs)
        self.stub = (end + 4095) & ~4095
        self.memory = mmap.mmap(-1, self.stub + 65536, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        self.base = ctypes.addressof(ctypes.c_char.from_buffer(self.memory))
        self.buffers = []
        for _, address, _, offset, length in image.segs:
            self.memory[address:address + length] = image.b[image.base + offset:image.base + offset + length]
        self.guard = ctypes.c_uint64(0x149842671530)
        library = ctypes.CDLL(None)
        traps = {}
        def trampoline(target):
            if target not in traps:
                offset = self.stub
                self.stub += 16
                self.memory[offset:offset + 14] = b'\xff\x25\0\0\0\0' + struct.pack('<Q', target)
                traps[target] = self.base + offset
            return traps[target]
        trap = self.base + self.stub
        self.memory[self.stub:self.stub + 2] = b'\x0f\x0b'
        self.stub += 16
        local_offset, local_count = image.dysym[16:18]
        for index in range(local_count):
            offset, flags = struct.unpack_from('<iI', image.b, image.base + local_offset + index * 8)
            assert flags >> 28 == 0 and flags >> 24 & 1 == 0 and flags >> 25 & 3 == 3
            raw = struct.unpack_from('<Q', self.memory, offset)[0]
            struct.pack_into('<Q', self.memory, offset, raw + self.base)
        for offset, (name, kind, relative, length) in image.relocs().items():
            width = 1 << length
            raw = int.from_bytes(self.memory[offset:offset + width], 'little', signed=relative != 0)
            if name == 'LOCAL':
                assert kind == 0 and not relative and width == 8
                value = raw + self.base
            else:
                symbol = image.names.get(name)
                if symbol and symbol[1] & 14 == 14:
                    target = self.base + symbol[4]
                elif name == '___stack_chk_guard':
                    target = ctypes.addressof(self.guard)
                elif name in ('_memset', '_memcpy', '_memcmp', '_strcmp', '_strlen', '_bzero'):
                    target = ctypes.cast(getattr(library, name[1:]), ctypes.c_void_p).value
                else:
                    target = trap
                if kind == 2 and relative and width == 4:
                    value = trampoline(target) + raw - (self.base + offset + 4)
                elif kind == 0 and not relative and width == 8:
                    value = target + raw
                else:
                    raise ValueError((offset, name, kind, relative, width))
            self.memory[offset:offset + width] = (value & ((1 << (8 * width)) - 1)).to_bytes(width, 'little')
        p = ctypes.c_void_p
        u = ctypes.c_uint32
        i = ctypes.c_int32
        self.init = self.function('_clm_init', i, p)
        self.lookup = self.function('_clm_country_lookup_shim', i, p, i, p)
        self.definition = self.function('_clm_country_def_shim', i, u, p)
        self.channels = self.function('_clm_valid_channels', i, p, u, p, p)
        self.limits_init = self.function('_clm_limits_params_init', i, p)
        self.limits = self.function('_clm_limits', i, p, u, u, i, u, p, p)
        assert self.init(self.base + model.symbol('_clm_header')) == 0

    def function(self, name, result, *args):
        return ctypes.CFUNCTYPE(result, *args)(self.base + self.model.symbol(name))

    def country(self, index):
        result = ctypes.create_string_buffer(32)
        assert self.definition(0x40000001 + index, result) == 0
        return result

    def channel_set(self, definition, band, width):
        parameters = (ctypes.c_uint32 * 2)(width, 0)
        result = ctypes.create_string_buffer(32)
        status = self.channels(definition, band, parameters, result)
        return status, result.raw

    def powers(self, definition, band, width, channel, limit_type=0, antenna=0):
        parameters = (ctypes.c_int32 * 4)()
        assert self.limits_init(parameters) == 0
        parameters[0] = width
        parameters[2] = antenna
        result = ctypes.create_string_buffer(178)
        status = self.limits(definition, band, channel, 0, limit_type, parameters, result)
        return status, result.raw

    def patch(self, countries, locales):
        country_buffer = ctypes.create_string_buffer(countries)
        locale_buffer = ctypes.create_string_buffer(locales)
        country_set = ctypes.create_string_buffer(struct.pack('<I4xQ', self.model.country_count,
                                                               ctypes.addressof(country_buffer)))
        self.buffers.extend([country_buffer, locale_buffer, country_set])
        self.memory[self.model.data + 72:self.model.data + 88] = struct.pack(
            '<QQ', ctypes.addressof(locale_buffer), ctypes.addressof(country_set))
        assert self.init(self.base + self.model.symbol('_clm_header')) == 0


def native_validation():
    reports = []
    for label in ('BrcmOriginal', 'BrcmTahoe'):
        model = CLM(label)
        countries, locales, rules = model.generate()
        runtime = Runtime(model)
        baseline_channels = {}
        for index in range(model.country_count):
            definition = runtime.country(index)
            for band in range(2):
                for width in range(4):
                    baseline_channels[index, band, width] = runtime.channel_set(definition, band, width)
        powers = {}
        for rule in rules:
            index = rule['countryIndex']
            definition = runtime.country(index)
            for band in range(2):
                for width in range(4):
                    for channel in range(1, 197):
                        key = index, band, width, channel
                        powers[key] = runtime.powers(definition, band, width, channel)
        runtime.patch(countries, locales)
        changed_indices = {r['countryIndex'] for r in rules}
        for index in range(model.country_count):
            definition = runtime.country(index)
            for band in range(2):
                for width in range(4):
                    before = baseline_channels[index, band, width]
                    after = runtime.channel_set(definition, band, width)
                    if index in changed_indices and band == 1 and width == 2:
                        wanted = bytearray(before[1])
                        assert not wanted[42 // 8] & (1 << (42 % 8))
                        wanted[42 // 8] |= 1 << (42 % 8)
                        assert after == (0, bytes(wanted)), (label, index, band, width)
                    else:
                        assert after == before, (label, index, band, width)
        for rule in rules:
            index = rule['countryIndex']
            definition = runtime.country(index)
            expected = bytes(rule['powerQuarterDBm'].get(str(rate), -128) & 255 for rate in range(178))
            for band in range(2):
                for width in range(4):
                    for channel in range(1, 197):
                        observed = runtime.powers(definition, band, width, channel)
                        if band == 1 and width == 2 and channel == 42:
                            assert observed == (0, expected), (label, rule['revision'], observed)
                            for antenna in (1, 2):
                                assert runtime.powers(definition, band, width, channel, antenna=antenna) == observed
                        else:
                            assert observed == powers[index, band, width, channel], (label, index, band, width, channel)
            handle = ctypes.c_uint32()
            assert runtime.lookup(b'CN', rule['revision'], ctypes.byref(handle)) == 0
            assert handle.value == 0x40000001 + index
        reports.append({'payload': label, 'countries': model.country_count,
                        'channelComparisons': len(baseline_channels), 'powerComparisons': len(powers),
                        'repairedRevisions': list(POLICIES), 'nativeCLMExecuted': True})
        model.image.close()
    return reports


HOST = r'''
#include <assert.h>
#include <vector>
#include <fstream>
#include "RadioPolicy.cpp"

namespace bcm {
uint64_t payloadChecksum(const uint8_t *p, size_t n) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < n; ++i) h = (h ^ p[i]) * 1099511628211ULL;
    return h;
}
}

int main(int argc, char **argv) {
    assert(argc == 2);
    std::ifstream input(argv[1], std::ios::binary);
    std::vector<uint8_t> original((std::istreambuf_iterator<char>(input)), {});
    unsigned cases = 0;
    for (const auto &guard : bcm::radiodata::Guards) {
        for (unsigned fault = 0; fault < 12; ++fault) {
            auto memory = original;
            bcm::Payload payload {};
            payload.sha256 = guard.sha256;
            payload.size = static_cast<uint32_t>(memory.size());
            bcm::LinkedImage image {&payload, memory.data(), reinterpret_cast<uintptr_t>(memory.data()), 0, false, true};
            auto pointer = [&](uint32_t offset, uintptr_t value) { memcpy(memory.data() + offset, &value, 8); };
            pointer(guard.header + 48, image.address + guard.header);
            pointer(guard.header + 56, image.address + guard.data);
            pointer(guard.data + 72, image.address + guard.locales);
            pointer(guard.data + 80, image.address + guard.countrySet);
            pointer(guard.countrySet + 8, image.address + guard.countries);
            switch (fault) {
                case 1: image.editable = false; break;
                case 2: image.registered = true; break;
                case 3: payload.sha256 = "wrong"; break;
                case 4: payload.size = guard.locales; break;
                case 5: memory[guard.header] ^= 1; break;
                case 6: pointer(guard.header + 48, 0); break;
                case 7: pointer(guard.data + 72, 0); break;
                case 8: memory[guard.countries + 474 * 10] ^= 1; break;
                case 9: memory[guard.locales + 100] ^= 1; break;
                case 10: pointer(guard.dataSources + 328, 1); break;
                case 11: image.address += 16; break;
            }
            const auto before = memory;
            assert(bcm::applyTables(image) == (fault == 0));
            if (fault) assert(memory == before);
            else {
                for (size_t i = 0; i < memory.size(); ++i)
                    if (i < guard.data + 72 || i >= guard.data + 88) assert(memory[i] == before[i]);
                assert(bcm::value<uintptr_t>(image, guard.data + 72) == reinterpret_cast<uintptr_t>(bcm::radiodata::Locales));
                assert(bcm::value<uintptr_t>(image, guard.data + 80) == reinterpret_cast<uintptr_t>(&bcm::countries));
                const auto patched = memory;
                assert(!bcm::applyTables(image));
                assert(memory == patched);
            }
            ++cases;
        }
    }
    printf("%u\n", cases);
}
'''


def verify_policy(folder):
    directory = Path(folder) / 'radio-policy-validation'
    directory.mkdir()
    for name, contents in HEADERS.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    model = CLM('BrcmTahoe')
    size = max(address + length for _, address, length, _, _ in model.image.segs)
    data = bytearray(size)
    for _, address, _, offset, length in model.image.segs:
        data[address:address + length] = model.image.b[model.image.base + offset:model.image.base + offset + length]
    (directory / 'payload.bin').write_bytes(data)
    model.image.close()
    source = directory / 'PolicyValidation.cpp'
    source.write_text(HOST)
    binary = directory / 'PolicyValidation'
    subprocess.run(['xcrun', 'clang++', '-std=c++14', '-g', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I' + str(directory), '-I' + str(ROOT / 'SimpleBCM'), str(source), '-o', str(binary)], check=True)
    cases = int(subprocess.check_output([str(binary), str(directory / 'payload.bin')], text=True))
    native = json.loads(subprocess.check_output([sys.executable, '-B', str(Path(__file__).resolve()), '--native'], text=True))
    return {'passed': True, 'guardCases': cases, 'sanitizers': ['AddressSanitizer', 'UndefinedBehaviorSanitizer'],
            'nativeCLM': native, 'hardwareExecuted': False}


if __name__ == '__main__':
    assert sys.argv[1:] == ['--native']
    print(json.dumps(native_validation()))
