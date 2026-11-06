#!/usr/bin/env python3
#
#  clm_policy.py
#  SimpleBCM
#
#  Created by laobamac on 2026/11/6.
#  Copyright © 2026 laobamac. All rights reserved.
#

import bisect
import hashlib
import json
import struct

from native_abi import EXPECTED_SOURCES, Mach, PATHS


POLICY_VERSION = '1.2.1'
POLICIES = (24, 29, 37, 40, 204, 206, 245, 280)


def checksum(data):
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & 0xffffffffffffffff
    return value


class CLM:
    def __init__(self, label):
        self.label = label
        self.image = Mach(PATHS[label])
        assert hashlib.sha256(PATHS[label].read_bytes()).hexdigest() == EXPECTED_SOURCES[label]
        self.addresses = sorted(self.image.byaddr)
        self.data = self.symbol('_clm_data')
        self.country_set = self.pointer(self.data + 80)
        self.country_count, self.countries = struct.unpack('<I4xQ', self.image.read(self.country_set, 16))
        assert self.country_count == 2710
        assert self.image.read(self.data + 104, 4) == bytes.fromhex('7fb20026')
        self.country_bytes = self.image.read(self.countries, self.country_count * 10)
        self.locale_bytes = self.blob('_locales_5g_ht')
        self.widths = self.blob('_bw_width_to_idx_ac')
        self.rates = []
        rates = self.blob('_rate_sets_5g_80m')
        position = 0
        while position < len(rates):
            count = rates[position]
            assert position + count + 1 <= len(rates)
            self.rates.append(frozenset(rates[position + 1:position + count + 1]))
            position += count + 1
        assert len(self.rates) == 70
        remaps = self.blob('_regrev_cc_remaps')
        revisions = self.symbol('_regrev_regrev_remaps')
        self.revisions = {}
        for position in range(0, len(remaps) - 4, 4):
            code = remaps[position:position + 2].decode()
            start = struct.unpack_from('<H', remaps, position + 2)[0]
            end = struct.unpack_from('<H', remaps, position + 6)[0]
            data = self.image.read(revisions + start * 3, (end - start) * 3)
            self.revisions[code] = {int.from_bytes(data[i:i + 2], 'big'): data[i + 2]
                                    for i in range(0, len(data), 3)}
        indices = [self.locale_index(self.country_bytes[i:i + 10], 3)
                   for i in range(0, len(self.country_bytes), 10)]
        self.locale_count = max(index for index in indices if index < 1021) + 1
        self.locales = []
        position = 0
        for _ in range(self.locale_count):
            start = position
            _, position = self.groups(self.locale_bytes, position)
            self.locales.append(self.locale_bytes[start:position])
        assert not any(self.locale_bytes[position:])

    def symbol(self, name):
        return self.image.names[name][4]

    def pointer(self, address):
        return struct.unpack('<Q', self.image.read(address, 8))[0]

    def blob(self, name):
        start = self.symbol(name)
        end = self.addresses[bisect.bisect_right(self.addresses, start)]
        return self.image.read(start, end - start)

    @staticmethod
    def locale_index(row, index):
        return row[3 + index] | ((row[7] << (8 - index * 2)) & 0x300)

    @staticmethod
    def groups(data, position=0):
        result = []
        while True:
            assert position + 2 <= len(data)
            flags, count = data[position:position + 2]
            width = 3 + ((flags >> 4) & 3)
            start = position + 2
            position = start + count * width
            assert position <= len(data)
            result.append((flags, [data[i:i + width] for i in range(start, position, width)]))
            if not flags & 4:
                return result, position

    def country(self, code, revision):
        internal = self.revisions[code][revision]
        matches = [(i // 10, self.country_bytes[i:i + 10])
                   for i in range(0, len(self.country_bytes), 10)
                   if self.country_bytes[i:i + 3] == code.encode() + bytes([internal])]
        assert len(matches) == 1
        return matches[0]

    def range80(self, entry):
        return self.image.read(self.symbol('_channel_ranges_80m') + entry[1] * 2, 2)

    def power80(self, code, revision, center):
        _, row = self.country(code, revision)
        groups, _ = self.groups(self.locales[self.locale_index(row, 3)])
        result = {}
        for flags, entries in groups:
            if self.widths[flags & 0x49] != 2:
                continue
            for entry in entries:
                low, high = self.range80(entry)
                if not low <= center <= high:
                    continue
                assert flags == 8
                power = struct.unpack('b', entry[:1])[0]
                for rate in self.rates[entry[2]]:
                    result[rate] = min(result.get(rate, 127), power)
        return result

    def generate(self):
        country_bytes = bytearray(self.country_bytes)
        locales = list(self.locales)
        evidence = []
        candidate = self.power80('CN', 242, 42)
        _, candidate_row = self.country('CN', 242)
        candidate_groups, _ = self.groups(locales[self.locale_index(candidate_row, 3)])
        candidate_entries = [entry for flags, entries in candidate_groups if flags == 8
                             for entry in entries if self.range80(entry) == bytes([42, 42])]
        assert len(candidate_entries) == 6 and set(candidate) == self.rates[0x0c]
        references = {revision: set() for revision in POLICIES}
        reverse = {cc: {v: k for k, v in mapping.items()} for cc, mapping in self.revisions.items()}
        aggregates = self.blob('_aggregate_cc_defs')
        assert len(aggregates) == 103 * 16
        for position in range(0, len(aggregates), 16):
            count, pointer = struct.unpack_from('<iQ', aggregates, position + 4)
            data = self.image.read(pointer, count * 3)
            mapping = {}
            for offset in range(0, len(data), 3):
                cc = data[offset:offset + 2].decode()
                mapping[cc] = reverse.get(cc, {}).get(data[offset + 2], data[offset + 2])
            if mapping.get('CN') in references:
                assert 'US' in mapping
                references[mapping['CN']].add(mapping['US'])
        affected = tuple(rev for rev in self.revisions['CN']
                         if self.power80('CN', rev, 42) and
                         set(self.power80('CN', rev, 42).values()) == {-128})
        assert affected == POLICIES
        for revision in POLICIES:
            index, row = self.country('CN', revision)
            source_index = self.locale_index(row, 3)
            profiles = [self.power80('US', ref, 42) for ref in sorted(references[revision])]
            assert profiles and all(profiles)
            native = {rate: min(profile.get(rate, -128) for profile in profiles) for rate in candidate}
            assert set(self.power80('CN', revision, 42).values()) == {-128}
            replacements = []
            expected = {}
            for entry in candidate_entries:
                rates = self.rates[entry[2]]
                value = min(entry[0], *(native[rate] for rate in rates))
                assert value == -128 or 0 <= value <= 127
                replacements.append(bytes([value & 255, 0, entry[2]]))
                for rate in rates:
                    expected[rate] = min(expected.get(rate, 127), value)
            assert set(expected) == set(candidate)
            assert all(expected[r] <= min(candidate[r], native[r]) for r in expected)
            assert any(power > -128 for power in expected.values())
            groups, _ = self.groups(locales[source_index])
            replacement_count = 0
            output = bytearray()
            for flags, entries in groups:
                fixed = []
                for entry in entries:
                    if flags == 8 and self.range80(entry) == bytes([42, 42]):
                        assert entry[0] == 0x80
                        fixed.extend(replacements)
                        replacement_count += 1
                    else:
                        fixed.append(entry)
                assert len(fixed) <= 255
                output.extend(bytes([flags, len(fixed)]) + b''.join(fixed))
            assert replacement_count == 1
            replacement_index = len(locales)
            assert replacement_index < 1021
            locales.append(bytes(output))
            patched = bytearray(row)
            patched[6] = replacement_index & 255
            patched[7] = (patched[7] & ~0xc0) | ((replacement_index >> 8) << 6)
            assert self.locale_index(patched, 3) == replacement_index
            country_bytes[index * 10:index * 10 + 10] = patched
            evidence.append({'country': 'CN', 'revision': revision, 'countryIndex': index,
                             'sourceLocale': source_index, 'replacementLocale': replacement_index,
                             'referenceCountry': 'US', 'referenceRevisions': sorted(references[revision]),
                             'candidateCountry': 'CN', 'candidateRevision': 242,
                             'centerChannel': 42, 'primaryChannels': [36, 40, 44, 48],
                             'replacementEntries': [x.hex() for x in replacements],
                             'rateCount': sum(p > -128 for p in expected.values()),
                             'powerQuarterDBm': {str(k): v for k, v in sorted(expected.items())}})
        for index in range(self.country_count):
            if index not in [r['countryIndex'] for r in evidence]:
                assert country_bytes[index * 10:index * 10 + 10] == self.country_bytes[index * 10:index * 10 + 10]
        return bytes(country_bytes), b''.join(locales), evidence


def generate_policy(directory):
    models = [CLM(label) for label in ('BrcmOriginal', 'BrcmTahoe')]
    generated = [model.generate() for model in models]
    assert generated[0] == generated[1]
    countries, locales, evidence = generated[0]
    guards = []
    for model in models:
        guards.append({'sha256': EXPECTED_SOURCES[model.label], 'header': model.symbol('_clm_header'),
                       'data': model.data, 'countrySet': model.country_set, 'countries': model.countries,
                       'locales': model.symbol('_locales_5g_ht'), 'dataSources': model.symbol('_data_sources')})
    source = models[0]
    scope = 'CN/' + ','.join(str(revision) for revision in POLICIES) + ':36,40,44,48@80MHz'
    report = {'version': POLICY_VERSION, 'scope': scope,
              'countryCount': source.country_count, 'sourceLocaleCount': source.locale_count,
              'replacementLocaleCount': source.locale_count + len(POLICIES),
              'countryTableSHA256': hashlib.sha256(countries).hexdigest(),
              'localeTableSHA256': hashlib.sha256(locales).hexdigest(),
              'guards': guards, 'rules': evidence}
    def array(name, data):
        lines = [', '.join(f'0x{v:02x}' for v in data[i:i + 24]) for i in range(0, len(data), 24)]
        return f'alignas(8) static const uint8_t {name}[] = {{\n    ' + ',\n    '.join(lines) + '\n};\n'
    text = '//\n//  RadioPolicyData.hpp\n//  SimpleBCM\n//\n//  Created by laobamac on 2026/11/6.\n//  Copyright © 2026 laobamac. All rights reserved.\n//\n'
    text += '#pragma once\n#include <stdint.h>\nnamespace bcm { namespace radiodata {\n'
    text += 'struct Guard { const char *sha256; uint32_t header, data, countrySet, countries, locales, dataSources; };\n'
    text += 'static const Guard Guards[] = {\n'
    for guard in guards:
        text += '    {"' + guard['sha256'] + '", ' + ', '.join(hex(guard[k]) for k in
                 ('header', 'data', 'countrySet', 'countries', 'locales', 'dataSources')) + '},\n'
    text += '};\n'
    text += f'constexpr uint32_t CountryCount = {source.country_count};\n'
    text += f'constexpr uint32_t RuleCount = {len(POLICIES)};\n'
    text += f'constexpr const char *Scope = "{scope}";\n'
    text += f'constexpr uint32_t SourceLocaleSize = {len(source.locale_bytes)};\n'
    text += f'constexpr uint64_t CountryChecksum = {checksum(source.country_bytes)}ULL;\n'
    text += f'constexpr uint64_t LocaleChecksum = {checksum(source.locale_bytes)}ULL;\n'
    text += f'constexpr const char *LocaleSHA256 = "{report["localeTableSHA256"]}";\n'
    text += array('Countries', countries) + array('Locales', locales) + '} }\n'
    (directory / 'RadioPolicyData.hpp').write_text(text)
    (directory / 'RadioPolicy.json').write_text(json.dumps(report, indent=2) + '\n')
    for model in models:
        model.image.close()
    return report
