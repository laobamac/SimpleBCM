#!/usr/bin/env python3
#
#  verify.py
#  SimpleBCM
#
#  Created by laobamac on 2026/9/5.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import hashlib
import json
import plistlib
import subprocess
import tempfile
from pathlib import Path

from macho import Image
from audit_dependencies import audit
from verify_configuration import verify as verify_configuration


ROOT = Path(__file__).resolve().parent.parent
HOST_SOURCE = r'''
//
//  ABIValidation.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/9/5.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "WirelessABI.hpp"
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <dispatch/dispatch.h>
#include <assert.h>
#include <algorithm>
#include <atomic>
#include <stdio.h>
#include <string.h>
#include <thread>
#include <vector>

static uint64_t checked;
static unsigned scanConversions;
static unsigned nativeScanRecords;
static unsigned capabilityConversions;
static unsigned nativeScanWakeups;
static unsigned associationConversions;
static unsigned nativeRoamRecords;
static unsigned availabilityConversions;
static unsigned nativeAvailabilityRecords;
static unsigned joinStatusConversions;
static unsigned nativeJoinRecords;
static unsigned powerAvailabilityConversions;
static uint32_t randomState = 0xB8021125;
static uint32_t randomValue() {
    randomState ^= randomState << 13;
    randomState ^= randomState >> 17;
    randomState ^= randomState << 5;
    return randomState;
}

template<bool Sequoia> static void joinStatusVectors() {
    constexpr auto abi = Sequoia ? bcm::SequoiaABI : bcm::TahoeABI;
    const uint8_t bssid[] = {2, 4, 6, 8, 10, 12};
    for (uint32_t status : {0U, 17U, 65535U}) {
        for (uint32_t result : {0U, 1U, 2U, 9U}) {
            uint8_t arena[abi.joinStatusSize + 16];
            memset(arena, 0xA5, sizeof(arena));
            auto output = arena + 8;
            const auto addressLength = result == 1 ? sizeof(bssid) : 0;
            assert(!bcm::encodeJoinStatus(status, result, bssid, addressLength, output, abi.joinStatusSize - 1, abi));
            for (auto byte : arena)
                assert(byte == 0xA5);
            assert(bcm::encodeJoinStatus(status, result, bssid, addressLength, output, abi.joinStatusSize, abi));
            uint8_t expected[abi.joinStatusSize] {};
            bcm::writeUInt32(expected + (Sequoia ? 8 : 0x1B8), status);
            bcm::writeUInt32(expected + (Sequoia ? 12 : 0x1BC), status);
            if (!Sequoia) {
                bcm::writeUInt32(expected + 0x1C4, result);
                bcm::writeUInt32(expected + 0x1C8, 1);
            }
            if (addressLength)
                memcpy(expected + (Sequoia ? 0 : 0x1CC), bssid, sizeof(bssid));
            assert(!memcmp(output, expected, sizeof(expected)));
            for (size_t index = 0; index < 8; ++index)
                assert(arena[index] == 0xA5 && output[abi.joinStatusSize + index] == 0xA5);
            ++joinStatusConversions;
        }
    }
    uint8_t output[abi.joinStatusSize];
    memset(output, 0xA5, sizeof(output));
    assert(!bcm::encodeJoinStatus(0, 1, nullptr, 6, output, sizeof(output), abi));
    assert(!bcm::encodeJoinStatus(0, 1, bssid, 5, output, sizeof(output), abi));
    assert(!bcm::encodeJoinStatus(0, 1, bssid, 6, nullptr, sizeof(output), abi));
    for (auto byte : output)
        assert(byte == 0xA5);
}

static void powerAvailabilityVectors() {
    for (uint32_t radios = 1; radios <= 4; ++radios) {
        for (uint32_t mask = 0; mask < (1U << radios); ++mask) {
            uint8_t power[bcm::PowerDataSize] {};
            bcm::writeUInt32(power, 1);
            bcm::writeUInt32(power + 4, radios);
            for (size_t index = 0; index < radios; ++index)
                bcm::writeUInt32(power + 8 + 4 * index, (mask >> index) & 1);
            const std::vector<uint8_t> source(power, power + sizeof(power));
            uint8_t arena[bcm::NativeDriverAvailableSize + 16];
            memset(arena, 0xA5, sizeof(arena));
            auto output = arena + 8;
            assert(!bcm::encodePowerAvailability(power, sizeof(power), output, bcm::NativeDriverAvailableSize - 1));
            for (auto byte : arena)
                assert(byte == 0xA5);
            assert(bcm::encodePowerAvailability(power, sizeof(power), output, bcm::NativeDriverAvailableSize));
            assert(bcm::readUInt32(output + 8) == (mask ? 1 : 0));
            assert(bcm::readUInt32(output + 0x10) == bcm::PowerStateAvailabilityReason);
            for (size_t index = 0; index < bcm::NativeDriverAvailableSize; ++index)
                if (!(index >= 8 && index < 12) && !(index >= 0x10 && index < 0x14))
                    assert(output[index] == 0);
            for (size_t index = 0; index < 8; ++index)
                assert(arena[index] == 0xA5 && output[bcm::NativeDriverAvailableSize + index] == 0xA5);
            assert(!memcmp(power, source.data(), sizeof(power)));
            ++powerAvailabilityConversions;
        }
    }
    uint8_t power[bcm::PowerDataSize] {};
    uint8_t output[bcm::NativeDriverAvailableSize];
    memset(output, 0xA5, sizeof(output));
    assert(!bcm::encodePowerAvailability(power, sizeof(power), output, sizeof(output)));
    bcm::writeUInt32(power, 1);
    for (uint32_t radios : {0U, 5U}) {
        bcm::writeUInt32(power + 4, radios);
        assert(!bcm::encodePowerAvailability(power, sizeof(power), output, sizeof(output)));
    }
    bcm::writeUInt32(power + 4, 1);
    bcm::writeUInt32(power + 8, 2);
    assert(!bcm::encodePowerAvailability(power, sizeof(power), output, sizeof(output)));
    bcm::writeUInt32(power + 8, 1);
    assert(!bcm::encodePowerAvailability(power, sizeof(power) - 1, output, sizeof(output)));
    assert(!bcm::encodePowerAvailability(power, sizeof(power) + 1, output, sizeof(output)));
    assert(!bcm::encodePowerAvailability(nullptr, sizeof(power), output, sizeof(output)));
    assert(!bcm::encodePowerAvailability(power, sizeof(power), nullptr, sizeof(output)));
    for (auto byte : output)
        assert(byte == 0xA5);
}

static void availabilityVectors() {
    for (size_t length : {size_t(0), size_t(1), bcm::LegacyDriverAvailableSize - 1,
                         bcm::LegacyDriverAvailableSize, bcm::LegacyDriverAvailableSize + 1,
                         bcm::NativeDriverAvailableSize, bcm::MaximumEventPayload}) {
        for (uint32_t event : {9U, 37U, bcm::DriverAvailableEvent}) {
            std::vector<uint8_t> source(length);
            for (auto &byte : source)
                byte = static_cast<uint8_t>(randomValue());
            auto original = source;
            const auto expected = event == 0x37 && length == 0xB8 ? size_t(0xF8) : length;
            assert(bcm::eventPayloadSize(event, length) == expected);
            std::vector<uint8_t> arena(expected + 16, 0xA5);
            auto output = arena.data() + 8;
            if (expected) {
                assert(!bcm::copyEventPayload(event, source.data(), length, output, expected - 1));
                for (auto byte : arena)
                    assert(byte == 0xA5);
            }
            assert(bcm::copyEventPayload(event, source.data(), length, output, expected));
            if (length)
                assert(!memcmp(output, source.data(), length));
            for (size_t index = length; index < expected; ++index)
                assert(output[index] == 0);
            for (size_t index = 0; index < 8; ++index)
                assert(arena[index] == 0xA5 && output[expected + index] == 0xA5);
            assert(source == original);
            ++availabilityConversions;
        }
    }
    uint8_t output[bcm::NativeDriverAvailableSize];
    memset(output, 0xA5, sizeof(output));
    assert(!bcm::copyEventPayload(0x37, nullptr, 0xB8, output, sizeof(output)));
    assert(!bcm::copyEventPayload(0x37, output, 0xB8, nullptr, sizeof(output)));
    assert(!bcm::copyEventPayload(1, output, bcm::MaximumEventPayload + 1, output, sizeof(output)));
    for (auto byte : output)
        assert(byte == 0xA5);
}

static void nativeAvailability() {
    auto library = dlopen("/System/Library/PrivateFrameworks/CoreWiFi.framework/CoreWiFi", RTLD_NOW | RTLD_LOCAL);
    assert(library);
    auto cls = objc_getClass("CWFDriverAvailabilityMessage");
    assert(cls);
    auto send = reinterpret_cast<id (*)(id, SEL)>(objc_msgSend);
    auto initialize = reinterpret_cast<id (*)(id, SEL, id)>(objc_msgSend);
    auto getAvailable = reinterpret_cast<signed char (*)(id, SEL)>(objc_msgSend);
    auto getReason = reinterpret_cast<uint32_t (*)(id, SEL)>(objc_msgSend);
    for (uint32_t available : {0U, 1U}) {
        uint8_t legacy[bcm::LegacyDriverAvailableSize] {};
        uint32_t reason = 0x42;
        memcpy(legacy + 0x10, &reason, sizeof(reason));
        memcpy(legacy + 8, &available, sizeof(available));
        uint8_t converted[bcm::NativeDriverAvailableSize];
        assert(bcm::copyEventPayload(bcm::DriverAvailableEvent, legacy, sizeof(legacy), converted, sizeof(converted)));
        auto data = CFDataCreate(kCFAllocatorDefault, converted, sizeof(converted));
        assert(data);
        auto message = initialize(send(reinterpret_cast<id>(cls), sel_registerName("alloc")),
                                  sel_registerName("initWithDriverAvailabiltyData:"),
                                  reinterpret_cast<id>(const_cast<void *>(static_cast<const void *>(data))));
        assert(message);
        assert(getAvailable(message, sel_registerName("available")) == available);
        assert(getReason(message, sel_registerName("reason")) == reason);
        send(message, sel_registerName("release"));
        CFRelease(data);
        ++nativeAvailabilityRecords;
    }
    for (uint32_t available : {0U, 1U}) {
        uint8_t power[bcm::PowerDataSize] {};
        bcm::writeUInt32(power, 1);
        bcm::writeUInt32(power + 4, 2);
        bcm::writeUInt32(power + 12, available);
        uint8_t converted[bcm::NativeDriverAvailableSize];
        assert(bcm::encodePowerAvailability(power, sizeof(power), converted, sizeof(converted)));
        auto data = CFDataCreate(kCFAllocatorDefault, converted, sizeof(converted));
        assert(data);
        auto message = initialize(send(reinterpret_cast<id>(cls), sel_registerName("alloc")),
            sel_registerName("initWithDriverAvailabiltyData:"),
            reinterpret_cast<id>(const_cast<void *>(static_cast<const void *>(data))));
        assert(message);
        assert(getAvailable(message, sel_registerName("available")) == available);
        assert(getReason(message, sel_registerName("reason")) == bcm::PowerStateAvailabilityReason);
        send(message, sel_registerName("release"));
        CFRelease(data);
        ++nativeAvailabilityRecords;
    }
    dlclose(library);
}

static void unhex(const char *source, uint8_t *output, size_t length) {
    assert(strlen(source) == length * 2);
    for (size_t index = 0; index < length; ++index) {
        unsigned value;
        assert(sscanf(source + index * 2, "%2x", &value) == 1);
        output[index] = static_cast<uint8_t>(value);
    }
}

template<bool Sequoia> static void associationVectorFor(const char *nativeHex, const char *legacyHex) {
    constexpr auto abi = Sequoia ? bcm::SequoiaABI : bcm::TahoeABI;
    uint8_t arena[abi.associateSize + 16];
    memset(arena, 0xA5, sizeof(arena));
    auto buffer = arena + 8;
    uint8_t decoded[bcm::TahoeABI.associateSize];
    unhex(nativeHex, decoded, sizeof(decoded));
    memcpy(buffer, decoded, abi.associateSize);
    uint8_t original[abi.associateSize];
    memcpy(original, buffer, sizeof(original));
    uint8_t expected[bcm::LegacyAssociateSize];
    unhex(legacyHex, expected, sizeof(expected));
    bcm::Request request {};
    request.length = abi.associateSize;
    assert(!bcm::prepareAssociate(request, buffer, abi.associateSize - 1, abi));
    assert(!memcmp(buffer, original, sizeof(original)));
    assert(bcm::prepareAssociate(request, buffer, abi.associateSize, abi));
    assert(request.length == bcm::LegacyAssociateSize);
    assert(!memcmp(buffer, expected, sizeof(expected)));
    for (size_t offset = bcm::LegacyAssociateSize; offset < abi.associateSize; ++offset)
        assert(buffer[offset] == 0);
    for (size_t offset = 0; offset < 8; ++offset)
        assert(arena[offset] == 0xA5 && buffer[abi.associateSize + offset] == 0xA5);
    for (size_t field : {size_t(8), size_t(12), size_t(0x206)}) {
        memcpy(buffer, original, sizeof(original));
        if (field == 0x206)
            buffer[field] = 4;
        else
            buffer[field + 2] = 1;
        uint8_t rejected[abi.associateSize];
        memcpy(rejected, buffer, sizeof(rejected));
        request.length = abi.associateSize;
        assert(!bcm::prepareAssociate(request, buffer, abi.associateSize, abi));
        assert(!memcmp(buffer, rejected, sizeof(rejected)));
    }
    ++associationConversions;
}

static void associationVector(const char *nativeHex, const char *legacyHex) {
    associationVectorFor<false>(nativeHex, legacyHex);
    associationVectorFor<true>(nativeHex, legacyHex);
}

static void associationVectors() {
    associationVector(
        "010000000200000001000000000000000d00000053696d706c6542434d2d41424900000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000020000000000000000",
        "0100000002000100000000000d00000053696d706c6542434d2d4142490000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000");
    associationVector(
        "010000000200000001000000080000000d00000053696d706c6542434d2d41424900000000000000000000000000000000000000000000000000000001000000"
        "120000000a0000000000000053696d706c6542434d2d4142492d4f6e6c7900000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000160030140100000fac040100000fac040100000fac028000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000020000000b7594b71ca9b7dc3afce7ed1f4f2cbbd35ee6c9a499455ecb17ff92626b58ffd04000040"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000020000000000000000",
        "0100000002000100080000000d00000053696d706c6542434d2d4142490000000000000000000000000000000000000000000000000000000100000012000000"
        "0a0000000000000053696d706c6542434d2d4142492d4f6e6c790000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000160030140100000fac040100000fac040100000fac02800000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000020000000b7594b71ca9b7dc3afce7ed1f4f2cbbd35ee6c9a499455ecb17ff92626b58ffd0400004000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000");
}

static void decode(uint8_t *ring, size_t capacity, bcm::EventState &state, const std::vector<uint8_t> &expected) {
    uint32_t read = state.read;
    while (capacity - read < 48 || *reinterpret_cast<uint32_t *>(ring + read) == 0x50)
        read = (read + 4) % capacity;
    bcm::EventHeader header;
    memcpy(&header, ring + read, sizeof(header));
    assert(header.status == 0x57 && header.event == 1);
    assert(header.length == expected.size());
    assert(header.padding == (4 - expected.size() % 4) % 4);
    assert(strcmp(header.interfaceName, "en0") == 0);
    assert(header.seconds == 123 && header.microseconds == 456);
    for (size_t j = 0; j < expected.size(); ++j)
        assert(ring[(read + 48 + j) % capacity] == expected[j]);
    state.read = static_cast<uint32_t>((read + 48 + header.length + header.padding) % capacity);
    assert(state.read == state.write);
    ++checked;
}

template<bool Sequoia> static void boundaries() {
    constexpr auto abi = Sequoia ? bcm::SequoiaABI : bcm::TahoeABI;
    for (uint8_t mask : {uint8_t(0), uint8_t(0x3F), uint8_t(0x40), uint8_t(0xFF)}) {
        uint8_t arena[abi.capabilitySize + 16];
        memset(arena, 0xA5, sizeof(arena));
        auto buffer = arena + 8;
        buffer[bcm::ScanCompletionCapabilityByte] = mask;
        uint8_t original[bcm::LegacyCapabilitySize];
        memcpy(original, buffer, sizeof(original));
        bcm::Request request {};
        request.length = bcm::LegacyCapabilitySize;
        assert(!bcm::expandCapabilities(request, buffer, abi.capabilitySize - 1, abi, true));
        assert(bcm::expandCapabilities(request, buffer, abi.capabilitySize, abi, true));
        assert(request.length == abi.capabilitySize);
        for (size_t index = 0; index < bcm::LegacyCapabilitySize; ++index)
            assert(buffer[index] == (index == bcm::ScanCompletionCapabilityByte ?
                   (original[index] | bcm::ScanCompletionCapabilityMask) : original[index]));
        for (size_t index = bcm::LegacyCapabilitySize; index < abi.capabilitySize; ++index)
            assert(buffer[index] == 0);
        for (size_t index = 0; index < 8; ++index)
            assert(arena[index] == 0xA5 && buffer[abi.capabilitySize + index] == 0xA5);
        ++capabilityConversions;
    }
    for (uint16_t capacity : {uint16_t(0), uint16_t(1), uint16_t(0x400), uint16_t(0x800), uint16_t(0xFFFF)}) {
        uint8_t arena[abi.scanResultSize + 16];
        memset(arena, 0xA5, sizeof(arena));
        auto buffer = arena + 8;
        memcpy(buffer + bcm::ScanIELengthOffset, &capacity, sizeof(capacity));
        bcm::Request request {};
        request.length = abi.scanResultSize;
        assert(!bcm::prepareScanResult(request, buffer, abi.scanResultSize - 1, abi));
        assert(bcm::prepareScanResult(request, buffer, abi.scanResultSize, abi));
        assert(request.length == bcm::LegacyScanResultSize);
        uint16_t limited;
        memcpy(&limited, buffer + bcm::ScanIELengthOffset, sizeof(limited));
        assert(limited == std::min(capacity, uint16_t(bcm::LegacyScanIECapacity)));
        uint8_t original[bcm::LegacyScanResultSize];
        memcpy(original, buffer, sizeof(original));
        assert(!bcm::expandScanResult(request, buffer, abi.scanResultSize - 1, abi));
        assert(bcm::expandScanResult(request, buffer, abi.scanResultSize, abi));
        assert(request.length == abi.scanResultSize);
        assert(!memcmp(original, buffer, sizeof(original)));
        for (size_t offset = sizeof(original); offset < abi.scanResultSize; ++offset)
            assert(buffer[offset] == 0);
        for (size_t offset = 0; offset < 8; ++offset)
            assert(arena[offset] == 0xA5 && buffer[abi.scanResultSize + offset] == 0xA5);
        ++scanConversions;
    }
    for (int32_t value : {INT32_MIN, -1, 0, 1, 0x12345678, INT32_MAX}) {
        bcm::Request request {};
        request.value = value;
        request.length = 32;
        uint8_t bytes[8];
        memset(bytes, 0xA5, sizeof(bytes));
        assert(bcm::encodeScalarResult(request, bytes, sizeof(bytes)));
        int32_t decoded;
        memcpy(&decoded, bytes, sizeof(decoded));
        assert(decoded == value && request.length == 4);
        for (size_t i = 4; i < sizeof(bytes); ++i)
            assert(bytes[i] == 0xA5);
        request.length = 3;
        assert(!bcm::encodeScalarResult(request, bytes, sizeof(bytes)));
    }
    alignas(8) uint8_t arena[0x4000 + 16];
    auto ring = arena + 8;
    for (size_t capacity : {size_t(4096), size_t(16384)}) {
        for (uint32_t offset = 0; offset < capacity; offset += 4) {
            for (size_t length : {size_t(0), size_t(1), size_t(3), size_t(4), size_t(37), size_t(1023), size_t(4080)}) {
                memset(arena, 0xA5, sizeof(arena));
                bcm::EventState state {offset, offset, 0};
                uint32_t write = offset;
                uint16_t sequence = 65535;
                std::vector<uint8_t> payload(length);
                for (size_t i = 0; i < length; ++i)
                    payload[i] = static_cast<uint8_t>(i * 7);
                auto result = bcm::EventRing::append(ring, capacity, &state, write, sequence, "en0", 1,
                                                    payload.data(), payload.size(), 123, 456);
                if (48 + length + 3 >= capacity) {
                    assert(result == bcm::RingResult::Full);
                } else if (result == bcm::RingResult::Written) {
                    decode(ring, capacity, state, payload);
                    assert(sequence == 0);
                } else {
                    assert(capacity == 4096 && length == 4080);
                }
                for (size_t i = 0; i < 8; ++i) {
                    assert(arena[i] == 0xA5);
                    assert(ring[capacity + i] == 0xA5);
                }
            }
        }
    }
    bcm::EventState state {};
    uint32_t write = 0;
    uint16_t sequence = 0;
    const auto before = state;
    assert(bcm::EventRing::append(ring, 16384, &state, write, sequence, "en0", 1, nullptr, 4097, 0, 0) == bcm::RingResult::Invalid);
    assert(memcmp(&state, &before, sizeof(state)) == 0);
    state.read = 3;
    assert(bcm::EventRing::append(ring, 16384, &state, write, sequence, "en0", 1, nullptr, 0, 0, 0) == bcm::RingResult::Invalid);
    bcm::EventFilter filter {};
    assert(!filter.accepts(1) && !filter.accepts(248) && !filter.accepts(249));
    filter.bitmap[0] = 1;
    filter.bitmap[30] = 0x80;
    assert(filter.accepts(1) && filter.accepts(248) && !filter.accepts(2) && !filter.accepts(249));
}

static void concurrent() {
    alignas(8) uint8_t ring[0x4000] {};
    bcm::EventState state {};
    constexpr uint32_t total = 100000;
    std::thread producer([&] {
        uint32_t write = 0;
        uint16_t sequence = 0;
        for (uint32_t n = 0; n < total; ++n) {
            const size_t length = randomValue() % 1024;
            std::vector<uint8_t> payload(length, static_cast<uint8_t>(n));
            for (;;) {
                auto result = bcm::EventRing::append(ring, sizeof(ring), &state, write, sequence,
                    "en0", n + 1, payload.data(), length, length, n);
                assert(result != bcm::RingResult::Invalid);
                if (result == bcm::RingResult::Written)
                    break;
                std::this_thread::yield();
            }
        }
    });
    std::thread consumer([&] {
        uint32_t read = 0;
        for (uint32_t n = 0; n < total;) {
            if (read == __atomic_load_n(&state.write, __ATOMIC_ACQUIRE)) {
                std::this_thread::yield();
                continue;
            }
            if (sizeof(ring) - read < 48 || *reinterpret_cast<uint32_t *>(ring + read) == 0x50) {
                read = (read + 4) % sizeof(ring);
                __atomic_store_n(&state.read, read, __ATOMIC_RELEASE);
                continue;
            }
            bcm::EventHeader header;
            memcpy(&header, ring + read, sizeof(header));
            assert(header.status == 0x57 && header.event == n + 1);
            assert(header.seconds == header.length && header.microseconds == n);
            for (size_t i = 0; i < header.length; ++i)
                assert(ring[(read + 48 + i) % sizeof(ring)] == static_cast<uint8_t>(n));
            read = (read + 48 + header.length + header.padding) % sizeof(ring);
            __atomic_store_n(&state.read, read, __ATOMIC_RELEASE);
            ++n;
        }
    });
    producer.join();
    consumer.join();
    assert(state.read == state.write);
    checked += total;
}

struct NativeResult {
    const uint8_t *expected;
    size_t length;
    unsigned calls;
    uint32_t event;
};

static void callback(int status, void *, uint32_t event, const void *payload, size_t length, void *reference) {
    auto result = static_cast<NativeResult *>(reference);
    assert(status == 0 && event == result->event);
    assert(length == std::min(result->length, size_t(4080)));
    if (length)
        assert(memcmp(payload, result->expected, length) == 0);
    ++result->calls;
}

template<typename T> static void field(uint8_t *object, size_t offset, T value) {
    memcpy(object + offset, &value, sizeof(value));
}

static char nativeUUID[37] = "unavailable";

static unsigned nativeConsumer() {
    auto library = dlopen("/System/Library/PrivateFrameworks/IO80211.framework/IO80211", RTLD_NOW | RTLD_LOCAL);
    assert(library);
    auto open = reinterpret_cast<int (*)(void **)>(dlsym(library, "Apple80211Open"));
    auto close = reinterpret_cast<int (*)(void *)>(dlsym(library, "Apple80211Close"));
    assert(open && close);
    Dl_info info {};
    assert(dladdr(reinterpret_cast<void *>(open), &info));
    auto header = static_cast<const mach_header_64 *>(info.dli_fbase);
    auto command = reinterpret_cast<const uint8_t *>(header + 1);
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        auto load = reinterpret_cast<const load_command *>(command);
        if (load->cmd == LC_UUID) {
            auto u = reinterpret_cast<const uuid_command *>(load)->uuid;
            snprintf(nativeUUID, sizeof(nativeUUID),
                "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                u[0],u[1],u[2],u[3],u[4],u[5],u[6],u[7],u[8],u[9],u[10],u[11],u[12],u[13],u[14],u[15]);
        }
        command += load->cmdsize;
    }
    // These optional native-consumer fixtures use private function layouts.
    // A different framework can still build; do not call an unfamiliar layout.
    if (strcmp(nativeUUID, "A7A35846-4067-3182-B70E-F7477FBC32BD")) {
        fprintf(stderr, "Native consumer skipped: framework UUID has no executable fixture.\n");
        dlclose(library);
        return 0;
    }
    auto address = reinterpret_cast<const uint8_t *>(header) + 0x32B7A;
    auto scanAddress = reinterpret_cast<const uint8_t *>(header) + 0x6D4F;
    auto roamAddress = reinterpret_cast<const uint8_t *>(header) + 0x37432;
    static const uint8_t guard[] = {0x55,0x48,0x89,0xE5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xEC,0x08,0x01,0x00,0x00,0x48,0x8B,0x05,0x33};
    static const uint8_t scanGuard[] = {0x55,0x48,0x89,0xE5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xEC,0xD8,0x00,0x00,0x00};
    static const uint8_t roamGuard[] = {0x55,0x48,0x89,0xE5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x83,0xEC,0x28};
    if (memcmp(address, guard, sizeof(guard)) || memcmp(scanAddress, scanGuard, sizeof(scanGuard)) ||
        memcmp(roamAddress, roamGuard, sizeof(roamGuard))) {
        fprintf(stderr, "Native private-consumer fixtures skipped: unrecognized function layout.\n");
        dlclose(library);
        return 0;
    }
    auto consume = reinterpret_cast<void (*)(void *, uint32_t, const uint64_t *, uint32_t)>(const_cast<uint8_t *>(address));
    void *opaque = nullptr;
    assert(open(&opaque) == 0 && opaque);
    auto context = static_cast<uint8_t *>(opaque);
    auto port = IONotificationPortCreate(kIOMainPortDefault);
    assert(port);
    field(context, 0x17C, IONotificationPortGetMachPort(port));
    field(context, 0x198, port);
    field(context, 0x33, uint8_t(1));
    field(context, 0x34, uint8_t(1));
    field(context, 0x48, callback);
    memcpy(context + 4, "en0", 4);
    alignas(8) uint8_t ring[0x4000] {};
    bcm::EventState state {};
    field(context, 0x1A0, ring + 0);
    field(context, 0x1A8, size_t(sizeof(ring)));
    field(context, 0x1B0, &state);
    unsigned count = 0;
    for (uint32_t offset : {0U, 4U, 12288U, 16284U, 16332U, 16336U, 16340U, 16380U}) {
        for (size_t length : {size_t(0),size_t(1),size_t(3),size_t(4),size_t(37),size_t(1024),size_t(4080),size_t(4096)}) {
            memset(ring, 0, sizeof(ring));
            state = {offset, offset, 0};
            uint32_t write = offset;
            uint16_t sequence = 65535;
            std::vector<uint8_t> payload(length);
            for (size_t i = 0; i < length; ++i)
                payload[i] = static_cast<uint8_t>(i * 13);
            NativeResult result {payload.data(), length, 0, 1};
            field(context, 0x50, &result);
            assert(bcm::EventRing::append(ring, sizeof(ring), &state, write, sequence, "en0", 1,
                                         payload.data(), length, 123, 456) == bcm::RingResult::Written);
            consume(opaque, bcm::EventNotification, nullptr, 0);
            assert(state.read == write);
            assert(result.calls == 1);
            ++count;
        }
    }
    auto semaphore = dispatch_semaphore_create(0);
    assert(semaphore);
    field(context, 0x98, semaphore);
    for (uint32_t offset : {0U, 4U, 16332U, 16336U, 16380U}) {
        for (size_t length : {size_t(0), sizeof(uint32_t)}) {
            memset(ring, 0, sizeof(ring));
            state = {offset, offset, 0};
            uint32_t write = offset;
            uint16_t sequence = 0;
            uint32_t status = 0;
            auto payload = reinterpret_cast<const uint8_t *>(&status);
            NativeResult result {payload, length, 0, bcm::ScanDoneEvent};
            field(context, 0x50, &result);
            assert(bcm::EventRing::append(ring, sizeof(ring), &state, write, sequence, "en0",
                   bcm::ScanDoneEvent, payload, length, 123, 456) == bcm::RingResult::Written);
            consume(opaque, bcm::EventNotification, nullptr, 0);
            assert(state.read == write && result.calls == 1);
            assert(dispatch_semaphore_wait(semaphore, DISPATCH_TIME_NOW) == 0);
            assert(dispatch_semaphore_wait(semaphore, DISPATCH_TIME_NOW) != 0);
            ++nativeScanWakeups;
        }
    }
    field(context, 0x98, static_cast<void *>(nullptr));
    dispatch_release(semaphore);
    for (uint32_t offset : {0U, 4U, 16332U, 16336U, 16380U}) {
        for (uint32_t available : {0U, 1U}) {
            uint8_t legacy[bcm::LegacyDriverAvailableSize] {};
            memcpy(legacy + 8, &available, sizeof(available));
            uint8_t payload[bcm::NativeDriverAvailableSize];
            assert(bcm::copyEventPayload(bcm::DriverAvailableEvent, legacy, sizeof(legacy), payload, sizeof(payload)));
            memset(ring, 0, sizeof(ring));
            state = {offset, offset, 0};
            uint32_t write = offset;
            uint16_t sequence = 0;
            NativeResult result {payload, sizeof(payload), 0, bcm::DriverAvailableEvent};
            field(context, 0x50, &result);
            assert(bcm::EventRing::append(ring, sizeof(ring), &state, write, sequence, "en0",
                bcm::DriverAvailableEvent, payload, sizeof(payload), 123, 456) == bcm::RingResult::Written);
            consume(opaque, bcm::EventNotification, nullptr, 0);
            assert(state.read == write && result.calls == 1);
            ++nativeAvailabilityRecords;
        }
    }
    for (uint32_t offset : {0U, 4U, 15868U, 16336U, 16380U}) {
        for (uint32_t status : {0U, 17U}) {
            uint8_t payload[bcm::TahoeABI.joinStatusSize];
            const uint8_t bssid[] = {2, 4, 6, 8, 10, 12};
            assert(bcm::encodeJoinStatus(status, status ? 2 : 1, bssid, status ? 0 : 6, payload, sizeof(payload), bcm::TahoeABI));
            memset(ring, 0, sizeof(ring));
            state = {offset, offset, 0};
            uint32_t write = offset;
            uint16_t sequence = 0;
            NativeResult result {payload, sizeof(payload), 0, bcm::AssociationDoneEvent};
            field(context, 0x50, &result);
            assert(bcm::EventRing::append(ring, sizeof(ring), &state, write, sequence, "en0",
                bcm::AssociationDoneEvent, payload, sizeof(payload), 123, 456) == bcm::RingResult::Written);
            consume(opaque, bcm::EventNotification, nullptr, 0);
            assert(state.read == write && result.calls == 1);
            ++nativeJoinRecords;
        }
    }
    field(context, 0x17C, uint32_t(0));
    field(context, 0x198, static_cast<void *>(nullptr));
    field(context, 0x1A0, static_cast<void *>(nullptr));
    field(context, 0x1B0, static_cast<void *>(nullptr));
    field(context, 0x48, static_cast<void *>(nullptr));
    field(context, 0x50, static_cast<void *>(nullptr));
    IONotificationPortDestroy(port);
    assert(close(opaque) == 0);
    using Parse = int (*)(void *, void *, CFMutableArrayRef, CFMutableArrayRef, void *, int, int, int, int, int, int);
    auto parse = reinterpret_cast<Parse>(const_cast<uint8_t *>(scanAddress));
    opaque = nullptr;
    assert(open(&opaque) == 0 && opaque);
    for (uint16_t ieLength : {uint16_t(0), uint16_t(32), uint16_t(0x400)}) {
        uint8_t record[bcm::TahoeABI.scanResultSize] {};
        field(record, 0, uint32_t(1));
        field(record, 4, uint32_t(1));
        field(record, 8, uint32_t(1));
        field(record, 12, uint32_t(0x80));
        field(record, 0x16, int16_t(-55));
        field(record, 0x18, uint16_t(100));
        field(record, 0x1A, uint16_t(1));
        record[0x1C] = 2;
        record[0x21] = 1;
        record[0x60] = 3;
        memcpy(record + 0x61, "SBC", 3);
        field(record, bcm::ScanIELengthOffset, ieLength);
        bcm::Request request {};
        request.length = bcm::TahoeABI.scanResultSize;
        assert(bcm::prepareScanResult(request, record, sizeof(record), bcm::TahoeABI));
        assert(bcm::expandScanResult(request, record, sizeof(record), bcm::TahoeABI));
        auto first = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
        auto second = CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks);
        assert(first && second);
        assert(parse(opaque, record, first, second, nullptr, 0, 0, 1, 0, 0, 0) == 0);
        assert(CFArrayGetCount(first) == 1 && CFArrayGetCount(second) == 1);
        CFRelease(first);
        CFRelease(second);
        ++nativeScanRecords;
    }
    assert(close(opaque) == 0);
    using ParseRoam = void (*)(int, const void *, CFMutableDictionaryRef);
    auto parseRoam = reinterpret_cast<ParseRoam>(const_cast<uint8_t *>(roamAddress));
    const char *roamVectors[] = {"01000000020000000100000080ffffffb5800abf0000000000000000030046000a0001000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "01000000040000000100000080ffffffb5800abf0000000000000000030046000a0001000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"};
    for (auto vector : roamVectors) {
        uint8_t legacy[bcm::LegacyRoamBandSize];
        unhex(vector, legacy, sizeof(legacy));
        uint8_t arena[bcm::NativeRoamBandSize + 16];
        memset(arena, 0xA5, sizeof(arena));
        auto native = arena + 8;
        bcm::Request request {};
        request.length = bcm::LegacyRoamBandSize;
        assert(!bcm::expandRoamBand(request, legacy, sizeof(legacy), native, bcm::NativeRoamBandSize - 1));
        assert(bcm::expandRoamBand(request, legacy, sizeof(legacy), native, bcm::NativeRoamBandSize));
        auto dictionary = CFDictionaryCreateMutable(nullptr, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        parseRoam(0, native, dictionary);
        assert(CFDictionaryGetCount(dictionary) == 3);
        CFRelease(dictionary);
        uint8_t recovered[bcm::LegacyRoamBandSize];
        assert(bcm::prepareRoamBand(request, recovered, sizeof(recovered), native, bcm::NativeRoamBandSize));
        assert(!memcmp(recovered, legacy, sizeof(legacy)));
        for (size_t offset = 0; offset < 8; ++offset)
            assert(arena[offset] == 0xA5 && native[bcm::NativeRoamBandSize + offset] == 0xA5);
        ++nativeRoamRecords;
    }
    dlclose(library);
    return count;
}

static void profileBoundaries() {
    assert(!bcm::userABIForKernel(23) && !bcm::userABIForKernel(26));
    assert(bcm::userABIForKernel(24)->kernel == 24 && bcm::userABIForKernel(25)->kernel == 25);
    assert(bcm::SequoiaABI.filterMonitorEvents == 0 && bcm::TahoeABI.filterMonitorEvents == 564);
    for (const auto &abi : {bcm::SequoiaABI, bcm::TahoeABI}) {
        std::vector<uint8_t> buffer(abi.scanResultSize + 8, 0xA5);
        bcm::Request request {};
        request.length = static_cast<uint32_t>(abi.kernel == 24 ? 0x8E0 : 0x8D8);
        assert(!bcm::prepareScanResult(request, buffer.data(), buffer.size(), abi));
        request.length = static_cast<uint32_t>(abi.kernel == 24 ? 0x38C : 0x384);
        assert(!bcm::prepareAssociate(request, buffer.data(), buffer.size(), abi));
        for (auto byte : buffer)
            assert(byte == 0xA5);
        for (bool scanEvents : {false, true}) {
            memset(buffer.data(), 0, buffer.size());
            buffer[0] = 0x81;
            request.length = bcm::LegacyCapabilitySize;
            assert(bcm::expandCapabilities(request, buffer.data(), buffer.size(), abi, scanEvents));
            assert(request.length == abi.capabilitySize && buffer[0] == 0x81);
            assert(buffer[5] == (scanEvents ? 0x40 : 0));
            for (size_t i = 12; i < abi.capabilitySize; ++i)
                assert(buffer[i] == 0);
        }
    }
}

int main() {
    profileBoundaries();
    boundaries<false>();
    boundaries<true>();
    availabilityVectors();
    joinStatusVectors<false>();
    joinStatusVectors<true>();
    powerAvailabilityVectors();
    nativeAvailability();
    associationVectors();
    concurrent();
    const auto native = nativeConsumer();
    printf("{\"ringRecords\":%llu,\"nativeConsumerRecords\":%u,\"scalarValueEncodings\":6,\"scanResultConversions\":%u,\"nativeScanConsumerRecords\":%u,\"capabilityConversions\":%u,\"nativeScanWakeups\":%u,\"associationConversions\":%u,\"nativeRoamRecords\":%u,\"availabilityConversions\":%u,\"nativeAvailabilityRecords\":%u,\"joinStatusConversions\":%u,\"nativeJoinRecords\":%u,\"nativeUUID\":\"%s\"}\n", checked, native, scanConversions, nativeScanRecords, capabilityConversions, nativeScanWakeups, associationConversions, nativeRoamRecords, availabilityConversions, nativeAvailabilityRecords, joinStatusConversions, nativeJoinRecords, nativeUUID);
}
'''


def run(args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode})\n{result.stdout}\n{result.stderr}")
    return result.stdout


def source_fingerprint():
    digest = hashlib.sha256()
    paths = sorted([path for folder in ["SimpleBCM", "Config", "Tools"]
                    for path in (ROOT / folder).iterdir() if path.is_file()]
                   + [ROOT / "SimpleBCM.xcodeproj/project.pbxproj"])
    for path in paths:
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    compiled = [path for path in paths if path.parent.name != 'Tools']
    return digest.hexdigest(), max(path.stat().st_mtime_ns for path in compiled)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Release")
    args = parser.parse_args()
    binary = ROOT / f"build/DerivedData/Build/Products/{args.configuration}/SimpleBCM.kext/Contents/MacOS/SimpleBCM"
    fingerprint, newest = source_fingerprint()
    if newest > binary.stat().st_mtime_ns:
        raise RuntimeError("内核源码新于二进制，先运行 Tools/build.py。")
    image = Image(binary)
    assert run(["xcrun", "lipo", "-archs", str(binary)]).strip() == "x86_64"
    assert struct_type(image.data) == 11
    plist = plistlib.loads((binary.parent.parent / "Info.plist").read_bytes())
    assert plist["CFBundleIdentifier"] == "cn.laobamac.SimpleBCM"
    assert plist["OSBundleLibraries"]["as.vit9696.Lilu"] == "1.7.1"
    symbols = run(["nm", "-gj", str(binary)])
    for name in ["_SimpleBCM_kern_start", "_SimpleBCM_kern_stop", "_kmod_info"]:
        assert name in symbols.splitlines(), name
    imports = set(run(["nm", "-u", "-j", str(binary)]).splitlines())
    lilu = {
        "__ZN13KernelPatcher10clearErrorEv", "__ZN13KernelPatcher11solveSymbolEmPKc", "__ZN13KernelPatcher15kernelWriteLockE",
        "__ZN13KernelPatcher17routeMultipleLongEmPNS_12RouteRequestEmymbb", "__ZN7LiluAPI10onKextLoadEPN13KernelPatcher8KextInfoEmPFvPvRS0_mymES3_",
        "__ZN7LiluAPI10shouldLoadEPKcmjPS1_mS2_mS2_m13KernelVersionS3_Rb",
        "__ZN7LiluAPI13releaseAccessEv", "__ZN7LiluAPI13requestAccessEmb", "__ZN8MachInfo16setKernelWritingEbP13_IOSimpleLock", "_lilu", "_lilu_os_log",
    }
    if args.configuration == "Debug":
        lilu.add("__ZN4Page7deleterEPS_")
    dependency = ROOT / "build/Lilu/Release/Lilu.kext/Contents/MacOS/Lilu"
    lilu_defined = set(run(["nm", "-g", "-j", "-U", str(dependency)]).splitlines())
    assert lilu <= lilu_defined, sorted(lilu - lilu_defined)
    assert imports & lilu_defined == lilu, sorted((imports & lilu_defined) ^ lilu)
    defined = set(run(["nm", "-g", "-j", "-U", "/System/Library/KernelCollections/BootKernelExtensions.kc"]).splitlines())
    assert imports - defined == lilu, sorted((imports - defined) ^ lilu)
    for name in ["_copyin", "_copyout"]:
        assert name in defined
    profile = json.loads((ROOT / "Docs/ABI.json").read_text())
    for data in profile["images"].values():
        path = ROOT / data["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == data["sha256"], path
        assert Image(path).uuid == data["uuid"], path
        assert Image(path).data not in image.data, f"驱动不应内嵌到 SimpleBCM：{path}"
    dependencies = audit(args.configuration)
    configuration_checks = verify_configuration()
    with tempfile.TemporaryDirectory(prefix="SimpleBCM-ABI-") as folder:
        source = Path(folder) / "ABIValidation.cpp"
        executable = Path(folder) / "ABIValidation"
        source.write_text(HOST_SOURCE)
        run(["xcrun", "clang++", "-std=c++14", "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             "-mmacosx-version-min=15.0",
             "-I", str(ROOT / "SimpleBCM"), str(source), "-framework", "IOKit", "-framework", "CoreFoundation", "-lobjc", "-o", str(executable)])
        host = json.loads(run([str(executable)], timeout=60).strip())
    report = {"configuration": args.configuration, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "uuid": image.uuid,
              "sourceFingerprint": fingerprint, "imports": len(imports), "kernelCollectionImports": len(imports & defined), "liluImports": sorted(lilu),
              "liluSHA256": hashlib.sha256(dependency.read_bytes()).hexdigest(),
              "liluMinimum": "1.7.1", "supportedKernel": "24.x / 25.x", "driverLoading": "external",
              "configurationChecks": configuration_checks,
              "validationMode": "host-executed",
              "codecProfiles": ["Sequoia", "Tahoe"],
              "dependencySymbolInventory": {"images": len(dependencies["images"]), "inheritedVtableRepairs": len(dependencies["inheritedVtableRepairs"]), "unmatchedImports": dependencies["unmatchedImports"]},
              "architecture": "x86_64", "sanitizers": ["AddressSanitizer", "UndefinedBehaviorSanitizer"], "hostABI": host,
              "hardwareValidation": "pending", "OSBuild": run(["sysctl", "-n", "kern.osversion"]).strip()}
    destination = ROOT / f"build/Validation-{args.configuration}.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def struct_type(data):
    import struct
    return struct.unpack_from("<I", data, 12)[0]


if __name__ == "__main__":
    main()
