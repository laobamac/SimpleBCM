//
//  WirelessABI.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/9/7.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_WIRELESS_ABI_HPP
#define SIMPLEBCM_WIRELESS_ABI_HPP

#include <stddef.h>
#include <stdint.h>

namespace bcm {

constexpr uint32_t GetCommand = 0xC02869C9;
constexpr uint32_t SetCommand = 0x802869C8;
constexpr size_t CommandCapacity = 0x3C00;
constexpr size_t LargeCommandCapacity = 0x3C000;
constexpr size_t EventCapacity = 0x4000;
constexpr size_t MaximumEventPayload = 0x1000;
constexpr uint32_t EventNotification = 0xE00002D5;
constexpr uint32_t ScanResultRequest = 11;
constexpr uint32_t ScanMultipleRequest = 86;
constexpr size_t LegacyScanMultipleSize = 0x14E0;
constexpr size_t NativeScanMultipleSize = 0x14E8;
constexpr uint32_t CardCapabilitiesRequest = 12;
constexpr uint32_t ScanDoneEvent = 10;
constexpr uint32_t DriverAvailableEvent = 0x37;
constexpr size_t LegacyDriverAvailableSize = 0xB8;
constexpr size_t NativeDriverAvailableSize = 0xF8;
constexpr size_t PowerDataSize = 0x18;
constexpr uint32_t PowerStateAvailabilityReason = 0xE0821803;
constexpr uint32_t AssociationDoneEvent = 9;
constexpr size_t LegacyCapabilitySize = 12;
constexpr size_t ScanCompletionCapabilityByte = 5;
constexpr uint8_t ScanCompletionCapabilityMask = 0x40;
constexpr uint32_t AssociateRequest = 20;
constexpr size_t LegacyAssociateSize = 0x224;
constexpr uint32_t RoamProfileRequest = 216;
constexpr size_t NativeRoamProfileSize = 0x180;
constexpr size_t NativeRoamBandSize = 0x80;
constexpr size_t LegacyRoamBandSize = 0x7C;
constexpr size_t LegacyScanResultSize = 0x48C;
constexpr size_t ScanIELengthOffset = 0x8A;
constexpr size_t ScanIEOffset = 0x8C;
constexpr size_t LegacyScanIECapacity = 0x400;

struct UserABI {
    uint32_t kernel;
    const char *name;
    size_t scanResultSize;
    size_t capabilitySize;
    size_t associateSize;
    size_t joinStatusSize;
    uint32_t filterMonitorEvents;
};

constexpr UserABI SequoiaABI {24, "Sequoia", 0x8D8, 19, 0x384, 0x1CC, 0};
constexpr UserABI TahoeABI {25, "Tahoe", 0x8E0, 21, 0x38C, 0x1D4, 0x234};

inline const UserABI *userABIForKernel(uint32_t kernel) {
    return kernel == 24 ? &SequoiaABI : kernel == 25 ? &TahoeABI : nullptr;
}

inline size_t eventPayloadSize(uint32_t event, size_t length) {
    return event == DriverAvailableEvent && length == LegacyDriverAvailableSize
        ? NativeDriverAvailableSize : length;
}

inline bool copyEventPayload(uint32_t event, const void *source, size_t length,
                             uint8_t *destination, size_t capacity) {
    const auto outputLength = eventPayloadSize(event, length);
    if (length > MaximumEventPayload || outputLength > capacity ||
        (outputLength && !destination) || (length && !source))
        return false;
    const auto bytes = static_cast<const uint8_t *>(source);
    for (size_t offset = 0; offset < length; ++offset)
        destination[offset] = bytes[offset];
    for (size_t offset = length; offset < outputLength; ++offset)
        destination[offset] = 0;
    return true;
}

enum class Selector : uint32_t {
    Command,
    UseIOUC,
    Subscribe,
    MonitorStart,
    MonitorStop,
    UseEventPipe,
    LargeCommand,
    DriverKitSupported,
    MapUserBuffer,
    Count
};

struct Request {
    char interfaceName[16];
    int32_t type;
    int32_t value;
    uint32_t length;
    uint32_t reserved;
    uint64_t data;
};

struct LegacyRequest {
    Request request;
    uint32_t pointerSize;
    uint32_t reserved;
};

struct CommandHeader {
    uint32_t command;
    uint32_t length;
};

inline bool encodeScalarResult(Request &request, uint8_t *buffer, size_t capacity) {
    if (!buffer || capacity < sizeof(request.value) || request.length < sizeof(request.value))
        return false;
    const auto bytes = reinterpret_cast<const uint8_t *>(&request.value);
    for (size_t index = 0; index < sizeof(request.value); ++index)
        buffer[index] = bytes[index];
    request.length = sizeof(request.value);
    return true;
}

inline bool prepareScanResult(Request &request, uint8_t *buffer, size_t capacity, const UserABI &abi) {
    if (!buffer || capacity < abi.scanResultSize || request.length != abi.scanResultSize)
        return false;
    uint16_t length = static_cast<uint16_t>(buffer[ScanIELengthOffset] |
                                          (uint16_t(buffer[ScanIELengthOffset + 1]) << 8));
    if (length > LegacyScanIECapacity)
        length = LegacyScanIECapacity;
    buffer[ScanIELengthOffset] = static_cast<uint8_t>(length);
    buffer[ScanIELengthOffset + 1] = static_cast<uint8_t>(length >> 8);
    request.length = LegacyScanResultSize;
    return true;
}

inline bool expandScanResult(Request &request, uint8_t *buffer, size_t capacity, const UserABI &abi) {
    if (!buffer || capacity < abi.scanResultSize || request.length != LegacyScanResultSize)
        return false;
    for (size_t offset = LegacyScanResultSize; offset < abi.scanResultSize; ++offset)
        buffer[offset] = 0;
    request.length = static_cast<uint32_t>(abi.scanResultSize);
    return true;
}

inline bool expandCapabilities(Request &request, uint8_t *buffer, size_t capacity, const UserABI &abi,
                               bool scanEvents) {
    if (!buffer || capacity < abi.capabilitySize || request.length != LegacyCapabilitySize)
        return false;
    for (size_t offset = LegacyCapabilitySize; offset < abi.capabilitySize; ++offset)
        buffer[offset] = 0;
    if (scanEvents)
        buffer[ScanCompletionCapabilityByte] |= ScanCompletionCapabilityMask;
    request.length = static_cast<uint32_t>(abi.capabilitySize);
    return true;
}

inline uint32_t readUInt32(const uint8_t *buffer) {
    return uint32_t(buffer[0]) | (uint32_t(buffer[1]) << 8) |
           (uint32_t(buffer[2]) << 16) | (uint32_t(buffer[3]) << 24);
}

inline void writeUInt32(uint8_t *buffer, uint32_t value) {
    for (size_t index = 0; index < sizeof(value); ++index)
        buffer[index] = static_cast<uint8_t>(value >> (index * 8));
}

inline bool prepareScanMultiple(Request &request, uint8_t *buffer, size_t capacity) {
    if (!buffer || capacity < NativeScanMultipleSize || request.length != NativeScanMultipleSize ||
        readUInt32(buffer) != 1 || readUInt32(buffer + 8) > 10 ||
        readUInt32(buffer + 0x19C) > 16 || readUInt32(buffer + 0x210) > 400)
        return false;
    for (size_t index = 0; index < readUInt32(buffer + 8); ++index) {
        if (readUInt32(buffer + 0x10 + index * 0x28) > 32)
            return false;
    }
    for (size_t offset = LegacyScanMultipleSize; offset < NativeScanMultipleSize; ++offset)
        buffer[offset] = 0;
    request.length = LegacyScanMultipleSize;
    return true;
}

inline bool encodePowerAvailability(const uint8_t *power, size_t length,
                                    uint8_t *output, size_t capacity) {
    if (!power || !output || length != PowerDataSize || capacity < NativeDriverAvailableSize ||
        readUInt32(power) != 1)
        return false;
    const auto radios = readUInt32(power + 4);
    if (!radios || radios > 4)
        return false;
    uint32_t available = 0;
    for (size_t index = 0; index < radios; ++index) {
        const auto value = readUInt32(power + 8 + index * 4);
        if (value > 1)
            return false;
        available |= value;
    }
    for (size_t index = 0; index < NativeDriverAvailableSize; ++index)
        output[index] = 0;
    writeUInt32(output + 8, available);
    writeUInt32(output + 0x10, PowerStateAvailabilityReason);
    return true;
}

inline bool encodeJoinStatus(uint32_t status, uint32_t result, const uint8_t *bssid,
                              size_t bssidLength, uint8_t *output, size_t capacity, const UserABI &abi) {
    if (!output || capacity < abi.joinStatusSize ||
        (bssidLength && (!bssid || bssidLength != 6)))
        return false;
    for (size_t index = 0; index < abi.joinStatusSize; ++index)
        output[index] = 0;
    const bool sequoia = abi.kernel == 24;
    writeUInt32(output + (sequoia ? 0x08 : 0x1B8), status);
    writeUInt32(output + (sequoia ? 0x0C : 0x1BC), status);
    if (!sequoia) {
        writeUInt32(output + 0x1C4, result);
        writeUInt32(output + 0x1C8, 1);
    }
    for (size_t index = 0; index < bssidLength; ++index)
        output[(sequoia ? 0 : 0x1CC) + index] = bssid[index];
    return true;
}

inline bool prepareAssociate(Request &request, uint8_t *buffer, size_t capacity, const UserABI &abi) {
    if (!buffer || capacity < abi.associateSize || request.length != abi.associateSize)
        return false;
    const auto lower = readUInt32(buffer + 8);
    const auto upper = readUInt32(buffer + 12);
    if (lower > UINT16_MAX || upper > UINT16_MAX || buffer[0x206] > 3)
        return false;
    for (size_t offset = 0xC; offset < 0x215; ++offset)
        buffer[offset] = buffer[offset + 4];
    buffer[6] = static_cast<uint8_t>(lower);
    buffer[7] = static_cast<uint8_t>(lower >> 8);
    buffer[8] = static_cast<uint8_t>(upper);
    buffer[9] = static_cast<uint8_t>(upper >> 8);
    buffer[10] = buffer[11] = 0;
    for (size_t offset = 0x215; offset < 0x218; ++offset)
        buffer[offset] = 0;
    for (size_t offset = 0x218; offset < LegacyAssociateSize; ++offset)
        buffer[offset] = buffer[offset + 0x2C];
    for (size_t offset = LegacyAssociateSize; offset < abi.associateSize; ++offset)
        buffer[offset] = 0;
    request.length = LegacyAssociateSize;
    return true;
}

inline bool prepareRoamBand(Request &request, uint8_t *buffer, size_t capacity,
                            const uint8_t *band, size_t bandCapacity) {
    if (!buffer || !band || capacity < LegacyRoamBandSize || bandCapacity < NativeRoamBandSize ||
        readUInt32(band + 12) != 1)
        return false;
    for (size_t offset = 0; offset < 4; ++offset)
        buffer[offset] = band[offset + 12];
    for (size_t offset = 4; offset < 12; ++offset)
        buffer[offset] = band[offset];
    for (size_t offset = 12; offset < LegacyRoamBandSize; ++offset)
        buffer[offset] = band[offset + 4];
    request.length = LegacyRoamBandSize;
    return true;
}

inline bool expandRoamBand(const Request &request, const uint8_t *buffer, size_t capacity,
                           uint8_t *band, size_t bandCapacity) {
    if (!buffer || !band || capacity < LegacyRoamBandSize || bandCapacity < NativeRoamBandSize ||
        request.length != LegacyRoamBandSize)
        return false;
    for (size_t offset = LegacyRoamBandSize; offset > 12; --offset)
        band[offset + 3] = buffer[offset - 1];
    for (size_t offset = 4; offset < 12; ++offset)
        band[offset] = buffer[offset];
    for (size_t offset = 0; offset < 4; ++offset)
        band[offset + 12] = buffer[offset];
    for (size_t offset = 0; offset < 4; ++offset)
        band[offset] = 0;
    return true;
}

struct EventFilter {
    uint8_t all;
    uint8_t bitmap[31];

    bool accepts(uint32_t event) const {
        return all || (event && event <= sizeof(bitmap) * 8 &&
                       (bitmap[(event - 1) / 8] & (1U << ((event - 1) % 8))));
    }
};

struct EventState {
    uint32_t read;
    uint32_t write;
    uint32_t reserved;
};

struct __attribute__((packed, aligned(4))) EventHeader {
    uint32_t status;
    uint16_t flags;
    uint16_t sequence;
    uint64_t seconds;
    uint64_t microseconds;
    uint16_t length;
    uint16_t padding;
    uint32_t event;
    char interfaceName[16];
};

enum class RingResult : uint8_t {
    Written,
    Full,
    Invalid
};

class EventRing {
public:
    static RingResult append(uint8_t *ring, size_t capacity, EventState *state,
                             uint32_t &write, uint16_t &sequence, const char *name,
                             uint32_t event, const void *payload, size_t length,
                             uint64_t seconds, uint64_t microseconds) {
        if (!ring || !state || !name || capacity < 4096 || capacity > 0x80000 ||
            (capacity & 3) || length > MaximumEventPayload || (length && !payload))
            return RingResult::Invalid;
        const uint32_t read = __atomic_load_n(&state->read, __ATOMIC_ACQUIRE);
        if (read >= capacity || write >= capacity || ((read | write) & 3))
            return RingResult::Invalid;
        const size_t record = (sizeof(EventHeader) + length + 3) & ~size_t(3);
        const size_t tail = capacity - write;
        const size_t gap = tail < sizeof(EventHeader) ? tail : 0;
        const size_t available = read > write ? read - write : capacity - write + read;
        if (record + gap + 4 > available)
            return RingResult::Full;
        if (gap) {
            for (size_t offset = write; offset < capacity; offset += 4)
                __atomic_store_n(reinterpret_cast<uint32_t *>(ring + offset), 0x50U, __ATOMIC_RELEASE);
            write = 0;
        }
        auto header = reinterpret_cast<EventHeader *>(ring + write);
        __atomic_store_n(&header->status, 0x52U, __ATOMIC_RELAXED);
        header->flags = 0;
        header->sequence = ++sequence;
        header->seconds = seconds;
        header->microseconds = microseconds;
        header->length = static_cast<uint16_t>(length);
        header->padding = static_cast<uint16_t>(record - sizeof(EventHeader) - length);
        header->event = event;
        size_t index = 0;
        for (; index < sizeof(header->interfaceName) - 1 && name[index]; ++index)
            header->interfaceName[index] = name[index];
        for (; index < sizeof(header->interfaceName); ++index)
            header->interfaceName[index] = 0;
        const auto bytes = static_cast<const uint8_t *>(payload);
        for (size_t offset = 0; offset < record - sizeof(EventHeader); ++offset)
            ring[(write + sizeof(EventHeader) + offset) % capacity] = offset < length ? bytes[offset] : 0;
        __atomic_store_n(&header->status, 0x57U, __ATOMIC_RELEASE);
        write = static_cast<uint32_t>((write + record) % capacity);
        __atomic_store_n(&state->write, write, __ATOMIC_RELEASE);
        return RingResult::Written;
    }
};

static_assert(sizeof(Request) == 0x28, "Request ABI");
static_assert(offsetof(Request, data) == 0x20, "Request pointer ABI");
static_assert(sizeof(LegacyRequest) == 0x30, "Legacy request ABI");
static_assert(sizeof(CommandHeader) + CommandCapacity + sizeof(Request) == 0x3C30, "Command ABI");
static_assert(sizeof(CommandHeader) + LargeCommandCapacity + sizeof(Request) == 0x3C030, "Large command ABI");
static_assert(sizeof(EventFilter) == 0x20, "Event filter ABI");
static_assert(sizeof(EventState) == 0xC, "Event state ABI");
static_assert(sizeof(EventHeader) == 0x30, "Event header ABI");
static_assert(offsetof(EventHeader, length) == 0x18, "Event length ABI");
static_assert(offsetof(EventHeader, event) == 0x1C, "Event number ABI");

}

#endif
