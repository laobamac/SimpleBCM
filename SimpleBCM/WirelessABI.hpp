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
constexpr uint32_t PowerRequest = 19;
constexpr uint32_t LegacyDriverSetCommand = 0x803069C8;
constexpr uint32_t LegacyDriverGetCommand = 0xC03069C9;
constexpr uint32_t PowerStateAvailabilityReason = 0xE0821803;
constexpr uint32_t AssociationDoneEvent = 9;
constexpr size_t LegacyCapabilitySize = 12;
constexpr size_t ScanCompletionCapabilityByte = 5;
constexpr uint8_t ScanCompletionCapabilityMask = 0x40;
constexpr uint32_t AssociateRequest = 20;
constexpr size_t LegacyAssociateSize = 0x224;
constexpr uint32_t IBSSModeRequest = 24;
constexpr uint32_t HostAPModeRequest = 25;
constexpr int32_t NetworkModeStart = 1;
constexpr int32_t NetworkModeStop = 2;
constexpr size_t LegacyNetworkDataSize = 0x5DC;
constexpr size_t LegacyNetworkKeyOffset = 0x3C;
constexpr size_t NetworkKeySize = 0x94;
constexpr size_t LegacyNetworkRSNOffset = 0xD4;
constexpr size_t LegacyNetworkRSNCapacity = 0x100;
constexpr size_t NativeNetworkRSNCapacity = 0x200;
constexpr size_t NetworkIECapacity = 0x400;
constexpr uint32_t LegacyNetworkWPA2PSK = 0x400;
constexpr uint32_t LegacyNetworkPSKCipher = 10;
constexpr uint32_t RoamProfileRequest = 216;
constexpr size_t NativeRoamProfileSize = 0x180;
constexpr size_t NativeRoamBandSize = 0x80;
constexpr size_t LegacyRoamBandSize = 0x7C;
constexpr size_t LegacyScanResultSize = 0x48C;
constexpr size_t ScanIELengthOffset = 0x8A;
constexpr size_t ScanIEOffset = 0x8C;
constexpr size_t LegacyScanIECapacity = 0x400;

enum class AirPortBackend : uint8_t { Original, Tahoe };
enum class AssociateLayout : uint8_t { Legacy, Extended };
enum class JoinEventPolicy : uint8_t { Passthrough, Sequoia, Tahoe };
enum class NetworkDataResult : uint8_t { Valid, Invalid, Unsupported };

struct UserABI {
    uint32_t kernel;
    const char *name;
    size_t scanResultSize;
    size_t capabilitySize;
    size_t associateSize;
    size_t joinStatusSize;
    uint32_t filterMonitorEvents;
    size_t scanMultipleSize;
    size_t roamProfileSize;
    size_t driverAvailableSize;
    uint32_t selectorCount;
    AirPortBackend backend;
    AssociateLayout associateLayout;
    JoinEventPolicy joinEventPolicy;
    size_t networkDataSize;
    bool extendedNetworkAuth;
};

constexpr UserABI SonomaABI {23, "Sonoma", 0x4CC, 16, 0x358, 0, 0,
    LegacyScanMultipleSize, LegacyRoamBandSize, LegacyDriverAvailableSize, 7,
    AirPortBackend::Original, AssociateLayout::Legacy, JoinEventPolicy::Passthrough, 0x6DC, false};
constexpr UserABI SequoiaABI {24, "Sequoia", 0x8D8, 19, 0x384, 0x1CC, 0,
    NativeScanMultipleSize, NativeRoamProfileSize, NativeDriverAvailableSize, 9,
    AirPortBackend::Original, AssociateLayout::Extended, JoinEventPolicy::Sequoia, 0x6E4, true};
constexpr UserABI TahoeABI {25, "Tahoe", 0x8E0, 21, 0x38C, 0x1D4, 0x234,
    NativeScanMultipleSize, NativeRoamProfileSize, NativeDriverAvailableSize, 9,
    AirPortBackend::Tahoe, AssociateLayout::Extended, JoinEventPolicy::Tahoe, 0x6E8, true};

inline const UserABI *userABIForKernel(uint32_t kernel) {
    return kernel == 23 ? &SonomaABI : kernel == 24 ? &SequoiaABI : kernel == 25 ? &TahoeABI : nullptr;
}

inline size_t eventPayloadSize(uint32_t event, size_t length, const UserABI &abi) {
    return event == DriverAvailableEvent && length == LegacyDriverAvailableSize
        ? abi.driverAvailableSize : length;
}

inline bool copyEventPayload(uint32_t event, const void *source, size_t length,
                             uint8_t *destination, size_t capacity, const UserABI &abi) {
    const auto outputLength = eventPayloadSize(event, length, abi);
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

struct LocaleData {
    uint32_t version;
    uint32_t locale;
};

struct CountryCodeData {
    uint32_t version;
    char country[4];
};

constexpr uint32_t LocaleUnknown = 0;
constexpr uint32_t LocaleETSI = 2;
constexpr uint32_t LocaleRoW = 6;

inline void resolveLocale(LocaleData &data, const CountryCodeData &country) {
    if (data.version == 1 && data.locale == LocaleUnknown && country.version == 1 && country.country[0] != '\0')
        data.locale = LocaleRoW;
}

inline const char *localeString(uint32_t locale) {
    static const char *const names[] = {
        "Unknown", "FCC", "ETSI", "Japan", "Korea", "APAC", "RoW", "Indonesia"
    };
    return locale < sizeof(names) / sizeof(names[0]) ? names[locale] : names[0];
}

static_assert(sizeof(LocaleData) == 8 && offsetof(LocaleData, locale) == 4, "Locale ABI");
static_assert(sizeof(CountryCodeData) == 8 && offsetof(CountryCodeData, country) == 4, "Country code ABI");

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

inline bool isNetworkModeRequest(int32_t request) {
    return request == static_cast<int32_t>(IBSSModeRequest) || request == static_cast<int32_t>(HostAPModeRequest);
}

inline bool isNetworkPowerOff(const uint8_t *buffer, size_t length) {
    if (!buffer || length != PowerDataSize || readUInt32(buffer) != 1)
        return false;
    const auto radios = readUInt32(buffer + 4);
    if (!radios || radios > 4)
        return false;
    for (size_t index = 0; index < radios; ++index) {
        if (readUInt32(buffer + 8 + index * 4))
            return false;
    }
    return true;
}

inline bool preserveNetworkModePower(bool active, bool systemTransition,
                                     const uint8_t *buffer, size_t length) {
    return active && !systemTransition && isNetworkPowerOff(buffer, length);
}

inline bool isNetworkPowerOn(const uint8_t *buffer, size_t length) {
    if (!buffer || length != PowerDataSize || readUInt32(buffer) != 1)
        return false;
    const auto radios = readUInt32(buffer + 4);
    if (!radios || radios > 4)
        return false;
    bool on = false;
    for (size_t index = 0; index < radios; ++index) {
        const auto value = readUInt32(buffer + 8 + index * 4);
        if (value > 3)
            return false;
        on |= value != 0;
    }
    return on;
}

inline bool allowLegacyNetworkMode(const Request &request) {
    if (!isNetworkModeRequest(request.type))
        return false;
    if (request.value == NetworkModeStop)
        return request.length == 0;
    return request.value == NetworkModeStart && request.length == LegacyNetworkDataSize && request.data;
}

inline bool isLegacyHostAPWPA2(const Request &request, const uint8_t *buffer, size_t capacity) {
    return request.type == HostAPModeRequest && request.value == NetworkModeStart &&
        request.length == LegacyNetworkDataSize && buffer && capacity >= LegacyNetworkDataSize &&
        buffer[6] == 1 && !buffer[7] && !buffer[8] && buffer[9] == 4 &&
        readUInt32(buffer + LegacyNetworkKeyOffset) == 1 &&
        readUInt32(buffer + LegacyNetworkKeyOffset + 4) >= 8 &&
        readUInt32(buffer + LegacyNetworkKeyOffset + 4) <= 64 &&
        readUInt32(buffer + LegacyNetworkKeyOffset + 8) == LegacyNetworkPSKCipher;
}

inline uint32_t networkSSIDCipher(bool secured, uint32_t original) {
    return original | (secured ? 4U : 0U);
}

inline bool isNetworkWPA2PSK(const uint8_t *ie, size_t capacity) {
    static const uint8_t body[] = {1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4,
                                   1, 0, 0, 15, 172, 2};
    if (!ie || capacity < sizeof(body) + 2 || ie[0] != 48 ||
        (ie[1] != sizeof(body) && ie[1] != sizeof(body) + 2) || size_t(ie[1]) + 2 > capacity)
        return false;
    for (size_t index = 0; index < sizeof(body); ++index) {
        if (ie[index + 2] != body[index])
            return false;
    }
    return ie[1] == sizeof(body) || !(ie[sizeof(body) + 2] & 0xC0);
}

inline bool isNetworkPassphrase(const uint8_t *bytes, size_t length) {
    if (!bytes || length < 8 || length > 64)
        return false;
    for (size_t index = 0; index < length; ++index) {
        const auto byte = bytes[index];
        if (!byte || (length == 64 && !((byte >= '0' && byte <= '9') ||
            (byte >= 'a' && byte <= 'f') || (byte >= 'A' && byte <= 'F'))))
            return false;
    }
    return true;
}

inline NetworkDataResult prepareNetworkMode(Request &request, uint8_t *buffer, size_t capacity,
                                           const UserABI &abi) {
    if (!isNetworkModeRequest(request.type))
        return NetworkDataResult::Invalid;
    if (request.value == NetworkModeStop)
        return request.length == 0 ? NetworkDataResult::Valid : NetworkDataResult::Invalid;
    if (request.value != NetworkModeStart || !buffer || !request.data ||
        capacity < abi.networkDataSize || request.length != abi.networkDataSize || readUInt32(buffer) != 1)
        return NetworkDataResult::Invalid;
    const size_t shift = abi.extendedNetworkAuth ? 4 : 0;
    const size_t key = LegacyNetworkKeyOffset + shift;
    const size_t rsn = LegacyNetworkRSNOffset + shift;
    const size_t nativeTail = rsn + NativeNetworkRSNCapacity;
    const size_t legacyTail = LegacyNetworkRSNOffset + LegacyNetworkRSNCapacity;
    const size_t tailSize = LegacyNetworkDataSize - legacyTail;
    if (abi.networkDataSize < nativeTail + tailSize || readUInt32(buffer + 0x18 + shift) > 32 ||
        readUInt32(buffer + key) > 1 || readUInt32(buffer + key + 4) > 64 ||
        readUInt32(buffer + key + 0x50) > 8 || readUInt32(buffer + key + 0x64) > 16 ||
        readUInt32(buffer + key + 0x78) > 16 || readUInt32(buffer + nativeTail + 4) > NetworkIECapacity)
        return NetworkDataResult::Invalid;
    uint32_t lower = uint32_t(buffer[6]) | uint32_t(buffer[7]) << 8;
    uint32_t upper = uint32_t(buffer[8]) | uint32_t(buffer[9]) << 8;
    if (shift) {
        lower = readUInt32(buffer + 8);
        upper = readUInt32(buffer + 12);
        if (lower > UINT16_MAX || upper > UINT16_MAX)
            return NetworkDataResult::Invalid;
    }
    if (buffer[rsn] && size_t(buffer[rsn + 1]) + 2 > LegacyNetworkRSNCapacity)
        return NetworkDataResult::Unsupported;
    for (size_t offset = rsn + LegacyNetworkRSNCapacity; offset < nativeTail; ++offset) {
        if (buffer[offset])
            return NetworkDataResult::Unsupported;
    }
    for (size_t offset = nativeTail + tailSize; offset < abi.networkDataSize; ++offset) {
        if (buffer[offset])
            return NetworkDataResult::Unsupported;
    }
    const bool hostAP = request.type == HostAPModeRequest;
    const auto keyLength = readUInt32(buffer + key + 4);
    const auto cipher = readUInt32(buffer + key + 8);
    bool emptyRSN = true;
    for (size_t offset = 0; offset < LegacyNetworkRSNCapacity; ++offset)
        emptyRSN &= buffer[rsn + offset] == 0;
    const bool passphrase = hostAP && upper == 8 && cipher == 0 &&
        isNetworkPassphrase(buffer + key + 16, keyLength) &&
        (emptyRSN || isNetworkWPA2PSK(buffer + rsn, NativeNetworkRSNCapacity));
    const bool pmk = hostAP && upper == 8 && cipher == 6 && keyLength == 32 &&
        isNetworkWPA2PSK(buffer + rsn, NativeNetworkRSNCapacity);
    const bool secured = passphrase || pmk;
    if (hostAP && (lower != 1 || (!secured && (upper || keyLength || cipher || !emptyRSN))))
        return NetworkDataResult::Unsupported;
    if (shift) {
        for (size_t offset = 12; offset < legacyTail; ++offset)
            buffer[offset] = buffer[offset + shift];
        buffer[6] = static_cast<uint8_t>(lower);
        buffer[7] = static_cast<uint8_t>(lower >> 8);
        buffer[8] = static_cast<uint8_t>(upper);
        buffer[9] = static_cast<uint8_t>(upper >> 8);
        buffer[10] = buffer[11] = 0;
    }
    for (size_t offset = 0; offset < tailSize; ++offset)
        buffer[legacyTail + offset] = buffer[nativeTail + offset];
    if (pmk) {
        static const char hex[] = "0123456789abcdef";
        auto material = buffer + LegacyNetworkKeyOffset + 16;
        for (size_t offset = 32; offset; --offset) {
            const auto byte = material[offset - 1];
            material[(offset - 1) * 2] = hex[byte >> 4];
            material[(offset - 1) * 2 + 1] = hex[byte & 15];
        }
        writeUInt32(buffer + LegacyNetworkKeyOffset + 4, 64);
    }
    if (secured) {
        buffer[8] = static_cast<uint8_t>(LegacyNetworkWPA2PSK);
        buffer[9] = static_cast<uint8_t>(LegacyNetworkWPA2PSK >> 8);
        writeUInt32(buffer + LegacyNetworkKeyOffset, 1);
        writeUInt32(buffer + LegacyNetworkKeyOffset + 8, LegacyNetworkPSKCipher);
    }
    for (size_t offset = LegacyNetworkDataSize; offset < abi.networkDataSize; ++offset)
        buffer[offset] = 0;
    request.length = LegacyNetworkDataSize;
    return NetworkDataResult::Valid;
}

inline bool prepareScanMultiple(Request &request, uint8_t *buffer, size_t capacity, const UserABI &abi) {
    if (!buffer || capacity < abi.scanMultipleSize || request.length != abi.scanMultipleSize ||
        readUInt32(buffer) != 1 || readUInt32(buffer + 8) > 10 ||
        readUInt32(buffer + 0x19C) > 16 || readUInt32(buffer + 0x210) > 400)
        return false;
    for (size_t index = 0; index < readUInt32(buffer + 8); ++index) {
        if (readUInt32(buffer + 0x10 + index * 0x28) > 32)
            return false;
    }
    for (size_t offset = LegacyScanMultipleSize; offset < abi.scanMultipleSize; ++offset)
        buffer[offset] = 0;
    request.length = LegacyScanMultipleSize;
    return true;
}

inline bool encodePowerAvailability(const uint8_t *power, size_t length,
                                    uint8_t *output, size_t capacity, const UserABI &abi) {
    if (!power || !output || length != PowerDataSize || capacity < abi.driverAvailableSize ||
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
    for (size_t index = 0; index < abi.driverAvailableSize; ++index)
        output[index] = 0;
    writeUInt32(output + 8, available);
    writeUInt32(output + 0x10, PowerStateAvailabilityReason);
    return true;
}

inline bool encodeJoinStatus(uint32_t status, uint32_t result, const uint8_t *bssid,
                              size_t bssidLength, uint8_t *output, size_t capacity, const UserABI &abi) {
    if (abi.joinEventPolicy == JoinEventPolicy::Passthrough || !output || capacity < abi.joinStatusSize ||
        (bssidLength && (!bssid || bssidLength != 6)))
        return false;
    for (size_t index = 0; index < abi.joinStatusSize; ++index)
        output[index] = 0;
    const bool sequoia = abi.joinEventPolicy == JoinEventPolicy::Sequoia;
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
    if (abi.associateLayout == AssociateLayout::Legacy) {
        if (buffer[0x202] > 3)
            return false;
        request.length = LegacyAssociateSize;
        return true;
    }
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
