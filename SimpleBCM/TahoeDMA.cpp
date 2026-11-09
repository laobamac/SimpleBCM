//
//  TahoeDMA.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/8.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "TahoeDMA.hpp"
#include "Patcher.hpp"
#include "../build/Embedded/TahoeDMAData.hpp"

extern "C" {
void bcmTahoeTxEntry();
void bcmTahoeRxFillEntry();
void bcmTahoeRxCopyEntry();
uintptr_t bcmTahoeTxResume;
uintptr_t bcmTahoeTxFail;
uintptr_t bcmTahoeRxFillResume;
uintptr_t bcmTahoeRxFillFail;
uintptr_t bcmTahoeRxCopyResume;
}

namespace bcm {
namespace {

struct Buffer {
    uint64_t address;
    uint8_t *bytes;
};

struct Slot {
    uint8_t *bytes;
    uint64_t address;
    void *mapping;
};

struct Ring {
    void *key;
    Slot *slots;
    uint32_t count;
    uint32_t capacity;
};

using Allocate = Buffer (*)(void *, uint64_t, uint32_t, uint32_t, void *);
using PacketData = uint8_t *(*)(void *, void *);
using PacketLength = size_t (*)(void *, void *);
using PacketNext = void *(*)(void *, void *);
using PacketFree = void (*)(void *, void *, uint32_t);

static_assert(sizeof(Buffer) == 16 && sizeof(Slot) == 24 && sizeof(Ring) == 24, "Tahoe DMA layout");
static constexpr uint32_t TxCapacity = 16384;
static constexpr uint32_t MaximumFragments = 1024;
static Allocate allocateBuffer;
static PacketData packetData;
static PacketLength packetLength;
static PacketNext packetNext;
static PacketFree packetFree;
static Ring *rings;
static const uint32_t *ringCount;
static uintptr_t imageBase;
static bool installed;
static const char *status = "NotPrepared";
static struct {
    uint64_t txPackets;
    uint64_t txBytes;
    uint64_t txFailures;
    uint64_t rxBuffers;
    uint64_t rxCopies;
    uint64_t rxBytes;
    uint64_t rxBytesAvoided;
    uint64_t rxFailures;
    uint64_t rxFullCopies;
    uint64_t rxReclaims;
} counters;

template <typename T> T read(const void *base, uint32_t offset) {
    T value;
    memcpy(&value, static_cast<const uint8_t *>(base) + offset, sizeof(value));
    return value;
}

template <typename T> void write(void *base, uint32_t offset, T value) {
    memcpy(static_cast<uint8_t *>(base) + offset, &value, sizeof(value));
}

static void add(uint64_t &value, uint64_t amount = 1) {
    __atomic_fetch_add(&value, amount, __ATOMIC_RELAXED);
}

static bool validRing(uint32_t count, uint32_t index) {
    return count && !(count & (count - 1)) && index < count;
}

static Slot *findSlot(void *key, uint32_t index, uint32_t count, uint32_t capacity) {
    const auto total = *ringCount;
    if (total > 16)
        return nullptr;
    for (uint32_t i = 0; i < total; ++i) {
        auto &ring = rings[i];
        if (ring.key != key)
            continue;
        if (!ring.slots || ring.count != count || ring.capacity != capacity || index >= ring.count)
            return nullptr;
        auto &slot = ring.slots[index];
        return slot.bytes && slot.address && slot.mapping ? &slot : nullptr;
    }
    return nullptr;
}

static Buffer bufferFor(void *di, uint32_t field, uint32_t index, uint32_t count, uint32_t capacity) {
    if (!validRing(count, index) || !capacity || capacity > UINT16_MAX || *ringCount > 16 || !read<void *>(di, field))
        return {};
    auto key = static_cast<uint8_t *>(di) + field;
    for (uint32_t i = 0; i < *ringCount && i < 16; ++i)
        if (rings[i].key == key && (rings[i].count != count || rings[i].capacity != capacity))
            return {};
    const auto result = allocateBuffer(key, index, capacity, count, read<void *>(di, 0x30));
    auto slot = findSlot(key, index, count, capacity);
    return slot && result.bytes == slot->bytes && result.address == slot->address &&
        result.address <= UINT64_MAX - capacity ? result : Buffer {};
}

}

extern "C" bool bcmTahoeTxMap(void *di, void *packet, uint32_t index) {
    auto osh = read<void *>(di, 0x30);
    size_t total = 0;
    uint32_t fragments = 0;
    for (auto item = packet; item; item = packetNext(osh, item)) {
        const auto length = packetLength(osh, item);
        if (++fragments > MaximumFragments || length > TxCapacity - total || (length && !packetData(osh, item))) {
            add(counters.txFailures);
            return false;
        }
        total += length;
    }
    const auto count = read<uint16_t>(di, 0x6A);
    auto map = read<uint8_t *>(di, 0x80);
    if (!total || !map || !validRing(count, index)) {
        add(counters.txFailures);
        return false;
    }
    const auto buffer = bufferFor(di, 0x80, index, count, TxCapacity);
    if (!buffer.bytes) {
        add(counters.txFailures);
        return false;
    }
    size_t offset = 0;
    for (auto item = packet; item; item = packetNext(osh, item)) {
        const auto length = packetLength(osh, item);
        if (length)
            memcpy(buffer.bytes + offset, packetData(osh, item), length);
        offset += length;
    }
    map += index * 0x70;
    write<uint32_t>(map, 8, static_cast<uint32_t>(total));
    write<uint32_t>(map, 12, 1);
    write<uint64_t>(map, 16, buffer.address);
    write<uint32_t>(map, 24, static_cast<uint32_t>(total));
    add(counters.txPackets);
    add(counters.txBytes, total);
    return true;
}

extern "C" uint64_t bcmTahoeRxMap(void *di, void *packet, uint32_t index) {
    auto osh = read<void *>(di, 0x30);
    const auto size = read<uint16_t>(di, 0xE4);
    const auto count = read<uint16_t>(di, 0xA4);
    if (packet && size >= 2 && packetLength(osh, packet) >= size) {
        const auto buffer = bufferFor(di, 0xC0, index, count, size);
        if (buffer.bytes) {
            write<uint16_t>(buffer.bytes, 0, 0);
            add(counters.rxBuffers);
            return buffer.address;
        }
    }
    add(counters.rxFailures);
    if (packet)
        packetFree(osh, packet, 0);
    return 0;
}

extern "C" void *bcmTahoeRxCopy(void *di, void *packet, uint32_t index,
                                uintptr_t caller, uint32_t remaining) {
    if (!packet || reinterpret_cast<uintptr_t>(packet) == 0x80000000)
        return packet;
    if (caller == imageBase + dma::RxReclaimReturn) {
        add(counters.rxReclaims);
        return packet;
    }
    auto osh = read<void *>(di, 0x30);
    const auto capacity = read<uint16_t>(di, 0xE4);
    const auto count = read<uint16_t>(di, 0xA4);
    auto slot = validRing(count, index) ? findSlot(static_cast<uint8_t *>(di) + 0xC0, index, count, capacity) : nullptr;
    auto destination = packetData(osh, packet);
    const auto available = packetLength(osh, packet);
    if (!slot || capacity < 2 || !destination || available < capacity) {
        add(counters.rxFailures);
        packetFree(osh, packet, 0);
        return nullptr;
    }
    size_t length = capacity;
    const auto header = read<uint32_t>(di, 0xF0);
    const bool simple = !read<uint8_t>(di, 0x42) && !read<uint8_t>(di, 0x136);
    if (simple && header >= 2 && header <= capacity &&
        (caller == imageBase + dma::RxFirstReturn || caller == imageBase + dma::RxRetryReturn)) {
        const auto received = static_cast<size_t>(read<uint16_t>(slot->bytes, 0)) + header;
        length = received < capacity ? received : capacity;
    } else if (simple && caller == imageBase + dma::RxContinuationReturn && remaining) {
        length = remaining < capacity ? remaining : capacity;
    } else {
        add(counters.rxFullCopies);
    }
    memcpy(destination, slot->bytes, length);
    add(counters.rxCopies);
    add(counters.rxBytes, length);
    add(counters.rxBytesAvoided, capacity - length);
    return packet;
}

bool TahoeDMA::prepare(LinkedImage &image, bool enabled) {
    if (getKernelVersion() != 25) {
        status = "NotRequired";
        return true;
    }
    if (!enabled) {
        status = "Disabled";
        return true;
    }
    if (installed)
        return false;
    status = "ValidationFailed";
    if (!image.editable || image.registered || !image.payload || !image.memory ||
        image.address != reinterpret_cast<uintptr_t>(image.memory) || !image.payload->sha256 ||
        strcmp(image.payload->sha256, dma::SourceSHA256) ||
        image.payload->size < dma::RequiredSize || image.payload->size > image.payload->mappedSize ||
        image.payload->stubOffset < image.payload->size || image.payload->stubOffset > image.payload->mappedSize ||
        image.payload->stubSize > image.payload->mappedSize - image.payload->stubOffset ||
        image.address > UINTPTR_MAX - image.payload->mappedSize || image.stubUsed > image.payload->stubSize ||
        image.payload->stubSize - image.stubUsed < 48)
        return false;
    for (const auto &guard : dma::Guards) {
        if (guard.offset > image.payload->size || guard.length > image.payload->size - guard.offset)
            return false;
        for (uint32_t i = 0; i < guard.length; ++i)
            if ((image.memory[guard.offset + i] & guard.mask[i]) != (guard.bytes[i] & guard.mask[i]))
                return false;
    }
    for (const auto &guard : dma::Checksums)
        if (guard.offset > image.payload->size || guard.length > image.payload->size - guard.offset ||
            payloadChecksum(image.memory + guard.offset, guard.length) != guard.checksum)
            return false;
    if (read<uint32_t>(image.memory, dma::RingCount))
        return false;
    for (uint32_t i = 0; i < 16 * sizeof(Ring); ++i)
        if (image.memory[dma::Rings + i])
            return false;
    const uintptr_t targets[] = {reinterpret_cast<uintptr_t>(bcmTahoeTxEntry),
        reinterpret_cast<uintptr_t>(bcmTahoeRxFillEntry), reinterpret_cast<uintptr_t>(bcmTahoeRxCopyEntry)};
    int32_t branches[3];
    for (uint32_t i = 0; i < 3; ++i) {
        const auto stub = image.address + image.payload->stubOffset + image.stubUsed + i * 16;
        const auto delta = static_cast<int64_t>(stub - (image.address + dma::Patches[i].offset + 5));
        if (delta < INT32_MIN || delta > INT32_MAX)
            return false;
        branches[i] = static_cast<int32_t>(delta);
    }
    for (auto target : targets)
        if (!allocateStub(image, target))
            return false;
    imageBase = image.address;
    allocateBuffer = reinterpret_cast<Allocate>(image.address + dma::Allocate);
    packetData = reinterpret_cast<PacketData>(image.address + dma::PacketData);
    packetLength = reinterpret_cast<PacketLength>(image.address + dma::PacketLength);
    packetNext = reinterpret_cast<PacketNext>(image.address + dma::PacketNext);
    packetFree = reinterpret_cast<PacketFree>(image.address + dma::PacketFree);
    rings = reinterpret_cast<Ring *>(image.memory + dma::Rings);
    ringCount = reinterpret_cast<const uint32_t *>(image.memory + dma::RingCount);
    bcmTahoeTxResume = image.address + dma::TxResume;
    bcmTahoeTxFail = image.address + dma::TxFail;
    bcmTahoeRxFillResume = image.address + dma::RxFillResume;
    bcmTahoeRxFillFail = image.address + dma::RxFillFail;
    bcmTahoeRxCopyResume = image.address + dma::RxCopyResume;
    for (uint32_t i = 0; i < 3; ++i) {
        const auto &patch = dma::Patches[i];
        auto bytes = image.memory + patch.offset;
        memset(bytes, 0x90, patch.length);
        bytes[0] = 0xE9;
        memcpy(bytes + 1, &branches[i], sizeof(branches[i]));
    }
    installed = true;
    status = "MappedDMAOptimized";
    return true;
}

void TahoeDMA::publish(IOService *service) {
    service->setProperty("TahoeDMAStatus", status);
    if (!installed)
        return;
    service->setProperty("TahoeDMAAddressing", "IODMACommand");
    service->setProperty("TahoeDMATxCapacity", TxCapacity, 32);
    const struct { const char *name; const uint64_t *value; } properties[] = {
        {"TahoeDMATxPackets", &counters.txPackets}, {"TahoeDMATxBytes", &counters.txBytes},
        {"TahoeDMATxFailures", &counters.txFailures}, {"TahoeDMARxBuffers", &counters.rxBuffers},
        {"TahoeDMARxCopies", &counters.rxCopies}, {"TahoeDMARxBytes", &counters.rxBytes},
        {"TahoeDMARxBytesAvoided", &counters.rxBytesAvoided}, {"TahoeDMARxFailures", &counters.rxFailures},
        {"TahoeDMARxFullCopies", &counters.rxFullCopies}, {"TahoeDMARxReclaims", &counters.rxReclaims},
    };
    for (const auto &property : properties)
        service->setProperty(property.name, __atomic_load_n(property.value, __ATOMIC_RELAXED), 64);
}

}
