//
//  AWDLCoexistence.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/8.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "AWDLCoexistence.hpp"
#include "Patcher.hpp"

namespace bcm {
namespace {

using SelectChannels = void (*)(void *);
static SelectChannels originalSelectChannels;
static bool installed;
static const char *status = "NotPrepared";
static uint64_t selections;
static uint32_t lastChannel;

template <typename T> T read(const void *base, size_t offset) {
    T value;
    memcpy(&value, static_cast<const uint8_t *>(base) + offset, sizeof(value));
    return value;
}

template <typename T> void write(void *base, size_t offset, T value) {
    memcpy(static_cast<uint8_t *>(base) + offset, &value, sizeof(value));
}

static void selectChannels(void *manager) {
    const auto infra = read<uint32_t>(manager, 0x68);
    const auto secondary = read<uint32_t>(manager, 0xCF4);
    if (read<uint32_t>(manager, 0x496C) == 0 &&
        read<uint32_t>(manager, 0xCF0) == 6 &&
        read<uint32_t>(manager, 0xCF8) == 44 &&
        (secondary == 44 || secondary == 149) &&
        (infra == 44 || infra == 149) && secondary != infra) {
        write<uint32_t>(manager, 0xCF4, infra);
        write<uint8_t>(manager, 0x60, 0);
        __atomic_fetch_add(&selections, 1ULL, __ATOMIC_RELAXED);
        __atomic_store_n(&lastChannel, infra, __ATOMIC_RELAXED);
    }
    originalSelectChannels(manager);
}

}

bool AWDLCoexistence::prepare(LinkedImage &image, bool enabled) {
    if (getKernelVersion() != 25) {
        status = "NotApplicable";
        return true;
    }
    if (!enabled) {
        status = "Disabled";
        return true;
    }
    if (installed)
        return false;
    status = "ValidationFailed";
    constexpr uint32_t minimumInstruction = 0x16A8A;
    constexpr uint32_t selectInstruction = 0x200C2;
    constexpr uint8_t minimumBytes[] = {0xC7, 0x83, 0xEB, 0x0C, 0, 0, 3, 3, 3, 3};
    constexpr uint8_t selectBytes[] = {0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56,
                                      0x53, 0x50, 0x48, 0x89, 0xFB, 0x8A, 0x87, 0xF0,
                                      0x0C, 0, 0, 0x88, 0x87, 0xFE, 0x0C, 0, 0,
                                      0xC6, 0x87, 0xFF, 0x0C, 0, 0, 0};
    constexpr const char *symbol = "__ZN22IO80211AWDLPeerManager26selectChannelsToUseForAWDLEv";
    if (!image.editable || image.registered || !image.memory || !image.payload ||
        !image.payload->sha256 || image.address != reinterpret_cast<uintptr_t>(image.memory) ||
        strcmp(image.payload->sha256, "ac2dc15b77f8eaf97b71b34c5d0e1b59f862bfeac618396449306e1837e73894") ||
        image.payload->size < selectInstruction + sizeof(selectBytes) ||
        memcmp(image.memory + minimumInstruction, minimumBytes, sizeof(minimumBytes)) ||
        memcmp(image.memory + selectInstruction, selectBytes, sizeof(selectBytes)))
        return false;
    KernelPatcher patcher(image);
    if (patcher.solveSymbol(0, symbol) != image.address + selectInstruction)
        return false;
    KernelPatcher::RouteRequest routes[] = {{symbol, selectChannels, originalSelectChannels}};
    if (!patcher.routeMultipleLong(0, routes, image.address, image.payload->mappedSize))
        return false;
    image.memory[minimumInstruction + 9] = 0;
    installed = true;
    status = "Active";
    return true;
}

void AWDLCoexistence::publish(IOService *service) {
    service->setProperty("AWDLCoexistenceStatus", status);
    service->setProperty("AWDLCoexistenceSelections", __atomic_load_n(&selections, __ATOMIC_RELAXED), 64);
    service->setProperty("AWDLCoexistenceLastSelectedChannel", __atomic_load_n(&lastChannel, __ATOMIC_RELAXED), 32);
}

}
