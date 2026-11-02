//
//  NativeProfile.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_NATIVE_PROFILE_HPP
#define SIMPLEBCM_NATIVE_PROFILE_HPP

#include <stdint.h>
#include <stddef.h>
#include "Payload.hpp"

namespace bcm {

enum class SkyAPI : uint32_t {
    EthernetConstructor, EthernetDestructor, EthernetInit, EthernetFree, EthernetTable, PacketTable, PoolTable,
    RegisterEthernet, RegisterEthernetLink, RegisterNetworkLink,
    DeregisterEthernet, TxWithPool, TxSubmission, TxRequest,
    TypedNew, TypedDelete, JoinPowerTree, Count
};

struct NativeClientProfile {
    uint32_t constructor;
    uint32_t destructor;
    uint32_t free;
    uint32_t meta;
    uint32_t vtable;
    uint32_t slots;
};

extern const NativeClientProfile nativeClientProfiles[2];

struct SkyEntry {
    uint32_t index;
    uint32_t source;
};

struct SkyMethod {
    uint32_t nativeIndex;
    uint32_t oldSlot;
};

struct SkyCallback {
    uint32_t nativeSlot;
    uint32_t method;
};

struct SkyClass {
    uint32_t image;
    uint32_t vtable;
    const SkyCallback *callbacks;
    uint32_t count;
};

struct NativeClassGuard {
    uint32_t meta;
    uint32_t size;
};

struct NativeCodeReference {
    uint32_t offset;
    uint32_t target;
};

struct NativeLinkPattern {
    const uint8_t *bytes;
    const uint8_t *mask;
    uint32_t size;
    const NativeCodeReference *references;
    uint32_t referenceCount;
};

struct NativeSystemProfile {
    uint32_t kernel;
    const char *name;
    uint32_t ethernetSize;
    uint32_t poolSize;
    uint32_t ethernetSlots;
    uint32_t airPortPayloadIndex;
    uint32_t ethernetLinkSlot;
    NativeLinkPattern ethernetLinkPattern;
    const NativeVtableGuard *vtableGuards;
    uint32_t vtableGuardCount;
    const NativeClassGuard *classGuards;
    uint32_t classGuardCount;
    const SkyClass *classes;
};

inline uintptr_t findNativeLink(const uint8_t *text, size_t size, uintptr_t address,
                               const NativeLinkPattern &pattern, const uintptr_t *imports, size_t importCount) {
    if (!text || !imports || !pattern.bytes || !pattern.mask || !pattern.size || pattern.size > size ||
        !pattern.references || !pattern.referenceCount)
        return 0;
    uintptr_t result = 0;
    for (size_t offset = 0; offset <= size - pattern.size; ++offset) {
        bool matches = true;
        for (size_t i = 0; i < pattern.size; ++i) {
            if ((text[offset + i] & pattern.mask[i]) != (pattern.bytes[i] & pattern.mask[i])) {
                matches = false;
                break;
            }
        }
        if (!matches)
            continue;
        for (uint32_t i = 0; i < pattern.referenceCount; ++i) {
            const auto &reference = pattern.references[i];
            if (reference.target >= importCount || reference.offset > pattern.size ||
                pattern.size - reference.offset < 4)
                return 0;
            const auto bytes = text + offset + reference.offset;
            const auto displacement = static_cast<int32_t>(uint32_t(bytes[0]) | uint32_t(bytes[1]) << 8 |
                uint32_t(bytes[2]) << 16 | uint32_t(bytes[3]) << 24);
            if (address + offset + reference.offset + 4 + displacement != imports[reference.target]) {
                matches = false;
                break;
            }
        }
        if (matches) {
            if (result)
                return 0;
            result = address + offset;
        }
    }
    return result;
}

extern const NativeSystemProfile nativeSystems[];
extern const uint32_t nativeSystemCount;
extern const NativeSystemProfile *nativeSystem;

inline const NativeSystemProfile *nativeSystemForKernel(uint32_t kernel) {
    for (uint32_t i = 0; i < nativeSystemCount; ++i)
        if (nativeSystems[i].kernel == kernel)
            return &nativeSystems[i];
    return nullptr;
}

struct SkyPatch {
    uint32_t offset;
    uint32_t before;
    uint32_t after;
};

extern const uint32_t skyAPIImports[];
extern const SkyEntry skyLegacyEntries[];
extern const uint32_t skyLegacySlotCount;
extern const SkyEntry skyPacketEntries[];
extern const uint32_t skyPacketSlotCount;
extern uint32_t skyNativeSlotCount;
extern const SkyMethod skyMethods[];
extern const uint32_t skyMethodCount;
extern const SkyClass *skyClasses;
extern const uint32_t skyClassCount;
extern const SkyPatch skyPacketCalls[];
extern const uint32_t skyPacketCallCount;
extern const uint32_t skyPacketVptrSites[];
extern const uint32_t skyPacketVptrSiteCount;
extern const uint32_t skyPoolTypeView;
extern const uint32_t skyPoolMetaSizeSites[];
extern const uint32_t skyPoolMetaSizeSiteCount;
extern const uint32_t skyPoolVtable;
extern const uint32_t skyPacketVtable;
extern const SkyEntry skyPacketSubclassEntries[];
extern const uint32_t skyPacketSubclassSlotCount;
extern "C" const uintptr_t bcmSkyForwarders[];
extern "C" const uintptr_t bcmSkyCallbacks[];
extern "C" const uintptr_t bcmCompatibilityImports[];
extern const uint32_t compatibilityImportCount;
extern const char *const compatibilityImportNames[];

}

#endif
