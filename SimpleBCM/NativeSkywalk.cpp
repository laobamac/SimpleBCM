//
//  NativeSkywalk.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "NativeSkywalk.hpp"
#include "Patcher.hpp"
#include "WirelessABI.hpp"
#include <IOKit/IOEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOLocks.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSCollectionIterator.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/OSAtomic.h>
#include <sys/systm.h>
#include <mach-o/loader.h>

extern "C" OSObject *bcmLookupKext(const char *) asm("__ZN6OSKext24lookupKextWithIdentifierEPKc");
extern "C" const section_64 *bcmLookupSection(OSObject *, const char *, const char *) asm("__ZN6OSKext13lookupSectionEPKcS1_");
extern "C" bool bcmTryRetain(const OSObject *, const void *) asm("__ZNK8OSObject15taggedTryRetainEPKv");

namespace bcm { struct InterfaceContext; }

extern "C" const uint8_t bcmEthernetMetaClass[] asm("__ZN26IOSkywalkEthernetInterface10gMetaClassE");

class BCMNativeMeta final : public OSMetaClass {
public:
    BCMNativeMeta() : OSMetaClass("BCMNativeInterface", reinterpret_cast<const OSMetaClass *>(bcmEthernetMetaClass), 296) {}
    OSObject *alloc() const override { return nullptr; }
};

static BCMNativeMeta nativeMetaClass;

class BCMLegacyInterface : public IOService {
    OSDeclareDefaultStructors(BCMLegacyInterface)
public:
    bool init(OSDictionary *) override;
    bool start(IOService *) override;
    void stop(IOService *) override;
    void free() override;
    bcm::InterfaceContext *context() const { return bridgeContext; }
private:
    uint8_t storage[272 - sizeof(IOService) - sizeof(void *)] __attribute__((unused));
    bcm::InterfaceContext *bridgeContext {nullptr};
};

static_assert(sizeof(BCMLegacyInterface) == 272, "Legacy interface layout");

OSDefineMetaClassAndStructors(BCMLegacyInterface, IOService)

extern "C" void bcmNativeDestructor(IOService *);
extern "C" void bcmNativeDeletingDestructor(IOService *);
extern "C" const OSMetaClass *bcmNativeMetaClass(IOService *);
extern "C" void bcmNativeInterfaceFree(IOService *);
extern "C" void bcmNativeJoinPowerTree(IOService *, IOService *);
extern "C" uintptr_t bcmLegacySkywalkVtable[512];
extern "C" uintptr_t bcmPacketCompatibilityVtable[128];
uintptr_t bcmLegacySkywalkVtable[512] {};
uintptr_t bcmPacketCompatibilityVtable[128] {};

namespace bcm {

struct InterfaceContext {
    BCMLegacyInterface *owner;
    IOService *native;
    IOPCIDevice *powerProvider;
    OSArray *queues;
    IOSimpleLock *lock;
    int32_t references;
    bool activeOwner;
    bool registered;
    bool ownsNative;
    bool counted;
    bool attached;
    bool started;
};

static uintptr_t nativeViews[3][512];
const NativeSystemProfile *nativeSystem;
const SkyClass *skyClasses;
uint32_t skyNativeSlotCount;
static uintptr_t packetView[128];
static uintptr_t oldViews[3];
static uintptr_t poolAllocationView;
static LinkedImage *activeImages;
static bool nativePrepared;
static bool nativeABIValidated;
static uintptr_t ethernetLink;
static uint32_t liveInterfaces;
static uint32_t powerJoins;
static const char *nativeStatus = "NotPrepared";

static InterfaceContext *nativeContext(IOService *service) {
    InterfaceContext *context;
    memcpy(&context, reinterpret_cast<const uint8_t *>(service) + 288, sizeof(context));
    return context;
}

static void setNativeContext(IOService *service, InterfaceContext *context) {
    memcpy(reinterpret_cast<uint8_t *>(service) + 288, &context, sizeof(context));
}

template<typename Function> static Function api(SkyAPI index) {
    auto address = bcmNativeImports[skyAPIImports[static_cast<uint32_t>(index)]];
    if (index == SkyAPI::RegisterEthernetLink)
        address = ethernetLink;
    return reinterpret_cast<Function>(address);
}

static uintptr_t entry(const SkyEntry &item) {
    switch (item.source) {
        case 0: return item.index < nativeImportCount ? bcmNativeImports[item.index] : 0;
        case 1: return item.index < compatibilityImportCount ? bcmCompatibilityImports[item.index] : 0;
        case 2: return item.index < skyMethodCount ? bcmSkyForwarders[item.index] : 0;
        case 3: return api<const uintptr_t *>(SkyAPI::PacketTable)[item.index + 2];
        case 4: return activeImages[1].address + item.index;
        case 5: return activeImages[0].address + item.index;
        default: return 0;
    }
}

static void releaseContext(InterfaceContext *context) {
    if (OSDecrementAtomic(&context->references) == 1) {
        if (context->queues)
            context->queues->release();
        if (context->powerProvider)
            context->powerProvider->release();
        IOSimpleLockFree(context->lock);
        IOFree(context, sizeof(*context));
    }
}

static InterfaceContext *contextFor(IOService *service) {
    auto context = static_cast<BCMLegacyInterface *>(service)->context();
    if (!context || !context->native)
        panic("SimpleBCM: native interface is unavailable");
    return context;
}

static void copyProperties(InterfaceContext *context) {
    auto properties = context->owner->dictionaryWithProperties();
    if (!properties)
        return;
    auto iterator = OSCollectionIterator::withCollection(properties);
    if (iterator) {
        while (auto key = OSDynamicCast(OSString, iterator->getNextObject())) {
            auto name = key->getCStringNoCopy();
            if (!strcmp(name, "IOClass") || !strcmp(name, "CFBundleIdentifier") ||
                !strcmp(name, "CFBundleIdentifierKernel") || !strcmp(name, "IOProviderClass") ||
                !strcmp(name, "IOMatchCategory") || !strcmp(name, "IOPowerManagement"))
                continue;
            context->native->setProperty(name, properties->getObject(name));
        }
        iterator->release();
    }
    for (IOService *parent = context->owner->getProvider(); parent; parent = parent->getProvider()) {
        if (parent->metaCast("AirPort_BrcmNIC")) {
            auto cc = OSDynamicCast(OSString, parent->getProperty("IO80211CountryCode"));
            if (cc) {
                context->owner->setProperty("IO80211CountryCode", cc);
                context->native->setProperty("IO80211CountryCode", cc);
                uint32_t loc = bcm::localeForCountryCode(cc->getCStringNoCopy());
                if (loc != bcm::LocaleUnknown) {
                    context->owner->setProperty("IO80211Locale", bcm::localeString(loc));
                    context->native->setProperty("IO80211Locale", bcm::localeString(loc));
                }
            }
            auto locProp = OSDynamicCast(OSString, parent->getProperty("IO80211Locale"));
            if (locProp) {
                context->owner->setProperty("IO80211Locale", locProp);
                context->native->setProperty("IO80211Locale", locProp);
            }
            break;
        }
    }
    properties->release();
}

bool validateNativeSkywalk() {
    if (nativeABIValidated)
        return true;
    if (!nativeSystem) {
        nativeSystem = nativeSystemForKernel(static_cast<uint32_t>(getKernelVersion()));
        if (!nativeSystem) {
            nativeStatus = "UnsupportedKernel";
            return false;
        }
        skyClasses = nativeSystem->classes;
        skyNativeSlotCount = nativeSystem->ethernetSlots;
    }
    if (skyClassCount != 3 || skyLegacySlotCount + 2 > 512 ||
        skyNativeSlotCount + 2 > 512 || skyPacketSlotCount + 2 > 128 ||
        skyPacketSubclassSlotCount + 2 > 128)
        return false;
    for (uint32_t i = 0; i < nativeSystem->classGuardCount; ++i) {
        const auto &guard = nativeSystem->classGuards[i];
        if (guard.meta >= nativeImportCount ||
            reinterpret_cast<const OSMetaClass *>(bcmNativeImports[guard.meta])->getClassSize() != guard.size) {
            nativeStatus = "NativeClassLayoutMismatch";
            return false;
        }
    }
    for (uint32_t i = 0; i < nativeSystem->vtableGuardCount; ++i) {
        const auto &guard = nativeSystem->vtableGuards[i];
        if (guard.parent >= nativeImportCount || guard.method >= nativeImportCount ||
            *reinterpret_cast<const uintptr_t *>(bcmNativeImports[guard.parent] + guard.offset) != bcmNativeImports[guard.method]) {
            nativeStatus = "NativeMethodLayoutMismatch";
            return false;
        }
    }
    auto module = bcmLookupKext("com.apple.iokit.IOSkywalkFamily");
    if (!module) {
        nativeStatus = "NativeSkywalkMissing";
        return false;
    }
    auto section = bcmLookupSection(module, "__TEXT_EXEC", "__text");
    if (!section)
        section = bcmLookupSection(module, "__TEXT", "__text");
    if (section && section->addr && section->size <= 32 * 1024 * 1024 &&
        section->addr <= UINTPTR_MAX - section->size) {
        if (nativeSystem->ethernetLinkSlot < skyNativeSlotCount) {
            ethernetLink = api<const uintptr_t *>(SkyAPI::EthernetTable)[2 + nativeSystem->ethernetLinkSlot];
            if (ethernetLink < section->addr || ethernetLink >= section->addr + section->size)
                ethernetLink = 0;
        } else {
            ethernetLink = findNativeLink(reinterpret_cast<const uint8_t *>(section->addr), section->size,
                section->addr, nativeSystem->ethernetLinkPattern, bcmNativeImports, nativeImportCount);
        }
    }
    module->release();
    const bool valid = ethernetLink != 0;
    if (valid) {
        auto name = OSSymbol::withCString("AirPortDriver");
        if (!name) {
            nativeStatus = "ControllerIdentityAllocationFailed";
            return false;
        }
        const auto existing = OSMetaClass::getMetaClassWithName(name);
        name->release();
        if (existing) {
            nativeStatus = "ControllerIdentityAlreadyRegistered";
            return false;
        }
    }
    nativeABIValidated = valid;
    nativeStatus = valid ? "NativeABIVerified" : "NativeLinkEntryNotFound";
    return valid;
}

bool prepareNativeSkywalk(LinkedImage *images, size_t count) {
    if (count != 2 || !images[0].editable || !images[1].editable || !validateNativeSkywalk())
        return false;
    activeImages = images;
    for (uint32_t i = 0; i < skyLegacySlotCount; ++i) {
        auto value = entry(skyLegacyEntries[i]);
        if (!value)
            return false;
        bcmLegacySkywalkVtable[i + 2] = value;
    }
    for (uint32_t i = 0; i < skyPacketSlotCount; ++i) {
        auto value = entry(skyPacketEntries[i]);
        if (!value)
            return false;
        bcmPacketCompatibilityVtable[i + 2] = value;
    }
    auto native = api<const uintptr_t *>(SkyAPI::EthernetTable);
    for (uint32_t type = 0; type < skyClassCount; ++type) {
        const auto &source = skyClasses[type];
        if (source.image >= count || source.vtable >= images[source.image].payload->size)
            return false;
        oldViews[type] = images[source.image].address + source.vtable + 16;
        memcpy(nativeViews[type], native, (skyNativeSlotCount + 2) * sizeof(uintptr_t));
        nativeViews[type][2] = reinterpret_cast<uintptr_t>(bcmNativeDestructor);
        nativeViews[type][3] = reinterpret_cast<uintptr_t>(bcmNativeDeletingDestructor);
        nativeViews[type][2 + 0x38 / 8] = reinterpret_cast<uintptr_t>(bcmNativeMetaClass);
        nativeViews[type][2 + 0x90 / 8] = reinterpret_cast<uintptr_t>(bcmNativeInterfaceFree);
        nativeViews[type][2 + 0x7a0 / 8] = reinterpret_cast<uintptr_t>(bcmNativeJoinPowerTree);
        for (uint32_t i = 0; i < source.count; ++i) {
            const auto &callback = source.callbacks[i];
            if (callback.nativeSlot >= skyNativeSlotCount || callback.method >= skyMethodCount)
                return false;
            nativeViews[type][callback.nativeSlot + 2] = bcmSkyCallbacks[callback.method];
        }
    }
    for (uint32_t i = 0; i < skyPacketSubclassSlotCount; ++i) {
        auto value = entry(skyPacketSubclassEntries[i]);
        if (!value)
            return false;
        packetView[i + 2] = value;
    }
    auto &air = images[1];
    if (skyPoolTypeView + 64 > air.payload->size ||
        skyPoolVtable + (2 + 52) * 8 > air.payload->size)
        return false;
    poolAllocationView = air.address + skyPoolTypeView;
    uint32_t newSize = nativeSystem->poolSize;
    for (uint32_t i = 0; i < skyPoolMetaSizeSiteCount; ++i) {
        auto offset = skyPoolMetaSizeSites[i];
        if (offset + 4 > air.payload->size)
            return false;
        uint32_t oldSize;
        memcpy(&oldSize, air.memory + offset, sizeof(oldSize));
        if (oldSize != 184)
            return false;
        memcpy(air.memory + offset, &newSize, sizeof(newSize));
    }
    auto poolTable = reinterpret_cast<uintptr_t *>(air.memory + skyPoolVtable) + 2;
    auto nativePoolTable = api<const uintptr_t *>(SkyAPI::PoolTable) + 2;
    poolTable[0x28 / 8] = nativePoolTable[0x28 / 8];
    poolTable[0x50 / 8] = nativePoolTable[0x50 / 8];
    for (uint32_t i = 0; i < skyPacketCallCount; ++i) {
        const auto &patch = skyPacketCalls[i];
        uint32_t value;
        if (patch.offset + 4 > air.payload->size)
            return false;
        memcpy(&value, air.memory + patch.offset, 4);
        if (value != patch.before)
            return false;
        memcpy(air.memory + patch.offset, &patch.after, 4);
    }
    for (uint32_t i = 0; i < skyPacketVptrSiteCount; ++i) {
        auto offset = skyPacketVptrSites[i];
        if (offset + 7 > air.payload->size || air.memory[offset] != 0x48 ||
            air.memory[offset + 1] != 0x8d || air.memory[offset + 2] != 0x05)
            return false;
        int32_t displacement;
        memcpy(&displacement, air.memory + offset + 3, 4);
        if (air.address + offset + 7 + displacement != air.address + skyPacketVtable + 16)
            return false;
        if (air.stubUsed + 16 > air.payload->stubSize)
            return false;
        auto literal = air.payload->stubOffset + air.stubUsed;
        air.stubUsed += 16;
        auto address = reinterpret_cast<uintptr_t>(packetView + 2);
        memcpy(air.memory + literal, &address, 8);
        auto delta = static_cast<int64_t>(literal) - offset - 7;
        if (delta < INT32_MIN || delta > INT32_MAX)
            return false;
        displacement = static_cast<int32_t>(delta);
        air.memory[offset + 1] = 0x8b;
        memcpy(air.memory + offset + 3, &displacement, 4);
    }
    nativePrepared = true;
    nativeStatus = "NativeAdapterPrepared";
    return true;
}

void publishNativeSkywalk(IOService *service) {
    service->setProperty("SkywalkBackend", "Native");
    service->setProperty("NativeSkywalkStatus", nativeStatus);
    service->setProperty("NativeSkywalkPrepared", nativePrepared);
    service->setProperty("NativeSkywalkInterfaces", liveInterfaces, 32);
    service->setProperty("EmbeddedSkywalk", false);
    service->setProperty("NativePowerTopology", "PCIProvider");
    service->setProperty("NativePowerJoins", __atomic_load_n(&powerJoins, __ATOMIC_RELAXED), 32);
    if (nativeSystem) {
        service->setProperty("NativeSystemProfile", nativeSystem->name);
        service->setProperty("NativeABIValidated", nativeABIValidated);
        service->setProperty("NativeEthernetSize", nativeSystem->ethernetSize, 32);
        service->setProperty("NativePoolSize", nativeSystem->poolSize, 32);
    }
}

IOReturn nativeSkywalkUserClient(IOService *self, task_t task, void *token, uint32_t type,
                                OSDictionary *properties, IOUserClient **result) {
    auto context = contextFor(self);
    using Method = IOReturn (*)(IOService *, task_t, void *, uint32_t, OSDictionary *, IOUserClient **);
    auto method = reinterpret_cast<Method>(api<const uintptr_t *>(SkyAPI::EthernetTable)[2 + 0x770 / 8]);
    return method(context->native, task, token, type, properties, result);
}

struct ForwardTarget {
    uintptr_t function;
    IOService *receiver;
};

extern "C" ForwardTarget bcmResolveOldSkywalk(IOService *self, uint32_t index) {
    if (index >= skyMethodCount)
        panic("SimpleBCM: invalid native method");
    auto context = contextFor(self);
    auto target = skyMethods[index].nativeIndex;
    if (target >= nativeImportCount)
        panic("SimpleBCM: unresolved native method");
    return {bcmNativeImports[target], context->native};
}

extern "C" ForwardTarget bcmResolveNativeSkywalk(IOService *self, uint32_t index) {
    auto context = nativeContext(self);
    if (index >= skyMethodCount || !context)
        panic("SimpleBCM: invalid legacy callback");
    auto slot = skyMethods[index].oldSlot;
    if (slot >= skyLegacySlotCount)
        panic("SimpleBCM: invalid legacy callback slot");
    IOSimpleLockLock(context->lock);
    auto owner = context->activeOwner ? context->owner : nullptr;
    if (owner && !bcmTryRetain(owner, nullptr))
        owner = nullptr;
    IOSimpleLockUnlock(context->lock);
    if (!owner) {
        auto target = skyMethods[index].nativeIndex;
        if (target >= nativeImportCount)
            panic("SimpleBCM: invalid native callback fallback");
        return {bcmNativeImports[target], self};
    }
    auto vtable = *reinterpret_cast<uintptr_t **>(owner);
    return {vtable[slot], reinterpret_cast<IOService *>(reinterpret_cast<uintptr_t>(owner) | 1)};
}

extern "C" void bcmReleaseNativeReceiver(uintptr_t receiver) {
    if (receiver & 1)
        reinterpret_cast<IOService *>(receiver & ~uintptr_t(1))->release();
}

extern "C" bool bcmLegacySkywalkInit(IOService *self, OSDictionary *dictionary) {
    return static_cast<BCMLegacyInterface *>(self)->BCMLegacyInterface::init(dictionary);
}

extern "C" bool bcmLegacySkywalkStart(IOService *self, IOService *provider) {
    return static_cast<BCMLegacyInterface *>(self)->BCMLegacyInterface::start(provider);
}

extern "C" void bcmLegacySkywalkStop(IOService *self, IOService *provider) {
    static_cast<BCMLegacyInterface *>(self)->BCMLegacyInterface::stop(provider);
}

extern "C" bool bcmLegacyWillTerminate(IOService *self, IOService *provider, uint32_t options) {
    return self->IOService::willTerminate(provider, options);
}

extern "C" bool bcmLegacyDidTerminate(IOService *self, IOService *provider, uint32_t options, bool *defer) {
    return self->IOService::didTerminate(provider, options, defer);
}

extern "C" void bcmLegacySkywalkFree(IOService *self __attribute__((os_consumed))) {
    static_cast<BCMLegacyInterface *>(self)->BCMLegacyInterface::free();
}

extern "C" IOReturn bcmLegacySkywalkUserClient(IOService *self, task_t task, void *token,
                                              uint32_t type, OSDictionary *properties,
                                              IOUserClient **result) {
    return createSkywalkUserClient(self, task, token, type, properties, result);
}

extern "C" IOReturn bcmRegisterLegacyEthernet(IOService *self, const void *info,
                                             OSObject **queues, uint32_t count,
                                             OSObject *txPool, OSObject *rxPool,
                                             uint32_t options) {
    if (!queues || !count || count > 1024)
        return kIOReturnBadArgument;
    auto context = contextFor(self);
    auto saved = OSArray::withCapacity(count);
    if (!saved)
        return kIOReturnNoMemory;
    for (uint32_t i = 0; i < count; ++i) {
        if (!queues[i] || !saved->setObject(queues[i])) {
            saved->release();
            return kIOReturnBadArgument;
        }
    }
    copyProperties(context);
    using Method = IOReturn (*)(IOService *, const void *, OSObject **, uint32_t,
                               OSObject *, OSObject *, uint32_t);
    auto result = api<Method>(SkyAPI::RegisterEthernet)(context->native, info, queues, count,
                                                      txPool, rxPool, options);
    if (result == kIOReturnSuccess) {
        if (context->queues)
            context->queues->release();
        context->queues = saved;
        context->registered = true;
        context->native->registerService();
    } else {
        saved->release();
    }
    return result;
}

static IOReturn registerLink(IOService *self, const void *info, OSObject *link,
                             OSObject *txPool, OSObject *rxPool, uint32_t options, SkyAPI entry) {
    auto context = contextFor(self);
    copyProperties(context);
    using Method = IOReturn (*)(IOService *, const void *, OSObject *, OSObject *, OSObject *, uint32_t);
    auto result = api<Method>(entry)(context->native, info, link, txPool, rxPool, options);
    if (result == kIOReturnSuccess) {
        context->registered = true;
        context->native->registerService();
    }
    return result;
}

extern "C" IOReturn bcmRegisterLegacyEthernetLink(IOService *self, const void *info, OSObject *link,
                                                 OSObject *txPool, OSObject *rxPool, uint32_t options) {
    return registerLink(self, info, link, txPool, rxPool, options, SkyAPI::RegisterEthernetLink);
}

extern "C" IOReturn bcmRegisterLegacyNetworkLink(IOService *self, const void *info, OSObject *link,
                                                OSObject *txPool, OSObject *rxPool, uint32_t options) {
    return registerLink(self, info, link, txPool, rxPool, options, SkyAPI::RegisterNetworkLink);
}

extern "C" IOReturn bcmDeregisterLegacyEthernet(IOService *self, uint32_t options) {
    auto context = contextFor(self);
    using Method = IOReturn (*)(IOService *, uint32_t);
    auto result = api<Method>(SkyAPI::DeregisterEthernet)(context->native, options);
    if (result == kIOReturnSuccess)
        context->registered = false;
    return result;
}

static void deactivateInterface(InterfaceContext *context) {
    if (!context || !context->native || !context->ownsNative)
        return;
    auto peer = context->native;
    auto provider = peer->getProvider();
    if (context->registered) {
        using Deregister = IOReturn (*)(IOService *, uint32_t);
        api<Deregister>(SkyAPI::DeregisterEthernet)(peer, 0);
        context->registered = false;
    }
    if (context->started)
        peer->stop(provider);
    if (context->attached)
        peer->detach(provider);
    context->started = false;
    context->attached = false;
    IOSimpleLockLock(context->lock);
    context->activeOwner = false;
    IOSimpleLockUnlock(context->lock);
}

static void joinPowerTree(InterfaceContext *context, IOService *child) {
    if (child && child->metaCast("IOSkywalkNetworkBSDClient")) {
        auto provider = context->powerProvider;
        if (!provider) {
            nativeStatus = "NativePowerProviderMissing";
            return;
        }
        child->setProperty("SimpleBCMPowerParent", provider->getName());
        child->setProperty("SimpleBCMPowerParentID", provider->getRegistryEntryID(), 64);
        provider->joinPMtree(child);
        __atomic_fetch_add(&powerJoins, 1U, __ATOMIC_RELAXED);
        return;
    }
    using Method = void (*)(IOService *, IOService *);
    api<Method>(SkyAPI::JoinPowerTree)(context->native, child);
}

extern "C" void bcmLegacyJoinPowerTree(IOService *self, IOService *child) {
    joinPowerTree(contextFor(self), child);
}

extern "C" void bcmNativeJoinPowerTree(IOService *self, IOService *child) {
    joinPowerTree(nativeContext(self), child);
}

extern "C" IOReturn bcmLegacyDoorbell(IOService *self, OSObject *, uint32_t options) {
    auto context = contextFor(self);
    if (!context->queues)
        return kIOReturnNotReady;
    IOReturn result = kIOReturnSuccess;
    for (uint32_t i = 0; i < context->queues->getCount(); ++i) {
        auto queue = context->queues->getObject(i);
        IOReturn status = kIOReturnUnsupported;
        if (queue->metaCast("IOSkywalkTxSubmissionQueue")) {
            if (options & 1) {
                using Method = IOReturn (*)(OSObject *, void *, uint32_t);
                status = api<Method>(SkyAPI::TxRequest)(queue, nullptr, 1);
            } else {
                using Method = IOReturn (*)(OSObject *, bool);
                status = api<Method>(SkyAPI::TxSubmission)(queue, true);
            }
        }
        if (status != kIOReturnSuccess)
            result = status;
    }
    return result;
}

using TxFree = uint32_t (*)(OSObject *, OSObject *, uint32_t *);
using TxAction = uint32_t (*)(OSObject *, OSObject *, OSObject *const *, uint32_t, void *);

extern "C" OSObject *bcmLegacyTxWithPool(OSObject *pool, uint32_t capacity, uint32_t serviceClass,
                                        OSObject *owner, TxFree freeSlots, TxAction action,
                                        void *reference, uint32_t options) {
    using Method = OSObject *(*)(OSObject *, uint32_t, uint32_t, OSObject *, TxFree,
                                TxAction, void *, uint32_t, uint32_t);
    return api<Method>(SkyAPI::TxWithPool)(pool, capacity, serviceClass, owner, freeSlots,
                                         action, reference, options, UINT32_MAX);
}

extern "C" void *bcmLegacyTypedNew(void *view, size_t size) {
    if (reinterpret_cast<uintptr_t>(view) == poolAllocationView) {
        if (size != 184 && size != 192)
            panic("SimpleBCM: unexpected legacy packet pool allocation");
        auto memory = IOMalloc(nativeSystem->poolSize);
        if (memory)
            bzero(memory, nativeSystem->poolSize);
        return memory;
    }
    using Method = void *(*)(void *, size_t);
    return api<Method>(SkyAPI::TypedNew)(view, size);
}

extern "C" void bcmLegacyTypedDelete(void *view, void *memory, size_t size) {
    if (reinterpret_cast<uintptr_t>(view) == poolAllocationView) {
        if (size != 184 && size != 192)
            panic("SimpleBCM: unexpected legacy packet pool deallocation");
        if (memory)
            IOFree(memory, nativeSystem->poolSize);
        return;
    }
    using Method = void (*)(void *, void *, size_t);
    api<Method>(SkyAPI::TypedDelete)(view, memory, size);
}

extern "C" void bcmLegacyPoolRelease(const OSObject *self) {
    using Method = void (*)(const OSObject *);
    auto table = api<const uintptr_t *>(SkyAPI::PoolTable);
    reinterpret_cast<Method>(table[2 + 0x28 / 8])(self);
}

}

bool BCMLegacyInterface::init(OSDictionary *dictionary) {
    if (!bcm::nativePrepared || !IOService::init(dictionary))
        return false;
    if (bridgeContext)
        return true;
    uintptr_t *view = nullptr;
    const auto current = *reinterpret_cast<uintptr_t *>(this);
    for (uint32_t i = 0; i < bcm::skyClassCount; ++i)
        if (current == bcm::oldViews[i])
            view = bcm::nativeViews[i] + 2;
    if (!view)
        return false;
    auto context = static_cast<bcm::InterfaceContext *>(IOMalloc(sizeof(bcm::InterfaceContext)));
    if (!context)
        return false;
    bzero(context, sizeof(*context));
    context->lock = IOSimpleLockAlloc();
    if (!context->lock) {
        IOFree(context, sizeof(*context));
        return false;
    }
    auto peer = static_cast<IOService *>(IOMalloc(296));
    if (!peer) {
        IOSimpleLockFree(context->lock);
        IOFree(context, sizeof(*context));
        return false;
    }
    context->owner = this;
    context->native = peer;
    context->ownsNative = true;
    context->references = 2;
    bzero(static_cast<void *>(peer), 296);
    using Constructor = void (*)(IOService *, const OSMetaClass *);
    bcm::api<Constructor>(bcm::SkyAPI::EthernetConstructor)(peer, &nativeMetaClass);
    bcm::setNativeContext(peer, context);
    bridgeContext = context;
    *reinterpret_cast<uintptr_t **>(peer) = view;
    nativeMetaClass.instanceConstructed();
    using Method = bool (*)(IOService *, OSDictionary *);
    if (!bcm::api<Method>(bcm::SkyAPI::EthernetInit)(peer, dictionary)) {
        peer->release();
        bridgeContext = nullptr;
        bcm::releaseContext(context);
        return false;
    }
    context->counted = true;
    OSIncrementAtomic(reinterpret_cast<volatile SInt32 *>(&bcm::liveInterfaces));
    return true;
}

bool BCMLegacyInterface::start(IOService *provider) {
    if (!bridgeContext || !bridgeContext->native || !IOService::start(provider))
        return false;
    auto context = bridgeContext;
    auto powerProvider = provider ? OSDynamicCast(IOPCIDevice, provider->getProvider()) : nullptr;
    if (!powerProvider) {
        bcm::nativeStatus = "UnsupportedPowerProvider";
        return false;
    }
    if (context->powerProvider != powerProvider) {
        powerProvider->retain();
        if (context->powerProvider)
            context->powerProvider->release();
        context->powerProvider = powerProvider;
    }
    auto peer = context->native;
    bcm::copyProperties(context);
    if (!peer->attach(provider))
        return false;
    context->attached = true;
    if (!peer->start(provider)) {
        peer->detach(provider);
        context->attached = false;
        return false;
    }
    IOSimpleLockLock(context->lock);
    context->activeOwner = true;
    IOSimpleLockUnlock(context->lock);
    context->started = true;
    return true;
}

void BCMLegacyInterface::stop(IOService *provider) {
    bcm::deactivateInterface(bridgeContext);
    IOService::stop(provider);
}

void BCMLegacyInterface::free() {
    auto context = bridgeContext;
    bridgeContext = nullptr;
    if (context) {
        IOSimpleLockLock(context->lock);
        context->owner = nullptr;
        context->activeOwner = false;
        IOSimpleLockUnlock(context->lock);
        bcm::deactivateInterface(context);
        if (context->native && context->ownsNative) {
            auto peer = context->native;
            context->ownsNative = false;
            peer->release();
        }
        bcm::releaseContext(context);
    }
    IOService::free();
}

extern "C" void bcmNativeDestructor(IOService *self) {
    using Method = void (*)(IOService *);
    bcm::api<Method>(bcm::SkyAPI::EthernetDestructor)(self);
}

extern "C" void bcmNativeDeletingDestructor(IOService *self) {
    bcmNativeDestructor(self);
    IOFree(self, 296);
}

extern "C" const OSMetaClass *bcmNativeMetaClass(IOService *) {
    return &nativeMetaClass;
}

extern "C" void bcmNativeInterfaceFree(IOService *self) {
    auto saved = bcm::nativeContext(self);
    using Method = void (*)(IOService *);
    bcm::api<Method>(bcm::SkyAPI::EthernetFree)(self);
    if (saved) {
        if (saved->native == self)
            saved->native = nullptr;
        if (saved->counted)
            OSDecrementAtomic(reinterpret_cast<volatile SInt32 *>(&bcm::liveInterfaces));
        bcm::releaseContext(saved);
    }
}
