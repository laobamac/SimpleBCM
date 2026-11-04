//
//  PCIRecovery.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/5.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "PCIRecovery.hpp"
#include "Patcher.hpp"
#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSNumber.h>

namespace bcm {

static constexpr const char *SnapshotKey = "SimpleBCMPCIConfiguration";
static constexpr const char *ResultKey = "PCIRecoveryState";
static constexpr const char *AttemptsKey = "PCIRecoveryAttempts";
using StartGated = bool (*)(IOService *, IOService *);
using VerifyD3 = int (*)(void *);
using SyncPower = IOReturn (*)(IOService *, unsigned long, int);
static StartGated originalStart;
static VerifyD3 originalVerify;
static SyncPower originalSyncPower;

struct PCIBus {
    IOPCIDevice *device;
    bool singleFunction;
    uint32_t read32(unsigned offset) { return device->isInactive() ? UINT32_MAX : device->configRead32(offset); }
    uint16_t read16(unsigned offset) { return device->isInactive() ? UINT16_MAX : device->configRead16(offset); }
    void write32(unsigned offset, uint32_t value) {
        if (!device->isInactive())
            device->configWrite32(offset, value);
    }
    void write16(unsigned offset, uint16_t value) {
        if (!device->isInactive())
            device->configWrite16(offset, value);
    }
    void write8(unsigned offset, uint8_t value) {
        if (device->isInactive())
            return;
        const unsigned aligned = offset & ~1U;
        const unsigned shift = (offset & 1) * 8;
        const auto current = device->configRead16(aligned);
        device->configWrite16(aligned, static_cast<uint16_t>((current & ~(0xffU << shift)) | (value << shift)));
    }
    void wait(unsigned milliseconds) { IOSleep(milliseconds); }
    bool reset() {
        if (!singleFunction || device->isInactive())
            return false;
        const auto plane = IORegistryEntry::getPlane("IODeviceTree");
        if (!plane)
            return false;
        auto parent = OSDynamicCast(IOPCIDevice, device->getParentEntry(plane));
        if (!parent || parent->isInactive())
            return false;
        parent->retain();
        auto children = parent->getChildIterator(plane);
        unsigned count = 0;
        bool isolated = children != nullptr;
        if (children) {
            while (auto child = children->getNextObject()) {
                ++count;
                isolated &= child == device;
            }
            isolated &= children->isValid();
            children->release();
        }
        isolated &= count == 1 && (parent->configRead32(8) >> 16) == 0x0604 &&
                    (parent->configRead16(0x0e) & 0x7f) == 1;
        uint8_t pmOffset = 0;
        if (parent->findPCICapability(1, &pmOffset))
            isolated &= (parent->configRead16(pmOffset + 4) & 3) == 0;
        const auto control = parent->configRead16(0x3e);
        if (isolated && control != UINT16_MAX && !(control & 0x40)) {
            parent->configWrite16(0x3e, (control & ~0x400U) | 0x40);
            IODelay(10000);
            parent->configWrite16(0x3e, control & ~0x400U);
            IOSleep(20);
        } else {
            isolated = false;
        }
        parent->release();
        return isolated;
    }
};

static uint32_t attempts(IOService *controller) {
    auto value = controller->copyProperty(AttemptsKey);
    auto number = OSDynamicCast(OSNumber, value);
    const auto result = number ? number->unsigned32BitValue() : 0;
    if (value)
        value->release();
    return result;
}

static void captureConfiguration(IOService *controller, bool initial) {
    auto device = OSDynamicCast(IOPCIDevice, controller->getProvider());
    if (!device || device->isInactive())
        return;
    PCIConfiguration snapshot {};
    snapshot.registryID = device->getRegistryEntryID();
    for (unsigned i = 0; i < 64; ++i)
        snapshot.words[i] = device->configRead32(i * 4);
    if (!snapshot.valid()) {
        if (initial)
            controller->setProperty(ResultKey, "SnapshotUnavailable");
        return;
    }
    if (!initial) {
        auto previous = controller->copyProperty(SnapshotKey);
        auto data = OSDynamicCast(OSData, previous);
        PCIConfiguration saved {};
        if (data && data->getLength() == sizeof(saved))
            memcpy(&saved, data->getBytesNoCopy(), sizeof(saved));
        if (previous)
            previous->release();
        PCIBus bus {device, false};
        if (!saved.valid() || saved.registryID != snapshot.registryID || !pciConfigurationMatches(bus, saved))
            return;
    }
    auto data = OSData::withBytes(&snapshot, sizeof(snapshot));
    if (data) {
        if (controller->setProperty(SnapshotKey, data) && initial)
            controller->setProperty(ResultKey, "Armed");
        data->release();
    }
}

static bool startGated(IOService *controller, IOService *provider) {
    const auto result = originalStart(controller, provider);
    if (result)
        captureConfiguration(controller, true);
    return result;
}

static IOReturn syncPower(IOService *controller, unsigned long ordinal, int callback) {
    auto loop = controller->getWorkLoop();
    if (callback == 2 && ordinal < 2 && !controller->isInactive() && loop && loop->inGate())
        captureConfiguration(controller, false);
    return originalSyncPower(controller, ordinal, callback);
}

static int verifyD3(void *wlc) {
    IOService *controller = nullptr;
    memcpy(&controller, static_cast<const uint8_t *>(wlc) + 0x10, sizeof(controller));
    auto loop = controller ? controller->getWorkLoop() : nullptr;
    auto device = controller ? OSDynamicCast(IOPCIDevice, controller->getProvider()) : nullptr;
    if (!controller || !controller->metaCast("AirPort_BrcmNIC") || controller->isInactive() ||
        !device || device->isInactive() || !loop || !loop->inGate())
        return originalVerify(wlc);
    auto value = controller->copyProperty(SnapshotKey);
    auto data = OSDynamicCast(OSData, value);
    PCIConfiguration snapshot {};
    if (data && data->getLength() == sizeof(snapshot))
        memcpy(&snapshot, data->getBytesNoCopy(), sizeof(snapshot));
    if (value)
        value->release();
    if (!snapshot.valid() || snapshot.registryID != device->getRegistryEntryID())
        return originalVerify(wlc);
    PCIBus bus {device, !(snapshot.byte(0x0e) & 0x80)};
    if (pciConfigurationMatches(bus, snapshot))
        return originalVerify(wlc);
    auto count = attempts(controller);
    if (count >= 3 || !controller->setProperty(AttemptsKey, count + 1, 32)) {
        controller->setProperty(ResultKey, "RetryLimit");
        return originalVerify(wlc);
    }
    controller->setProperty("PCIRecoveryInitialID", bus.read32(0), 32);
    controller->setProperty("PCIRecoveryInitialBAR0", bus.read32(0x10), 32);
    const auto recovered = recoverPCIConfiguration(bus, snapshot);
    static const char *const names[] = {"Unchanged", "ConfigurationRestored", "InvalidSnapshot", "IdentityChanged",
        "ResourceChanged", "ResetRefused", "LinkUnavailable", "RestoreFailed"};
    controller->setProperty(ResultKey, names[static_cast<unsigned>(recovered)]);
    controller->setProperty("PCIRecoveryFinalID", bus.read32(0), 32);
    controller->setProperty("PCIRecoveryFinalBAR0", bus.read32(0x10), 32);
    const auto driverResult = originalVerify(wlc);
    const auto result = driverResult || recovered == PCIRecoveryResult::Restored || recovered == PCIRecoveryResult::Unchanged ?
        driverResult : -1;
    controller->setProperty("PCIRecoveryDriverResult", static_cast<uint32_t>(driverResult), 32);
    controller->setProperty("PCIRecoveryResult", static_cast<uint32_t>(result), 32);
    if (recovered == PCIRecoveryResult::Restored)
        controller->setProperty(ResultKey, result ? "DriverValidationFailed" : "Verified");
    SYSLOG("pci", "attempt %u: %s, driver result %d, result %d", count + 1,
        names[static_cast<unsigned>(recovered)], driverResult, result);
    return result;
}

bool preparePCIRecovery(KernelPatcher &patcher, size_t index, uintptr_t address, size_t size) {
    KernelPatcher::RouteRequest routes[] = {
        {"__ZN15AirPort_BrcmNIC10startGatedEP9IOService", startGated, originalStart},
        {"__ZN15AirPort_BrcmNIC14syncPowerStateEmi", syncPower, originalSyncPower},
        {"_wlc_verify_d3_exit", verifyD3, originalVerify},
    };
    return patcher.routeMultipleLong(index, routes, address, size);
}

void publishPCIRecovery(IOService *service, IOService *controller) {
    const char *keys[] = {ResultKey, AttemptsKey, "PCIRecoveryInitialID", "PCIRecoveryInitialBAR0",
        "PCIRecoveryFinalID", "PCIRecoveryFinalBAR0", "PCIRecoveryDriverResult", "PCIRecoveryResult"};
    for (auto key : keys) {
        auto value = controller->copyProperty(key);
        if (value) {
            service->setProperty(key, value);
            value->release();
        }
    }
}

}
