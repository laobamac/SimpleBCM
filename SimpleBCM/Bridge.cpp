//
//  Bridge.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/9/4.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "Bridge.hpp"
#include "NativeSkywalk.hpp"
#include "NativeUserClient.hpp"
#include "Profiles.hpp"
#include "UserClient.hpp"
#include "HardwareIdentity.hpp"
#include "RadioPolicy.hpp"
#include "TahoeDMA.hpp"
#include "AWDLCoexistence.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/IOWorkLoop.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSBoolean.h>
#include <kern/clock.h>
#include <mach/mach_time.h>
#include <kern/thread_call.h>
#include <mach/thread_act.h>
#include <mach-o/loader.h>
#include <net/if.h>
#include <net/kpi_interface.h>
#include <pexpert/pexpert.h>
#include <sys/errno.h>
#include <sys/systm.h>

namespace bcm {

Counters counters {};
static uint32_t state;
static bool awdlCoexistenceEnabled;
static bool tahoeDMAEnabled;
static IOService *observedController;
static const char *failure = "WaitingForDependencies";
static IOSimpleLock *contextLock;
static IOSimpleLock *hubLock;
static BCM80211UserClient *clients[64];
static thread_call_t eventCall;

struct CopyContext {
    thread_t thread;
    uintptr_t begin;
    size_t length;
    IOService *controller;
    OSObject *interface;
    bool hostAPWPA2;
    CopyContext *next;
};

struct PendingEvent {
    IOService *controller;
    IOService *interface;
    uint64_t serial;
    char name[16];
    uint32_t event;
    uint32_t length;
    uint64_t seconds;
    uint64_t microseconds;
    uint8_t payload[MaximumEventPayload];
};

static CopyContext *contexts;
static PendingEvent *pending;
static uint32_t pendingRead;
static uint32_t pendingWrite;
static uint64_t serial;
static constexpr uint32_t PendingCapacity = 64;

static struct {
    IOService *controller;
    char name[16];
    bool original;
    AvailabilityEvent event;
} availability[16];

using NewClient = IOReturn (*)(IOService *, task_t, void *, uint32_t, OSDictionary *, IOUserClient **);
using PostMessage = IOReturn (*)(IOService *, uint32_t, void *, size_t);
using Ioctl = int (*)(IOService *, IOService *, IOService *, IOService *, void *);
using Controller = IOService *(*)(IOService *);
using BSDName = const char *(*)(IOService *);
using InterfaceFlags = void (*)(IOService *, const char *);
static InterfaceFlags updateVirtualFlags;
using PerformCommand = int (*)(IOService *, IOService *, unsigned long, void *, void *);

static NewClient originalClassicClient;
static NewClient originalVirtualClient;
static NewClient originalSkywalkClient;
static PostMessage originalClassicEvent;
static PostMessage originalVirtualEvent;
static PostMessage originalInfraEvent;
static Ioctl getRequest;
static Ioctl setRequest;
static Controller classicController;
static Controller virtualController;
static BSDName classicName;
static BSDName virtualName;
static BSDName skywalkName;
static PerformCommand classicCommand;
static const UserABI *activeABI;

static void reject(const char *reason) {
    __atomic_store_n(&failure, reason, __ATOMIC_RELEASE);
    __atomic_fetch_or(&state, 0x80000000U, __ATOMIC_RELEASE);
    SYSLOG("bridge", "disabled: %s", reason);
}

bool Bridge::ready() {
    return __atomic_load_n(&state, __ATOMIC_ACQUIRE) == 7;
}

const UserABI &Bridge::abi() {
    return *activeABI;
}

bool Bridge::isScalarGet(uint32_t request) {
    for (auto entry : ScalarGetRequests) {
        if (entry == request)
            return true;
    }
    return false;
}

static bool contains(uintptr_t begin, size_t size, uintptr_t address, size_t length) {
    return address >= begin && address - begin <= size && length <= size - (address - begin);
}

static bool isShadow(uintptr_t address, size_t size) {
    bool found = false;
    auto thread = current_thread();
    IOSimpleLockLock(contextLock);
    for (auto context = contexts; context; context = context->next) {
        if (context->thread == thread && contains(context->begin, context->length, address, size)) {
            found = true;
            break;
        }
    }
    IOSimpleLockUnlock(contextLock);
    return found;
}

static int bridgeCopyIn(user_addr_t address, void *destination, size_t size) {
    if (!isShadow(static_cast<uintptr_t>(address), size))
        return copyin(address, destination, size);
    memcpy(destination, reinterpret_cast<const void *>(address), size);
    return 0;
}

static int bridgeCopyOut(const void *source, user_addr_t address, size_t size) {
    if (!isShadow(static_cast<uintptr_t>(address), size))
        return copyout(source, address, size);
    memcpy(reinterpret_cast<void *>(address), source, size);
    return 0;
}

bool Bridge::identify(IOService *interface, InterfaceKind kind, Endpoint &endpoint) {
    if (!interface || !ready())
        return false;
    IOService *controller = nullptr;
    const char *name = nullptr;
    switch (kind) {
        case InterfaceKind::Classic:
            controller = classicController(interface);
            name = classicName(interface);
            break;
        case InterfaceKind::Virtual:
            controller = virtualController(interface);
            name = virtualName(interface);
            break;
        case InterfaceKind::Skywalk:
            for (IOService *parent = interface->getProvider(); parent; parent = parent->getProvider()) {
                if (parent->metaCast("AirPort_BrcmNIC")) {
                    controller = parent;
                    break;
                }
            }
            name = skywalkName(interface);
            break;
    }
    if (!controller || !controller->metaCast("AirPort_BrcmNIC") || !name || !name[0] || strnlen(name, 16) == 16)
        return false;
    bool supported = false;
    for (IOService *parent = controller->getProvider(); parent; parent = parent->getProvider()) {
        auto vendor = OSDynamicCast(OSData, parent->getProperty("vendor-id"));
        auto device = OSDynamicCast(OSData, parent->getProperty("device-id"));
        if (!vendor || !device || vendor->getLength() != 4 || device->getLength() != 4)
            continue;
        uint32_t v, d;
        memcpy(&v, vendor->getBytesNoCopy(), sizeof(v));
        memcpy(&d, device->getBytesNoCopy(), sizeof(d));
        static constexpr uint32_t ids[] = {0x4331, 0x4353, 0x43BA, 0x43A3, 0x43A0, 0x4357, 0x43B1, 0x43B2};
        for (auto id : ids)
            supported |= v == 0x14E4 && d == id;
        break;
    }
    if (!supported)
        return false;
    endpoint.interface = interface;
    endpoint.controller = controller;
    endpoint.kind = kind;
    strlcpy(endpoint.name, name, sizeof(endpoint.name));
    return true;
}

using LocaleQuery = int (*)(IOService *, OSObject *, LocaleData *);
using CountryCodeQuery = int (*)(IOService *, OSObject *, CountryCodeData *);
using CountryProperty = void (*)(IOService *, bool);
using DriverRequest = int (*)(IOService *, uint32_t, int, IOService *, void *);

static LocaleQuery originalLocale;
static CountryCodeQuery getCountryCode;
static CountryProperty originalCountryProperty;
static DriverRequest classicRequest;
using CipherKeySet = int (*)(IOService *, OSObject *, void *);
using IovarSet = int (*)(IOService *, const char *, int);
using FirmwareRequest = int (*)(IOService *, uint32_t, void *, size_t, bool, OSObject *);
using CipherCalculate = uint32_t (*)(IOService *, OSObject *);
using VirtualFirmwareInterface = void *(*)(IOService *, OSObject *);
using FirmwareBSS = void *(*)(void *, void *);
using AuthenticatorCreate = void *(*)(void *, void *);
using AKMPolicySet = void (*)(void *, uint16_t);
static CipherKeySet originalCipherKeySet;
static IovarSet setIovar;
static FirmwareRequest sendFirmwareRequest;
static CipherCalculate originalCipherCalculate;
static VirtualFirmwareInterface firmwareVirtualInterface;
static FirmwareBSS firmwareBSS;
static AuthenticatorCreate createAuthenticator;
static AKMPolicySet setAKMPolicy;
using MACValidate = int (*)(void *, void *, const void *);
static MACValidate validateNetworkMAC;
static IOReturn maintainNetworkMAC(OSObject *, void *, void *, void *, void *);

using NetworkModeSet = int (*)(IOService *, IOService *, IOService *, IOService *, Request *, bool);
static NetworkModeSet originalNetworkModeSet;

static int setNetworkMode(IOService *controller, IOService *classic, IOService *virtualInterface,
                          IOService *infra, Request *request, bool wide) {
    if (!request || !allowLegacyNetworkMode(*request))
        return EINVAL;
    return originalNetworkModeSet(controller, classic, virtualInterface, infra, request, wide);
}

static int disableNetworkPower(IOService *controller, uint32_t command, int request,
                               IOService *interface, void *payload) {
    if (command == LegacyDriverSetCommand && request == PowerRequest && controller && interface &&
        !controller->isInactive() && !interface->isInactive() &&
        controller->metaCast("AirPort_BrcmNIC") &&
        preserveNetworkModePower(controller->getProperty("SimpleBCMHostAPActive") == kOSBooleanTrue,
            __atomic_load_n(reinterpret_cast<const uint8_t *>(controller) + LegacySystemPowerTransitionOffset,
                            __ATOMIC_ACQUIRE) != 0 ||
            __atomic_load_n(reinterpret_cast<const uint8_t *>(controller) + 6816, __ATOMIC_ACQUIRE) != 0 ||
            __atomic_load_n(reinterpret_cast<const uint64_t *>(reinterpret_cast<const uint8_t *>(controller) + 6800),
                            __ATOMIC_ACQUIRE) != 2,
            static_cast<const uint8_t *>(payload), PowerDataSize)) {
        uint8_t power[PowerDataSize] {};
        if (!classicRequest(controller, LegacyDriverGetCommand, PowerRequest, interface, power) &&
            isNetworkPowerOn(power, sizeof(power))) {
            maintainNetworkMAC(controller, nullptr, nullptr, nullptr, nullptr);
            return 0;
        }
    }
    const auto result = classicRequest(controller, command, request, interface, payload);
    if (!result && controller && interface && command == LegacyDriverSetCommand && request == PowerRequest &&
        isNetworkPowerOff(static_cast<const uint8_t *>(payload), PowerDataSize))
        controller->setProperty("SimpleBCMHostAPActive", false);
    return result;
}

static int ensureNetworkAuthenticator(IOService *controller, OSObject *interface) {
    void *wlc;
    memcpy(&wlc, reinterpret_cast<const uint8_t *>(controller) + 2576, sizeof(wlc));
    if (!wlc)
        return ENXIO;
    auto virtualInterface = firmwareVirtualInterface(controller, interface);
    void *wlcif = nullptr;
    if (virtualInterface)
        memcpy(&wlcif, static_cast<const uint8_t *>(virtualInterface) + 544, sizeof(wlcif));
    auto configuration = static_cast<uint8_t *>(firmwareBSS(wlc, wlcif));
    if (!configuration || !configuration[10])
        return EINVAL;
    void *pub;
    void *module;
    memcpy(&pub, wlc, sizeof(pub));
    memcpy(&module, static_cast<const uint8_t *>(wlc) + 400, sizeof(module));
    if (!pub || !static_cast<const uint8_t *>(pub)[210] || !module)
        return ENOTSUP;
    void *authenticator;
    memcpy(&authenticator, configuration + 32, sizeof(authenticator));
    if (!authenticator) {
        authenticator = createAuthenticator(wlc, configuration);
        if (!authenticator)
            return ENOMEM;
        memcpy(configuration + 32, &authenticator, sizeof(authenticator));
    }
    setAKMPolicy(configuration, 2);
    return 0;
}

static int installNetworkCipher(IOService *controller, OSObject *interface, void *payload) {
    auto key = static_cast<const uint8_t *>(payload);
    int result = 0;
    const auto length = key ? readUInt32(key + 4) : 0;
    const bool secured = key && length >= 8 && length <= 64 && readUInt32(key + 8) == LegacyNetworkPSKCipher;
    if (secured)
        result = ensureNetworkAuthenticator(controller, interface);
    if (!result && secured)
        result = setIovar(controller, "wsec", 4);
    if (!result && secured) {
        uint8_t pmk[68] {};
        pmk[0] = static_cast<uint8_t>(length);
        pmk[2] = 1;
        memcpy(pmk + 4, key + 16, length);
        result = sendFirmwareRequest(controller, 268, pmk, sizeof(pmk), true, interface);
        bzero(pmk, sizeof(pmk));
    } else if (!result)
        result = originalCipherKeySet(controller, interface, payload);
    return result;
}

static uint32_t calculateNetworkCipher(IOService *controller, OSObject *interface) {
    const auto original = originalCipherCalculate(controller, interface);
    const auto thread = current_thread();
    bool secured = false;
    IOSimpleLockLock(contextLock);
    for (auto context = contexts; context; context = context->next) {
        if (context->thread == thread && context->controller == controller && context->interface == interface) {
            secured = context->hostAPWPA2;
            break;
        }
    }
    IOSimpleLockUnlock(contextLock);
    return networkSSIDCipher(secured, original);
}

static int getLocale(IOService *controller, OSObject *, LocaleData *output) {
    const auto result = originalLocale(controller, nullptr, output);
    if (result || !output || output->version != 1 || output->locale != LocaleUnknown)
        return result;
    CountryCodeData country {};
    if (!getCountryCode(controller, nullptr, &country))
        resolveLocale(*output, country);
    return result;
}

static int synchronizeNetworkMAC(IOService *controller) {
    void *wlc;
    memcpy(&wlc, reinterpret_cast<const uint8_t *>(controller) + 2576, sizeof(wlc));
    if (!wlc)
        return ENXIO;
    auto configuration = static_cast<uint8_t *>(firmwareBSS(wlc, nullptr));
    if (!configuration || !configuration[8] || !configuration[9] || !configuration[10])
        return EINVAL;
    uint8_t address[6];
    memcpy(address, configuration + 232, sizeof(address));
    uint8_t nonzero = 0;
    for (auto octet : address)
        nonzero |= octet;
    if (!nonzero || (address[0] & 1U))
        return EIO;
    if (validateNetworkMAC(wlc, configuration, address))
        return EIO;
    configuration = static_cast<uint8_t *>(firmwareBSS(wlc, nullptr));
    if (!configuration || !configuration[8] || !configuration[9] || !configuration[10] ||
        memcmp(address, configuration + 232, sizeof(address)) ||
        memcmp(address, configuration + 238, sizeof(address)))
        return EIO;
    return 0;
}

static IOReturn maintainNetworkMAC(OSObject *owner, void *, void *, void *, void *) {
    auto controller = static_cast<IOService *>(owner);
    if (controller->isInactive() || controller->getProperty("SimpleBCMHostAPActive") != kOSBooleanTrue)
        return kIOReturnSuccess;
    const auto bytes = reinterpret_cast<const uint8_t *>(controller);
    if (__atomic_load_n(bytes + LegacySystemPowerTransitionOffset, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(bytes + 6816, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(reinterpret_cast<const uint64_t *>(bytes + 6800), __ATOMIC_ACQUIRE) != 2)
        return kIOReturnSuccess;
    void *wlc;
    memcpy(&wlc, bytes + 2576, sizeof(wlc));
    if (!wlc)
        return kIOReturnSuccess;
    const auto configuration = static_cast<const uint8_t *>(firmwareBSS(wlc, nullptr));
    if (!configuration || !configuration[8] || !configuration[9] || !configuration[10] ||
        !memcmp(configuration + 232, configuration + 238, 6))
        return kIOReturnSuccess;
    return synchronizeNetworkMAC(controller) ? kIOReturnIOError : kIOReturnSuccess;
}

static IOReturn restoreNetworkAWDL(OSObject *owner, void *, void *, void *, void *) {
    auto controller = static_cast<IOService *>(owner);
    if (controller->isInactive() || controller->getProperty("SimpleBCMHostAPRestoreAWDL") != kOSBooleanTrue ||
        controller->getProperty("SimpleBCMHostAPActive") == kOSBooleanTrue)
        return kIOReturnSuccess;
    const auto bytes = reinterpret_cast<const uint8_t *>(controller);
    if (__atomic_load_n(bytes + LegacySystemPowerTransitionOffset, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(bytes + 6816, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(reinterpret_cast<const uint64_t *>(bytes + 6800), __ATOMIC_ACQUIRE) != 2)
        return kIOReturnSuccess;
    void *wlc;
    memcpy(&wlc, bytes + 2576, sizeof(wlc));
    if (!wlc)
        return kIOReturnSuccess;
    const auto configuration = static_cast<const uint8_t *>(firmwareBSS(wlc, nullptr));
    void *pub;
    memcpy(&pub, wlc, sizeof(pub));
    if (!configuration || configuration[10] || !pub || !static_cast<const uint8_t *>(pub)[32] ||
        static_cast<const uint8_t *>(pub)[33])
        return kIOReturnSuccess;
    auto iterator = controller->getClientIterator();
    if (!iterator)
        return kIOReturnSuccess;
    IOReturn result = kIOReturnNotReady;
    while (auto object = iterator->getNextObject()) {
        auto interface = OSDynamicCast(IOService, object);
        Endpoint endpoint {};
        if (!interface || !interface->metaCast("AirPort_BrcmNIC_P2PInterface") || interface->isInactive() ||
            !Bridge::identify(interface, InterfaceKind::Virtual, endpoint) || endpoint.controller != controller ||
            strncmp(endpoint.name, "awdl", 4))
            continue;
        ifnet_t network = nullptr;
        if (ifnet_find_by_name(endpoint.name, &network) || !network)
            continue;
        if (ifnet_softc(network) == interface) {
            result = kIOReturnSuccess;
            if (ifnet_flags(network) & IFF_UP) {
                const auto down = ifnet_set_flags(network, 0, IFF_UP);
                if (!down)
                    updateVirtualFlags(interface, "HostAP stop");
                const auto up = ifnet_set_flags(network, IFF_UP, IFF_UP);
                if (!up)
                    updateVirtualFlags(interface, "HostAP stop");
                if (down || up || (ifnet_flags(network) & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING))
                    result = kIOReturnIOError;
            }
            if (result == kIOReturnSuccess)
                controller->setProperty("SimpleBCMHostAPRestoreAWDL", false);
        }
        ifnet_release(network);
        break;
    }
    iterator->release();
    return result;
}

static IOReturn updateCountryProperties(OSObject *target, void *argument, void *logging, void *, void *) {
    auto controller = static_cast<IOService *>(target);
    auto interface = static_cast<IOService *>(argument);
    originalCountryProperty(interface, *static_cast<bool *>(logging));
    LocaleData locale {};
    if (interface->isInactive() || controller->isInactive() ||
        !interface->getProperty("IO80211CountryCode") ||
        classicRequest(controller, 0xC03069C9, 28, interface, &locale) || locale.version != 1)
        interface->removeProperty("IO80211Locale");
    else
        interface->setProperty("IO80211Locale", localeString(locale.locale));
    return kIOReturnSuccess;
}

static void updateCountryProperty(IOService *interface, bool logging) {
    auto controller = classicController(interface);
    auto loop = controller ? controller->getWorkLoop() : nullptr;
    if (!controller || !controller->metaCast("AirPort_BrcmNIC") || !loop) {
        originalCountryProperty(interface, logging);
        return;
    }
    if (loop->runAction(updateCountryProperties, controller, interface, &logging) != kIOReturnSuccess) {
        originalCountryProperty(interface, logging);
        interface->removeProperty("IO80211Locale");
    }
}

using HardwareVersion = IOReturn (*)(IOService *, OSObject *, void *);
static HardwareVersion originalHardwareVersion;

static IOReturn getHardwareVersion(IOService *controller, OSObject *interface, void *output) {
    auto result = originalHardwareVersion(controller, interface, output);
    if (result != kIOReturnSuccess || !output)
        return result;
    auto bytes = static_cast<uint8_t *>(output);
    uint16_t length;
    memcpy(&length, bytes + 4, sizeof(length));
    auto text = reinterpret_cast<char *>(bytes + 6);
    HardwareIdentity identity {};
    if (readUInt32(bytes) != 1 || length >= 256 || text[length] != '\0' ||
        !decodeHardwareIdentity(text, length, identity))
        return result;
    controller->setProperty("SimpleBCMOriginalHardwareVersion", text);
    int count;
    if (identity.boardVendor == 0x106b)
        count = snprintf(text, 256, "AirPort Extreme (0x%X, 0x%X)", identity.vendor, identity.board);
    else
        count = snprintf(text, 256, "Broadcom BCM%u (%04x:%04x)", identity.chip, identity.vendor, identity.device);
    length = static_cast<uint16_t>(count);
    memcpy(bytes + 4, &length, sizeof(length));
    return result;
}

static IOReturn newClassicClient(IOService *self, task_t task, void *token, uint32_t type,
                                OSDictionary *properties, IOUserClient **result) {
    auto status = type || !Bridge::ready() ?
        originalClassicClient(self, task, token, type, properties, result) :
        BCM80211UserClient::create(self, task, token, properties, InterfaceKind::Classic, result);
    return wrapNativeUserClient(status, task, token, type, properties, result);
}

static IOReturn newVirtualClient(IOService *self, task_t task, void *token, uint32_t type,
                                OSDictionary *properties, IOUserClient **result) {
    auto status = type || !Bridge::ready() ?
        originalVirtualClient(self, task, token, type, properties, result) :
        BCM80211UserClient::create(self, task, token, properties, InterfaceKind::Virtual, result);
    return wrapNativeUserClient(status, task, token, type, properties, result);
}

static IOReturn newSkywalkClient(IOService *self, task_t task, void *token, uint32_t type,
                                OSDictionary *properties, IOUserClient **result) {
    auto status = type || !Bridge::ready() || !self->metaCast("BCMLegacyInterface") ?
        originalSkywalkClient(self, task, token, type, properties, result) :
        BCM80211UserClient::create(self, task, token, properties, InterfaceKind::Skywalk, result);
    return wrapNativeUserClient(status, task, token, type, properties, result);
}

IOReturn createSkywalkUserClient(IOService *self, task_t task, void *token, uint32_t type,
                                OSDictionary *properties, IOUserClient **result) {
    return newSkywalkClient(self, task, token, type, properties, result);
}

void Bridge::enableNativeSkywalk() {
    originalSkywalkClient = nativeSkywalkUserClient;
    __atomic_fetch_or(&state, 2U, __ATOMIC_RELEASE);
}

bool Bridge::addClient(BCM80211UserClient *client) {
    bool added = false;
    const auto interruptState = IOSimpleLockLockDisableInterrupt(hubLock);
    for (auto &entry : clients) {
        if (!entry) {
            client->retain();
            entry = client;
            added = true;
            break;
        }
    }
    IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
    return added;
}

void Bridge::removeClient(BCM80211UserClient *client) {
    BCM80211UserClient *removed = nullptr;
    const auto interruptState = IOSimpleLockLockDisableInterrupt(hubLock);
    for (auto &entry : clients) {
        if (entry == client) {
            removed = entry;
            entry = nullptr;
            break;
        }
    }
    IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
    if (removed)
        removed->release();
}

static int readEventValue(const Endpoint &endpoint, uint32_t type, uint8_t *buffer, size_t length,
                          uint32_t *value = nullptr) {
    LegacyRequest request {};
    strlcpy(request.request.interfaceName, endpoint.name, sizeof(request.request.interfaceName));
    request.request.type = static_cast<int32_t>(type);
    request.request.length = static_cast<uint32_t>(length);
    request.request.data = reinterpret_cast<uint64_t>(buffer);
    request.pointerSize = 8;
    const auto result = Bridge::command(endpoint, false, request, buffer, length);
    if (!result && !value && request.request.length != length)
        return EINVAL;
    if (!result && value)
        *value = static_cast<uint32_t>(request.request.value);
    return result;
}

static IOReturn captureJoinEvent(OSObject *, void *argument, void *, void *, void *) {
    auto event = static_cast<PendingEvent *>(argument);
    Endpoint endpoint {event->interface, event->controller, InterfaceKind::Classic, {}};
    strlcpy(endpoint.name, event->name, sizeof(endpoint.name));
    uint8_t buffer[6] {};
    uint32_t status {}, result {};
    auto error = readEventValue(endpoint, 50, buffer, sizeof(uint32_t), &status);
    if (!error)
        error = readEventValue(endpoint, 21, buffer, sizeof(uint32_t), &result);
    if (!error && result == 1)
        error = readEventValue(endpoint, 9, buffer, sizeof(buffer));
    __atomic_store_n(&counters.lastAssociationEventReadResult, static_cast<uint32_t>(error), __ATOMIC_RELAXED);
    if (error) {
        __atomic_fetch_add(&counters.associationEventReadErrors, 1ULL, __ATOMIC_RELAXED);
        return static_cast<IOReturn>(error);
    }
    if (encodeJoinStatus(status, result, buffer, result == 1 ? sizeof(buffer) : 0,
                         event->payload, sizeof(event->payload), Bridge::abi())) {
        event->length = static_cast<uint32_t>(Bridge::abi().joinStatusSize);
        __atomic_fetch_add(&counters.associationEventConversions, 1ULL, __ATOMIC_RELAXED);
    }
    return kIOReturnSuccess;
}

static void drainEvents(thread_call_param_t, thread_call_param_t) {
    PendingEvent event;
    for (;;) {
        BCM80211UserClient *targets[64];
        size_t count = 0;
        const auto interruptState = IOSimpleLockLockDisableInterrupt(hubLock);
        if (pendingRead == pendingWrite) {
            IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
            return;
        }
        memcpy(&event, &pending[pendingRead], sizeof(event));
        pendingRead = (pendingRead + 1) % PendingCapacity;
        for (auto client : clients) {
            if (client) {
                client->retain();
                targets[count++] = client;
            }
        }
        IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
        auto controllerLoop = event.controller->getWorkLoop();
        if (controllerLoop && event.controller->getProperty("SimpleBCMHostAPActive") == kOSBooleanTrue)
            controllerLoop->runAction(maintainNetworkMAC, event.controller);
        if (event.interface) {
            auto loop = event.controller->getWorkLoop();
            if (loop)
                loop->runAction(captureJoinEvent, event.controller, &event);
            event.interface->release();
        }
        for (size_t index = 0; index < count; ++index) {
            targets[index]->receive(event.controller, event.name, event.event, event.payload,
                                    event.length, event.seconds, event.microseconds, event.serial);
            targets[index]->release();
        }
        event.controller->release();
    }
}

static void queueEvent(IOService *self, InterfaceKind kind, uint32_t message, void *payload, size_t length,
                       bool powerSnapshot = false) {
    if (!Bridge::ready())
        return;
    Endpoint endpoint {};
    if (length > MaximumEventPayload || (length && !payload) || !Bridge::identify(self, kind, endpoint)) {
        __atomic_fetch_add(&counters.dropped, 1ULL, __ATOMIC_RELAXED);
        return;
    }
    const auto &abi = Bridge::abi();
    const auto outputLength = static_cast<uint32_t>(eventPayloadSize(message, length, abi));
    clock_sec_t seconds;
    clock_usec_t microseconds;
    clock_get_calendar_microtime(&seconds, &microseconds);
    const auto interruptState = IOSimpleLockLockDisableInterrupt(hubLock);
    const auto eventSerial = __atomic_add_fetch(&serial, 1ULL, __ATOMIC_RELEASE);
    if (message == DriverAvailableEvent) {
        size_t slot = arrsize(availability);
        for (size_t index = 0; index < arrsize(availability); ++index) {
            if (availability[index].controller && availability[index].controller == endpoint.controller &&
                !strncmp(availability[index].name, endpoint.name, sizeof(endpoint.name))) {
                slot = index;
                break;
            }
            if (!availability[index].controller && slot == arrsize(availability))
                slot = index;
        }
        if (powerSnapshot && slot == arrsize(availability)) {
            IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
            return;
        }
        if (slot < arrsize(availability)) {
            auto &saved = availability[slot];
            if (powerSnapshot && (saved.original ||
                (saved.event.length == abi.driverAvailableSize &&
                 readUInt32(saved.event.payload + 8) == readUInt32(static_cast<uint8_t *>(payload) + 8)))) {
                IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
                return;
            }
            if (!saved.controller) {
                saved.controller = endpoint.controller;
                saved.controller->retain();
                strlcpy(saved.name, endpoint.name, sizeof(saved.name));
            }
            saved.event.length = 0;
            saved.original = !powerSnapshot && outputLength == abi.driverAvailableSize;
            if (outputLength == abi.driverAvailableSize) {
                copyEventPayload(message, payload, length, saved.event.payload, sizeof(saved.event.payload), abi);
                saved.event.length = outputLength;
                saved.event.seconds = seconds;
                saved.event.microseconds = microseconds;
            }
        }
        __atomic_fetch_add(powerSnapshot ? &counters.powerAvailabilityEvents : &counters.availabilityEvents,
                           1ULL, __ATOMIC_RELAXED);
    }
    if (message == AssociationDoneEvent) {
        __atomic_fetch_add(&counters.associationEvents, 1ULL, __ATOMIC_RELAXED);
        __atomic_store_n(&counters.lastAssociationEventLength, static_cast<uint32_t>(length), __ATOMIC_RELAXED);
    }
    const auto next = (pendingWrite + 1) % PendingCapacity;
    if (next == pendingRead) {
        IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
        __atomic_fetch_add(&counters.dropped, 1ULL, __ATOMIC_RELAXED);
        return;
    }
    auto &entry = pending[pendingWrite];
    entry.serial = eventSerial;
    entry.controller = endpoint.controller;
    entry.controller->retain();
    entry.interface = abi.joinEventPolicy != JoinEventPolicy::Passthrough &&
        message == AssociationDoneEvent && !length && kind == InterfaceKind::Classic ? self : nullptr;
    if (entry.interface)
        entry.interface->retain();
    strlcpy(entry.name, endpoint.name, sizeof(entry.name));
    entry.event = message;
    entry.length = outputLength;
    entry.seconds = seconds;
    entry.microseconds = microseconds;
    copyEventPayload(message, payload, length, entry.payload, sizeof(entry.payload), abi);
    pendingWrite = next;
    IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
    __atomic_fetch_add(&counters.events, 1ULL, __ATOMIC_RELAXED);
    if (message == ScanDoneEvent)
        __atomic_fetch_add(&counters.scanDoneEvents, 1ULL, __ATOMIC_RELAXED);
    thread_call_enter(eventCall);
}

int Bridge::refreshAvailability(const Endpoint &endpoint) {
    if (endpoint.kind != InterfaceKind::Classic)
        return ENOTSUP;
    uint8_t power[PowerDataSize] {};
    return readEventValue(endpoint, 19, power, sizeof(power));
}

uint64_t Bridge::copyAvailability(const Endpoint &endpoint, AvailabilityEvent &event) {
    const auto interruptState = IOSimpleLockLockDisableInterrupt(hubLock);
    const auto boundary = __atomic_load_n(&serial, __ATOMIC_ACQUIRE);
    event.length = 0;
    for (const auto &saved : availability) {
        if (saved.controller == endpoint.controller &&
            !strncmp(saved.name, endpoint.name, sizeof(endpoint.name))) {
            event = saved.event;
            break;
        }
    }
    IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
    return boundary;
}

static IOReturn postClassic(IOService *self, uint32_t message, void *payload, size_t length) {
    queueEvent(self, InterfaceKind::Classic, message, payload, length);
    return originalClassicEvent(self, message, payload, length);
}

static IOReturn postVirtual(IOService *self, uint32_t message, void *payload, size_t length) {
    queueEvent(self, InterfaceKind::Virtual, message, payload, length);
    return originalVirtualEvent(self, message, payload, length);
}

static IOReturn postInfra(IOService *self, uint32_t message, void *payload, size_t length) {
    queueEvent(self, InterfaceKind::Skywalk, message, payload, length);
    return originalInfraEvent(self, message, payload, length);
}

int Bridge::command(const Endpoint &endpoint, bool set, LegacyRequest &request, void *shadow, size_t size) {
    if (!ready() || endpoint.interface->isInactive() || endpoint.controller->isInactive())
        return ENXIO;
    CopyContext context {current_thread(), reinterpret_cast<uintptr_t>(shadow), size,
        endpoint.controller, endpoint.interface,
        set && isLegacyHostAPWPA2(request.request, static_cast<const uint8_t *>(shadow), size), nullptr};
    IOSimpleLockLock(contextLock);
    context.next = contexts;
    contexts = &context;
    IOSimpleLockUnlock(contextLock);
    const bool startAP = set && request.request.type == HostAPModeRequest && request.request.value == NetworkModeStart;
    const bool stopAP = set && request.request.type == HostAPModeRequest && request.request.value == NetworkModeStop;
    const bool cancelRestore = set && ((isNetworkModeRequest(request.request.type) &&
        request.request.value == NetworkModeStart) ||
        (request.request.type == PowerRequest && request.request.length <= size &&
         isNetworkPowerOff(static_cast<const uint8_t *>(shadow), request.request.length)));
    const bool restorePending = cancelRestore &&
        endpoint.controller->getProperty("SimpleBCMHostAPRestoreAWDL") == kOSBooleanTrue;
    if (restorePending)
        endpoint.controller->setProperty("SimpleBCMHostAPRestoreAWDL", false);
    const bool releaseAP = set &&
        (isNetworkModeRequest(request.request.type) || request.request.type == AssociateRequest || request.request.type == 26 ||
         (request.request.type == PowerRequest && request.request.length <= size &&
          isNetworkPowerOff(static_cast<const uint8_t *>(shadow), request.request.length)));
    const bool active = releaseAP && endpoint.controller->getProperty("SimpleBCMHostAPActive") == kOSBooleanTrue;
    if (active)
        endpoint.controller->setProperty("SimpleBCMHostAPActive", false);
    const auto result = endpoint.kind == InterfaceKind::Classic ?
        classicCommand(endpoint.interface, endpoint.controller, set ? SetCommand : GetCommand, nullptr, &request.request) :
        (set ? setRequest : getRequest)(endpoint.controller, nullptr,
            endpoint.kind == InterfaceKind::Virtual ? endpoint.interface : nullptr,
            endpoint.kind == InterfaceKind::Skywalk ? endpoint.interface : nullptr, &request);
    if (!result && startAP) {
        endpoint.controller->setProperty("SimpleBCMHostAPActive", true);
        maintainNetworkMAC(endpoint.controller, nullptr, nullptr, nullptr, nullptr);
    }
    if (result && active)
        endpoint.controller->setProperty("SimpleBCMHostAPActive", true);
    if (!result && stopAP && active)
        endpoint.controller->setProperty("SimpleBCMHostAPRestoreAWDL", true);
    else if (result && restorePending)
        endpoint.controller->setProperty("SimpleBCMHostAPRestoreAWDL", true);
    IOSimpleLockLock(contextLock);
    for (auto cursor = &contexts; *cursor; cursor = &(*cursor)->next) {
        if (*cursor == &context) {
            *cursor = context.next;
            break;
        }
    }
    IOSimpleLockUnlock(contextLock);
    if (!set && request.request.type == 19 && endpoint.kind == InterfaceKind::Classic) {
        __atomic_store_n(&counters.lastAvailabilityReadResult, static_cast<uint32_t>(result), __ATOMIC_RELAXED);
        uint8_t event[NativeDriverAvailableSize];
        if (!result && size >= PowerDataSize && request.request.length == PowerDataSize &&
            encodePowerAvailability(static_cast<const uint8_t *>(shadow), PowerDataSize, event, sizeof(event), abi()))
            queueEvent(endpoint.interface, endpoint.kind, DriverAvailableEvent, event, abi().driverAvailableSize, true);
    }
    return result;
}

static bool validate(mach_vm_address_t address, size_t size,
                     const ByteGuard *guards, size_t count) {
    if (size < sizeof(mach_header_64))
        return false;
    auto header = reinterpret_cast<const mach_header_64 *>(address);
    if (header->magic != MH_MAGIC_64 || header->cputype != CPU_TYPE_X86_64 ||
        header->ncmds > 512 || header->sizeofcmds > size - sizeof(*header))
        return false;
    const auto end = address + sizeof(*header) + header->sizeofcmds;
    auto cursor = address + sizeof(*header);
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if (cursor > end || end - cursor < sizeof(load_command))
            return false;
        auto cmd = reinterpret_cast<const load_command *>(cursor);
        if (cmd->cmdsize < sizeof(*cmd) || cmd->cmdsize > end - cursor)
            return false;
        cursor += cmd->cmdsize;
    }
    for (size_t i = 0; i < count; ++i) {
        const auto &guard = guards[i];
        if (!contains(address, size, address + guard.offset, sizeof(guard.bytes)))
            return false;
        auto actual = reinterpret_cast<const uint8_t *>(address + guard.offset);
        for (size_t byte = 0; byte < sizeof(guard.bytes); ++byte) {
            if ((actual[byte] & guard.mask[byte]) != (guard.bytes[byte] & guard.mask[byte]))
                return false;
        }
    }
    return true;
}

static mach_vm_address_t followBranch(mach_vm_address_t address) {
    for (unsigned i = 0; i < 3; ++i) {
        auto bytes = reinterpret_cast<const uint8_t *>(address);
        int32_t offset;
        if (bytes[0] == 0xE9) {
            memcpy(&offset, bytes + 1, sizeof(offset));
            address += 5 + offset;
        } else if (bytes[0] == 0xFF && bytes[1] == 0x25) {
            memcpy(&offset, bytes + 2, sizeof(offset));
            memcpy(&address, bytes + 6 + offset, sizeof(address));
        } else {
            return address;
        }
    }
    return address;
}

static bool patchCopies(KernelPatcher &patcher, mach_vm_address_t address, size_t size, const CopySite *sites, size_t count) {
    if (count > 14)
        return false;
    const auto input = patcher.solveSymbol(KernelPatcher::KernelID, "_copyin");
    const auto output = patcher.solveSymbol(KernelPatcher::KernelID, "_copyout");
    if (!input || !output) {
        patcher.clearError();
        return false;
    }
    int32_t offsets[14];
    for (size_t i = 0; i < count; ++i) {
        const auto &site = sites[i];
        auto call = address + site.offset;
        if (!contains(address, size, call, 5) || *reinterpret_cast<uint8_t *>(call) != 0xE8)
            return false;
        int32_t old;
        memcpy(&old, reinterpret_cast<void *>(call + 1), sizeof(old));
        if (followBranch(call + 5 + old) != followBranch(site.output ? output : input))
            return false;
        auto target = site.output ? reinterpret_cast<mach_vm_address_t>(bridgeCopyOut) : reinterpret_cast<mach_vm_address_t>(bridgeCopyIn);
        target = patcher.branchTarget(target, call + 5);
        if (!target)
            return false;
        auto delta = static_cast<int64_t>(target - (call + 5));
        if (delta < INT32_MIN || delta > INT32_MAX)
            return false;
        offsets[i] = static_cast<int32_t>(delta);
    }
    for (size_t i = 0; i < count; ++i)
        memcpy(reinterpret_cast<void *>(address + sites[i].offset + 1), &offsets[i], sizeof(offsets[i]));
    return true;
}

static bool patchNetworkPower(KernelPatcher &patcher, mach_vm_address_t address, size_t size) {
    const auto call = address + LegacyNetworkDisablePowerCall;
    if (!contains(address, size, call, 5) || *reinterpret_cast<const uint8_t *>(call) != 0xE8)
        return false;
    int32_t previous;
    memcpy(&previous, reinterpret_cast<const void *>(call + 1), sizeof(previous));
    if (followBranch(call + 5 + previous) != followBranch(reinterpret_cast<uintptr_t>(classicRequest)))
        return false;
    const auto target = patcher.branchTarget(reinterpret_cast<uintptr_t>(disableNetworkPower), call + 5);
    if (!target)
        return false;
    const auto delta = static_cast<int64_t>(target - (call + 5));
    if (delta < INT32_MIN || delta > INT32_MAX)
        return false;
    const auto offset = static_cast<int32_t>(delta);
    memcpy(reinterpret_cast<void *>(call + 1), &offset, sizeof(offset));
    return true;
}

static bool patchNetworkCall(KernelPatcher &patcher, mach_vm_address_t address, size_t size, uint32_t offset,
                             uintptr_t original, uintptr_t replacement) {
    const auto call = address + offset;
    if (!contains(address, size, call, 5) || *reinterpret_cast<const uint8_t *>(call) != 0xE8)
        return false;
    int32_t previous;
    memcpy(&previous, reinterpret_cast<const void *>(call + 1), sizeof(previous));
    if (followBranch(call + 5 + previous) != followBranch(original))
        return false;
    const auto target = patcher.branchTarget(replacement, call + 5);
    if (!target)
        return false;
    const auto delta = static_cast<int64_t>(target - (call + 5));
    if (delta < INT32_MIN || delta > INT32_MAX)
        return false;
    const auto displacement = static_cast<int32_t>(delta);
    memcpy(reinterpret_cast<void *>(call + 1), &displacement, sizeof(displacement));
    return true;
}

void Bridge::disable(const char *reason) {
    reject(reason);
}

bool Bridge::prepareImage(LinkedImage &image, size_t index) {
    if (index >= 2 || !image.editable || !activeABI)
        return false;
    KernelPatcher patcher(image);
    patchImage(patcher, index, image.address, image.payload->mappedSize);
    if (index == 0 && !(__atomic_load_n(&state, __ATOMIC_ACQUIRE) & 0x80000000U) &&
        !AWDLCoexistence::prepare(image, awdlCoexistenceEnabled))
        reject("AWDLCoexistencePreparationFailed");
    if (index == 1 && !(__atomic_load_n(&state, __ATOMIC_ACQUIRE) & 0x80000000U) &&
        !RadioPolicy::prepare(image))
        reject("RadioPolicyPreparationFailed");
    if (index == 1 && !(__atomic_load_n(&state, __ATOMIC_ACQUIRE) & 0x80000000U) &&
        !TahoeDMA::prepare(image, tahoeDMAEnabled))
        reject("TahoeDMAPreparationFailed");
    return !(__atomic_load_n(&state, __ATOMIC_ACQUIRE) & 0x80000000U);
}

void Bridge::patchImage(KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size) {
    if (__atomic_load_n(&state, __ATOMIC_ACQUIRE) & 0x80000000U)
        return;
    if (index == 0) {
        if (!validate(address, size, LegacyGuards, arrsize(LegacyGuards))) {
            reject("LegacyBinaryMismatch");
            return;
        }
        getRequest = reinterpret_cast<Ioctl>(patcher.solveSymbol(index, "__ZN17IO80211Controller20apple80211_ioctl_getEP16IO80211InterfaceP23IO80211VirtualInterfaceP23IO80211SkywalkInterfacePv"));
        setRequest = reinterpret_cast<Ioctl>(patcher.solveSymbol(index, "__ZN17IO80211Controller20apple80211_ioctl_setEP16IO80211InterfaceP23IO80211VirtualInterfaceP23IO80211SkywalkInterfacePv"));
        classicController = reinterpret_cast<Controller>(patcher.solveSymbol(index, "__ZN16IO80211Interface13getControllerEv"));
        virtualController = reinterpret_cast<Controller>(patcher.solveSymbol(index, "__ZN23IO80211VirtualInterface13getControllerEv"));
        classicName = reinterpret_cast<BSDName>(patcher.solveSymbol(index, "__ZN16IO80211Interface10getBSDNameEv"));
        virtualName = reinterpret_cast<BSDName>(patcher.solveSymbol(index, "__ZN23IO80211VirtualInterface10getBSDNameEv"));
        updateVirtualFlags = reinterpret_cast<InterfaceFlags>(patcher.solveSymbol(index,
            "__ZN23IO80211VirtualInterface18handleSIOCSIFFLAGSEPKc"));
        skywalkName = reinterpret_cast<BSDName>(patcher.solveSymbol(index, "__ZN23IO80211SkywalkInterface10getBSDNameEv"));
        classicCommand = reinterpret_cast<PerformCommand>(patcher.solveSymbol(index, "__ZN16IO80211Interface14performCommandEP19IONetworkControllermPvS2_"));
        classicRequest = reinterpret_cast<DriverRequest>(patcher.solveSymbol(index, "__ZN17IO80211Controller22apple80211RequestIoctlEjiP16IO80211InterfacePv"));
        if (!getRequest || !setRequest || !classicController || !virtualController || !classicName || !virtualName || !updateVirtualFlags || !skywalkName || !classicCommand || !classicRequest) {
            patcher.clearError();
            reject("LegacySymbolsMissing");
            return;
        }
        KernelPatcher::RouteRequest routes[] = {
            {"__ZN16IO80211Interface13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient", newClassicClient, originalClassicClient},
            {"__ZN23IO80211VirtualInterface13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient", newVirtualClient, originalVirtualClient},
            {"__ZN16IO80211Interface27IO80211InterfacePostMessageEjPvm", postClassic, originalClassicEvent},
            {"__ZN23IO80211VirtualInterface27IO80211InterfacePostMessageEjPvm", postVirtual, originalVirtualEvent},
            {"__ZN21IO80211InfraInterface19postMessageInternalEjPvm", postInfra, originalInfraEvent},
            {"__ZN16IO80211Interface25updateCountryCodePropertyEb", updateCountryProperty, originalCountryProperty},
            {"__ZL22setIBSS_Or_HostAP_ModeP17IO80211ControllerP16IO80211InterfaceP23IO80211VirtualInterfaceP21IO80211InfraInterfaceP13apple80211reqb",
             setNetworkMode, originalNetworkModeSet},
        };
        if (!patcher.routeMultipleLong(index, routes, address, size) ||
            !patchCopies(patcher, address, size, LegacyCopySites, arrsize(LegacyCopySites)) ||
            !patchNetworkPower(patcher, address, size)) {
            patcher.clearError();
            reject("LegacyRoutingFailed");
            return;
        }
        __atomic_fetch_or(&state, 1U, __ATOMIC_RELEASE);
    } else if (index == 1) {
        const bool original = abi().backend == AirPortBackend::Original;
        const auto guards = original ? AirPortOriginalGuards : AirPortGuards;
        const auto guardCount = original ? arrsize(AirPortOriginalGuards) : arrsize(AirPortGuards);
        const auto copies = original ? AirPortOriginalCopySites : AirPortCopySites;
        const auto copyCount = original ? arrsize(AirPortOriginalCopySites) : arrsize(AirPortCopySites);
        if (!validate(address, size, guards, guardCount)) {
            reject(original ? "OriginalAirPortBinaryMismatch" : "TahoeAirPortBinaryMismatch");
            return;
        }
        originalCipherKeySet = reinterpret_cast<CipherKeySet>(patcher.solveSymbol(index,
            "__ZN15AirPort_BrcmNIC13setCIPHER_KEYEP8OSObjectP14apple80211_key"));
        setIovar = reinterpret_cast<IovarSet>(patcher.solveSymbol(index,
            "__ZN15AirPort_BrcmNIC13wlIovarSetIntEPKci"));
        sendFirmwareRequest = reinterpret_cast<FirmwareRequest>(patcher.solveSymbol(index,
            "__ZN15AirPort_BrcmNIC7wlIoctlEjPvmbP8OSObject"));
        originalCipherCalculate = reinterpret_cast<CipherCalculate>(patcher.solveSymbol(index,
            "__ZN15AirPort_BrcmNIC12wl_calc_wsecEP8OSObject"));
        firmwareVirtualInterface = reinterpret_cast<VirtualFirmwareInterface>(patcher.solveSymbol(index,
            "__ZNK15AirPort_BrcmNIC9getVirtIfEP8OSObject"));
        firmwareBSS = reinterpret_cast<FirmwareBSS>(patcher.solveSymbol(index, "_wlc_bsscfg_find_by_wlcif"));
        createAuthenticator = reinterpret_cast<AuthenticatorCreate>(patcher.solveSymbol(index, "_wlc_authenticator_attach"));
        setAKMPolicy = reinterpret_cast<AKMPolicySet>(patcher.solveSymbol(index, "_wlc_sae_process_akm_type"));
        validateNetworkMAC = reinterpret_cast<MACValidate>(patcher.solveSymbol(index, "_wlc_validate_mac_pub"));
        if (!originalCipherKeySet || !setIovar || !sendFirmwareRequest || !originalCipherCalculate ||
            !firmwareVirtualInterface || !firmwareBSS || !createAuthenticator || !setAKMPolicy ||
            !validateNetworkMAC ||
            !patchNetworkCall(patcher, address, size,
                original ? AirPortOriginalNetworkCipherCall : AirPortNetworkCipherCall,
                reinterpret_cast<uintptr_t>(originalCipherKeySet), reinterpret_cast<uintptr_t>(installNetworkCipher)) ||
            !patchNetworkCall(patcher, address, size,
                original ? AirPortOriginalNetworkSSIDCipherCall : AirPortNetworkSSIDCipherCall,
                reinterpret_cast<uintptr_t>(originalCipherCalculate), reinterpret_cast<uintptr_t>(calculateNetworkCipher))) {
            patcher.clearError();
            reject("NetworkCipherRoutingFailed");
            return;
        }
        if (!patchCopies(patcher, address, size, copies, copyCount)) {
            patcher.clearError();
            reject("AirPortCopyRoutingFailed");
            return;
        }
        getCountryCode = reinterpret_cast<CountryCodeQuery>(patcher.solveSymbol(index,
            "__ZN15AirPort_BrcmNIC15getCOUNTRY_CODEEP8OSObjectP28apple80211_country_code_data"));
        if (!getCountryCode) {
            patcher.clearError();
            reject("CountryCodeSymbolMissing");
            return;
        }
        KernelPatcher::RouteRequest routes[] = {
            {"__ZN15AirPort_BrcmNIC19getHARDWARE_VERSIONEP8OSObjectP23apple80211_version_data",
             getHardwareVersion, originalHardwareVersion},
            {"__ZN15AirPort_BrcmNIC9getLOCALEEP8OSObjectP22apple80211_locale_data", getLocale, originalLocale},
        };
        if (!patcher.routeMultipleLong(index, routes, address, size)) {
            patcher.clearError();
            reject("AirPortQueryRoutingFailed");
            return;
        }
        __atomic_fetch_or(&state, 4U, __ATOMIC_RELEASE);
    }
    if (ready()) {
        __atomic_store_n(&failure, "ReadyForHardwareValidation", __ATOMIC_RELEASE);
        SYSLOG("bridge", "%s ABI bridge ready", abi().name);
    }
}

void Bridge::initialize() {
    int value = 0;
    awdlCoexistenceEnabled = PE_parse_boot_argn("-sbcmawdlcc", &value, sizeof(value));
    tahoeDMAEnabled = PE_parse_boot_argn("-sbcmdma", &value, sizeof(value));
    activeABI = userABIForKernel(static_cast<uint32_t>(getKernelVersion()));
    if (!activeABI) {
        reject("UnsupportedKernel");
        return;
    }
    contextLock = IOSimpleLockAlloc();
    hubLock = IOSimpleLockAlloc();
    pending = static_cast<PendingEvent *>(IOMalloc(sizeof(PendingEvent) * PendingCapacity));
    eventCall = thread_call_allocate_with_options(drainEvents, nullptr, THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
    if (!contextLock || !hubLock || !pending || !eventCall) {
        reject("AllocationFailed");
        return;
    }
}

void Bridge::trackController(IOService *controller) {
    if (!controller || !hubLock)
        return;
    const auto interruptState = IOSimpleLockLockDisableInterrupt(hubLock);
    if (!observedController) {
        controller->retain();
        observedController = controller;
    }
    IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
}

void Bridge::publish(IOService *service) {
    RadioPolicy::publish(service);
    TahoeDMA::publish(service);
    AWDLCoexistence::publish(service);
    service->setProperty("Status", __atomic_load_n(&failure, __ATOMIC_ACQUIRE));
    service->setProperty("PatchState", __atomic_load_n(&state, __ATOMIC_ACQUIRE), 32);
    service->setProperty("SupportedKernel", "23.x / 24.x / 25.x / 27.x");
    service->setProperty("AdapterVersion", "1.2.2");
    service->setProperty("NativePowerDomainPatched", false);
    IOService *controller = nullptr;
    if (hubLock) {
        const auto interruptState = IOSimpleLockLockDisableInterrupt(hubLock);
        controller = observedController;
        if (controller)
            controller->retain();
        IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
    }
    if (controller) {
        auto controllerLoop = controller->getWorkLoop();
        if (controllerLoop && controller->getProperty("SimpleBCMHostAPActive") == kOSBooleanTrue)
            controllerLoop->runAction(maintainNetworkMAC, controller);
        else if (controllerLoop && controller->getProperty("SimpleBCMHostAPRestoreAWDL") == kOSBooleanTrue)
            controllerLoop->runAction(restoreNetworkAWDL, controller);
        service->setProperty("WirelessControllerIdentity", controller->metaCast("AirPortDriver") ? "AirPortDriver" : "Unrecognized");
        auto bytes = reinterpret_cast<const uint8_t *>(controller);
        service->setProperty("BrcmPowerState", __atomic_load_n(reinterpret_cast<const uint64_t *>(bytes + 6800), __ATOMIC_RELAXED), 64);
        service->setProperty("BrcmRequestedPowerState", __atomic_load_n(reinterpret_cast<const uint64_t *>(bytes + 6808), __ATOMIC_RELAXED), 64);
        service->setProperty("BrcmPowerTransition", __atomic_load_n(bytes + 6816, __ATOMIC_RELAXED) != 0);
        controller->release();
    }
    service->setProperty("ActiveABI", activeABI ? activeABI->name : "Unsupported");
    service->setProperty("AirPortBackend", !activeABI ? "Unsupported" : activeABI->backend == AirPortBackend::Original ? "Original" : "Tahoe");
    service->setProperty("DriverKitBackend", false);
    struct Metric { const char *name; uint64_t *value; } metrics[] = {
        {"Opens", &counters.opens}, {"DeniedOpens", &counters.denied},
        {"Commands", &counters.commands}, {"CommandErrors", &counters.errors},
        {"Events", &counters.events}, {"DroppedEvents", &counters.dropped},
        {"Notifications", &counters.notifications}, {"NotificationErrors", &counters.notificationErrors},
        {"ScanRecords", &counters.scanRecords}, {"ScanDoneEvents", &counters.scanDoneEvents},
        {"ScanDoneRecords", &counters.scanDoneRecords}, {"AssociationRequests", &counters.associationRequests},
        {"AssociationAccepted", &counters.associationAccepted},
        {"DriverAvailabilityEvents", &counters.availabilityEvents},
        {"DriverAvailabilityReplays", &counters.availabilityReplays},
        {"AssociationEvents", &counters.associationEvents},
        {"AssociationEventConversions", &counters.associationEventConversions},
        {"AssociationEventReadErrors", &counters.associationEventReadErrors},
        {"PowerAvailabilityEvents", &counters.powerAvailabilityEvents},
    };
    for (const auto &metric : metrics)
        service->setProperty(metric.name, __atomic_load_n(metric.value, __ATOMIC_RELAXED), 64);
    for (size_t i = 0; i < arrsize(counters.selectors); ++i) {
        char name[24];
        snprintf(name, sizeof(name), "Selector%u", static_cast<unsigned>(i));
        service->setProperty(name, __atomic_load_n(&counters.selectors[i], __ATOMIC_RELAXED), 64);
    }
    service->setProperty("LastRequest", __atomic_load_n(&counters.lastRequest, __ATOMIC_RELAXED), 32);
    service->setProperty("LastResult", __atomic_load_n(&counters.lastResult, __ATOMIC_RELAXED), 32);
    service->setProperty("LastAssociationResult", __atomic_load_n(&counters.lastAssociationResult, __ATOMIC_RELAXED), 32);
    service->setProperty("LastAssociationEventLength", __atomic_load_n(&counters.lastAssociationEventLength, __ATOMIC_RELAXED), 32);
    service->setProperty("LastAssociationEventReadResult", __atomic_load_n(&counters.lastAssociationEventReadResult, __ATOMIC_RELAXED), 32);
    service->setProperty("LastAvailabilityReadResult", __atomic_load_n(&counters.lastAvailabilityReadResult, __ATOMIC_RELAXED), 32);
}

}
