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
#include <IOKit/IOLib.h>
#include <IOKit/IOWorkLoop.h>
#include <libkern/c++/OSData.h>
#include <kern/clock.h>
#include <mach/mach_time.h>
#include <kern/thread_call.h>
#include <mach/thread_act.h>
#include <mach-o/loader.h>
#include <sys/errno.h>
#include <sys/systm.h>

namespace bcm {

Counters counters {};
static uint32_t state;
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

static int getLocale(IOService *controller, OSObject *, LocaleData *output) {
    const auto result = originalLocale(controller, nullptr, output);
    if (result || !output || output->version != 1 || output->locale != LocaleUnknown)
        return result;
    CountryCodeData country {};
    if (!getCountryCode(controller, nullptr, &country))
        resolveLocale(*output, country);
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
    CopyContext context {current_thread(), reinterpret_cast<uintptr_t>(shadow), size, nullptr};
    IOSimpleLockLock(contextLock);
    context.next = contexts;
    contexts = &context;
    IOSimpleLockUnlock(contextLock);
    const auto result = endpoint.kind == InterfaceKind::Classic ?
        classicCommand(endpoint.interface, endpoint.controller, set ? SetCommand : GetCommand, nullptr, &request.request) :
        (set ? setRequest : getRequest)(endpoint.controller, nullptr,
            endpoint.kind == InterfaceKind::Virtual ? endpoint.interface : nullptr,
            endpoint.kind == InterfaceKind::Skywalk ? endpoint.interface : nullptr, &request);
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

void Bridge::disable(const char *reason) {
    reject(reason);
}

bool Bridge::prepareImage(LinkedImage &image, size_t index) {
    if (index >= 2 || !image.editable || !activeABI)
        return false;
    KernelPatcher patcher(image);
    patchImage(patcher, index, image.address, image.payload->mappedSize);
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
        skywalkName = reinterpret_cast<BSDName>(patcher.solveSymbol(index, "__ZN23IO80211SkywalkInterface10getBSDNameEv"));
        classicCommand = reinterpret_cast<PerformCommand>(patcher.solveSymbol(index, "__ZN16IO80211Interface14performCommandEP19IONetworkControllermPvS2_"));
        classicRequest = reinterpret_cast<DriverRequest>(patcher.solveSymbol(index, "__ZN17IO80211Controller22apple80211RequestIoctlEjiP16IO80211InterfacePv"));
        if (!getRequest || !setRequest || !classicController || !virtualController || !classicName || !virtualName || !skywalkName || !classicCommand || !classicRequest) {
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
        };
        if (!patcher.routeMultipleLong(index, routes, address, size) || !patchCopies(patcher, address, size, LegacyCopySites, arrsize(LegacyCopySites))) {
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
    service->setProperty("Status", __atomic_load_n(&failure, __ATOMIC_ACQUIRE));
    service->setProperty("PatchState", __atomic_load_n(&state, __ATOMIC_ACQUIRE), 32);
    service->setProperty("SupportedKernel", "23.x / 24.x / 25.x");
    service->setProperty("AdapterVersion", "1.2.0");
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
