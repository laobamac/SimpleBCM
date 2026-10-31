//
//  UserClient.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/9/11.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "UserClient.hpp"
#include <libkern/c++/OSBoolean.h>
#include <sys/errno.h>

OSDefineMetaClassAndStructors(IO80211APIUserClient, IOUserClient)

bool IO80211APIUserClient::entitled(const char *entitlement) const {
    auto value = copyClientEntitlement(ownerTask, entitlement);
    const bool allowed = value == kOSBooleanTrue;
    if (value)
        value->release();
    return allowed;
}

IOReturn IO80211APIUserClient::create(IOService *provider, task_t task, void *token,
                                   OSDictionary *properties, bcm::InterfaceKind kind,
                                   IOUserClient **result) {
    if (!result || !task)
        return kIOReturnBadArgument;
    *result = nullptr;
    auto client = new IO80211APIUserClient;
    if (!client)
        return kIOReturnNoMemory;
    client->ownerTask = task;
    if (!client->initWithTask(task, token, 0, properties)) {
        client->release();
        return kIOReturnError;
    }
    if (!client->entitled("com.apple.wlan.authentication")) {
        __atomic_fetch_add(&bcm::counters.denied, 1ULL, __ATOMIC_RELAXED);
        client->release();
        return kIOReturnNotPrivileged;
    }
    if (!bcm::Bridge::identify(provider, kind, client->endpoint)) {
        client->release();
        return kIOReturnUnsupported;
    }
    client->endpoint.controller->retain();
    client->setProperty("IOUserClientDefaultLocking", kOSBooleanTrue);
    if (client->attach(provider)) {
        if (client->start(provider)) {
            __atomic_fetch_add(&bcm::counters.opens, 1ULL, __ATOMIC_RELAXED);
            *result = client;
            return kIOReturnSuccess;
        }
        client->detach(provider);
    }
    client->release();
    return kIOReturnError;
}

bool IO80211APIUserClient::start(IOService *provider) {
    if (!IOUserClient::start(provider))
        return false;
    eventLock = IOLockAlloc();
    workLoop = endpoint.controller->getWorkLoop();
    if (workLoop)
        workLoop->retain();
    commandGate = IOCommandGate::commandGate(this);
    filter.all = 1;
    if (!eventLock || !workLoop || !commandGate)
        return false;
    if (workLoop->addEventSource(commandGate) != kIOReturnSuccess)
        return false;
    gateAdded = true;
    registered = bcm::Bridge::addClient(this);
    return registered;
}

void IO80211APIUserClient::close() {
    if (!eventLock)
        return;
    IOLockLock(eventLock);
    closed = true;
    monitoring = false;
    if (subscribed) {
        releaseAsyncReference64(asyncReference);
        bzero(asyncReference, sizeof(asyncReference));
        subscribed = false;
    }
    IOLockUnlock(eventLock);
    if (registered) {
        registered = false;
        bcm::Bridge::removeClient(this);
    }
}

IOReturn IO80211APIUserClient::closeAction(OSObject *owner, void *, void *, void *, void *) {
    static_cast<IO80211APIUserClient *>(owner)->close();
    return kIOReturnSuccess;
}

IOReturn IO80211APIUserClient::clientClose() {
    if (commandGate && gateAdded)
        commandGate->runAction(closeAction);
    else
        close();
    if (!isInactive())
        terminate();
    return kIOReturnSuccess;
}

IOReturn IO80211APIUserClient::clientDied() {
    return clientClose();
}

void IO80211APIUserClient::stop(IOService *provider) {
    if (commandGate && gateAdded) {
        commandGate->runAction(closeAction);
        workLoop->removeEventSource(commandGate);
        gateAdded = false;
    } else {
        close();
    }
    IOUserClient::stop(provider);
}

void IO80211APIUserClient::free() {
    close();
    if (commandGate) {
        if (gateAdded && workLoop)
            workLoop->removeEventSource(commandGate);
        commandGate->release();
    }
    if (workLoop)
        workLoop->release();
    if (ringMemory)
        ringMemory->release();
    if (stateMemory)
        stateMemory->release();
    if (eventLock)
        IOLockFree(eventLock);
    if (endpoint.controller)
        endpoint.controller->release();
    IOUserClient::free();
}

IOReturn IO80211APIUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
                                           IOExternalMethodDispatch *, OSObject *, void *) {
    if (!arguments || !commandGate || !gateAdded || selector >= bcm::Bridge::abi().selectorCount)
        return kIOReturnBadArgument;
    __atomic_fetch_add(&bcm::counters.selectors[selector], 1ULL, __ATOMIC_RELAXED);
    return commandGate->runAction(dispatchAction, reinterpret_cast<void *>(static_cast<uintptr_t>(selector)), arguments);
}

IOReturn IO80211APIUserClient::dispatchAction(OSObject *owner, void *selector, void *arguments, void *, void *) {
    return static_cast<IO80211APIUserClient *>(owner)->dispatch(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(selector)),
                                                            static_cast<IOExternalMethodArguments *>(arguments));
}

IOReturn IO80211APIUserClient::dispatch(uint32_t selector, IOExternalMethodArguments *arguments) {
    if (closed || isInactive() || !bcm::Bridge::ready())
        return kIOReturnNotOpen;
    const auto method = static_cast<bcm::Selector>(selector);
    if (arguments->scalarOutputCount || arguments->scalarInputCount != (method == bcm::Selector::MapUserBuffer ? 2U : 0U))
        return kIOReturnBadArgument;
    if (method == bcm::Selector::Command || method == bcm::Selector::LargeCommand) {
        if (arguments->asyncReferenceCount)
            return kIOReturnBadArgument;
        return runCommand(arguments, method == bcm::Selector::Command ? bcm::CommandCapacity : bcm::LargeCommandCapacity);
    }
    if (arguments->structureInputSize || arguments->structureInputDescriptor)
        return kIOReturnBadArgument;
    if (method != bcm::Selector::Subscribe && arguments->asyncReferenceCount)
        return kIOReturnBadArgument;
    switch (method) {
        case bcm::Selector::UseIOUC:
        case bcm::Selector::UseEventPipe:
        case bcm::Selector::DriverKitSupported: {
            if (!arguments->structureOutput || arguments->structureOutputSize != 1 || arguments->structureOutputDescriptor)
                return kIOReturnBadArgument;
            auto value = static_cast<uint8_t *>(arguments->structureOutput);
            *value = method != bcm::Selector::DriverKitSupported;
            return kIOReturnSuccess;
        }
        case bcm::Selector::Subscribe:
        case bcm::Selector::MonitorStart:
        case bcm::Selector::MonitorStop:
        case bcm::Selector::MapUserBuffer:
            if (arguments->structureOutputSize || arguments->structureOutputDescriptor)
                return kIOReturnBadArgument;
            break;
        default:
            return kIOReturnUnsupported;
    }
    switch (method) {
        case bcm::Selector::Subscribe:
            return subscribe(arguments);
        case bcm::Selector::MonitorStart:
            return startMonitor();
        case bcm::Selector::MonitorStop:
            IOLockLock(eventLock);
            monitoring = false;
            IOLockUnlock(eventLock);
            return kIOReturnSuccess;
        case bcm::Selector::MapUserBuffer:
            return kIOReturnUnsupported;
        default:
            return kIOReturnUnsupported;
    }
}

static IOReturn runRoamProfiles(const bcm::Endpoint &endpoint, bool set, bcm::LegacyRequest &request,
                               uint8_t *shadow, size_t capacity) {
    uint8_t profiles[bcm::NativeRoamProfileSize] {};
    if (set)
        memcpy(profiles, shadow, sizeof(profiles));
    IOReturn result = kIOReturnBadArgument;
    for (size_t index = 0; index < 2; ++index) {
        auto band = profiles + index * bcm::NativeRoamBandSize;
        if (set) {
            if (!bcm::readUInt32(band + 12))
                continue;
            if (!bcm::prepareRoamBand(request.request, shadow, capacity, band, bcm::NativeRoamBandSize))
                return kIOReturnBadArgument;
        } else {
            bzero(shadow, bcm::LegacyRoamBandSize);
            shadow[0] = 1;
            shadow[4] = static_cast<uint8_t>(2U << index);
            request.request.length = bcm::LegacyRoamBandSize;
        }
        result = static_cast<IOReturn>(bcm::Bridge::command(endpoint, set, request, shadow, capacity));
        if (result != kIOReturnSuccess)
            return result;
        if (!set && !bcm::expandRoamBand(request.request, shadow, capacity, band, bcm::NativeRoamBandSize))
            return kIOReturnOverrun;
    }
    if (!set && result == kIOReturnSuccess) {
        memcpy(shadow, profiles, sizeof(profiles));
        request.request.length = sizeof(profiles);
    }
    return result;
}

IOReturn IO80211APIUserClient::runCommand(IOExternalMethodArguments *arguments, size_t capacity) {
    const auto packetSize = sizeof(bcm::CommandHeader) + capacity + sizeof(bcm::Request);
    const size_t inputSize = arguments->structureInputDescriptor ? arguments->structureInputDescriptor->getLength() : arguments->structureInputSize;
    const size_t outputSize = arguments->structureOutputDescriptor ? arguments->structureOutputDescriptorSize : arguments->structureOutputSize;
    if (inputSize != packetSize || outputSize > capacity ||
        (arguments->structureInputDescriptor && arguments->structureInputSize) ||
        (arguments->structureOutputDescriptor && (arguments->structureOutputSize || outputSize > arguments->structureOutputDescriptor->getLength())) ||
        (!arguments->structureInputDescriptor && !arguments->structureInput) ||
        (!arguments->structureOutputDescriptor && outputSize && !arguments->structureOutput))
        return kIOReturnBadArgument;
    auto packet = static_cast<uint8_t *>(IOMalloc(packetSize));
    if (!packet)
        return kIOReturnNoMemory;
    IOReturn result = kIOReturnBadArgument;
    if (arguments->structureInputDescriptor) {
        auto status = arguments->structureInputDescriptor->prepare(kIODirectionOut);
        if (status != kIOReturnSuccess) {
            IOFree(packet, packetSize);
            return status;
        }
        const auto copied = arguments->structureInputDescriptor->readBytes(0, packet, packetSize);
        status = arguments->structureInputDescriptor->complete(kIODirectionOut);
        if (copied != packetSize || status != kIOReturnSuccess) {
            bzero(packet, packetSize);
            IOFree(packet, packetSize);
            return copied != packetSize ? kIOReturnVMError : status;
        }
    } else {
        memcpy(packet, arguments->structureInput, packetSize);
    }
    auto header = reinterpret_cast<bcm::CommandHeader *>(packet);
    auto shadow = packet + sizeof(*header);
    bcm::LegacyRequest legacy {};
    memcpy(&legacy.request, shadow + capacity, sizeof(legacy.request));
    legacy.pointerSize = 8;
    const auto request = legacy.request.type;
    const bool set = header->command == bcm::SetCommand;
    const bool get = header->command == bcm::GetCommand;
    const auto &abi = bcm::Bridge::abi();
    const bool scalar = get && bcm::Bridge::isScalarGet(static_cast<uint32_t>(request));
    const bool scanResult = get && request == bcm::ScanResultRequest && outputSize == abi.scanResultSize;
    const bool capabilities = get && request == bcm::CardCapabilitiesRequest &&
        outputSize == abi.capabilitySize;
    const bool associate = set && request == bcm::AssociateRequest;
    const bool roamProfiles = request == bcm::RoamProfileRequest && abi.roamProfileSize == bcm::NativeRoamProfileSize;
    bool outputPrepared = false;
    __atomic_fetch_add(&bcm::counters.commands, 1ULL, __ATOMIC_RELAXED);
    __atomic_store_n(&bcm::counters.lastRequest, static_cast<uint32_t>(request), __ATOMIC_RELAXED);
    if (associate)
        __atomic_fetch_add(&bcm::counters.associationRequests, 1ULL, __ATOMIC_RELAXED);
    if ((!set && !get) || header->length > capacity ||
        strncmp(legacy.request.interfaceName, endpoint.name, sizeof(endpoint.name)))
        goto done;
    if ((get && request == bcm::ScanResultRequest && !scanResult) ||
        (get && request == bcm::CardCapabilitiesRequest && !capabilities) ||
        (associate && header->length != abi.associateSize) ||
        (set && request == bcm::ScanMultipleRequest && header->length != abi.scanMultipleSize) ||
        (request == bcm::RoamProfileRequest && (get ? outputSize : header->length) != abi.roamProfileSize))
        goto done;
    if (get && request == 0x178 && !entitled("com.apple.private.wifi.IO80211.get_pmk")) {
        result = kIOReturnNotPrivileged;
        goto done;
    }
    if (scalar && outputSize < sizeof(legacy.request.value)) {
        result = kIOReturnNoSpace;
        goto done;
    }
    if (arguments->structureOutputDescriptor && outputSize) {
        const auto status = arguments->structureOutputDescriptor->prepare(kIODirectionIn);
        if (status != kIOReturnSuccess) {
            result = status;
            goto done;
        }
        outputPrepared = true;
    }
    legacy.request.data = reinterpret_cast<uintptr_t>(shadow);
    legacy.request.length = static_cast<uint32_t>(get ? outputSize : header->length);
    if (scanResult && !bcm::prepareScanResult(legacy.request, shadow, capacity, abi))
        goto done;
    if (set && request == bcm::ScanMultipleRequest &&
        !bcm::prepareScanMultiple(legacy.request, shadow, capacity, abi))
        goto done;
    if (associate && !bcm::prepareAssociate(legacy.request, shadow, capacity, abi))
        goto done;
    if (set && abi.filterMonitorEvents && static_cast<uint32_t>(request) == abi.filterMonitorEvents) {
        if (legacy.request.length != sizeof(bcm::EventFilter) || header->length < sizeof(bcm::EventFilter))
            goto done;
        IOLockLock(eventLock);
        memcpy(&filter, shadow, sizeof(filter));
        IOLockUnlock(eventLock);
        result = kIOReturnSuccess;
    } else if (roamProfiles) {
        result = runRoamProfiles(endpoint, set, legacy, shadow, capacity);
    } else {
        result = static_cast<IOReturn>(bcm::Bridge::command(endpoint, set, legacy, shadow, capacity));
    }
    if (result == kIOReturnSuccess) {
        if (capabilities && !bcm::expandCapabilities(legacy.request, shadow, capacity, abi,
                                                   endpoint.kind == bcm::InterfaceKind::Classic)) {
            result = kIOReturnOverrun;
            goto done;
        }
        if (scanResult) {
            if (!bcm::expandScanResult(legacy.request, shadow, capacity, abi)) {
                result = kIOReturnOverrun;
                goto done;
            }
        }
        if (scalar && !bcm::encodeScalarResult(legacy.request, shadow, capacity)) {
            result = kIOReturnNoSpace;
            goto done;
        }
        size_t produced = get ? legacy.request.length : 0;
        if (set && (request == 0x5E || request == 0x125 || request == 0x99))
            produced = legacy.request.length;
        if (produced > capacity) {
            result = kIOReturnOverrun;
            goto done;
        }
        if (produced > outputSize) {
            result = kIOReturnNoSpace;
            goto done;
        }
        if (arguments->structureOutputDescriptor) {
            if (arguments->structureOutputDescriptor->writeBytes(0, shadow, produced) != produced) {
                result = kIOReturnVMError;
                goto done;
            }
            arguments->structureOutputDescriptorSize = static_cast<uint32_t>(produced);
        } else {
            if (produced)
                memcpy(arguments->structureOutput, shadow, produced);
            arguments->structureOutputSize = static_cast<uint32_t>(produced);
        }
    }
done:
    if (outputPrepared) {
        const auto status = arguments->structureOutputDescriptor->complete(kIODirectionIn);
        if (result == kIOReturnSuccess)
            result = status;
    }
    if (scanResult && result == kIOReturnSuccess)
        __atomic_fetch_add(&bcm::counters.scanRecords, 1ULL, __ATOMIC_RELAXED);
    if (associate) {
        __atomic_store_n(&bcm::counters.lastAssociationResult, static_cast<uint32_t>(result), __ATOMIC_RELAXED);
        if (result == kIOReturnSuccess)
            __atomic_fetch_add(&bcm::counters.associationAccepted, 1ULL, __ATOMIC_RELAXED);
    }
    if (result != kIOReturnSuccess) {
        __atomic_fetch_add(&bcm::counters.errors, 1ULL, __ATOMIC_RELAXED);
        DBGLOG("iouc", "%s command 0x%08x request %d length %u output %lu result 0x%08x",
               endpoint.name, header->command, request, header->length,
               static_cast<unsigned long>(outputSize), result);
    }
    __atomic_store_n(&bcm::counters.lastResult, static_cast<uint32_t>(result), __ATOMIC_RELAXED);
    bzero(packet, packetSize);
    IOFree(packet, packetSize);
    return result;
}

IOReturn IO80211APIUserClient::startMonitor() {
    bcm::Bridge::refreshAvailability(endpoint);
    IOLockLock(eventLock);
    if (!ringMemory)
        ringMemory = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task, kIOMemoryKernelUserShared | kIODirectionInOut, bcm::EventCapacity, PAGE_SIZE);
    if (!stateMemory)
        stateMemory = IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task, kIOMemoryKernelUserShared | kIODirectionInOut, PAGE_SIZE, PAGE_SIZE);
    if (!ringMemory || !stateMemory) {
        IOLockUnlock(eventLock);
        return kIOReturnNoMemory;
    }
    if (!monitoring) {
        bzero(ringMemory->getBytesNoCopy(), ringMemory->getLength());
        bzero(stateMemory->getBytesNoCopy(), stateMemory->getLength());
        writeOffset = 0;
        bcm::AvailabilityEvent initial {};
        monitorSerial = bcm::Bridge::copyAvailability(endpoint, initial);
        monitoring = true;
        if (initial.length && filter.accepts(bcm::DriverAvailableEvent)) {
            const auto result = bcm::EventRing::append(static_cast<uint8_t *>(ringMemory->getBytesNoCopy()),
                bcm::EventCapacity, static_cast<bcm::EventState *>(stateMemory->getBytesNoCopy()),
                writeOffset, sequence, endpoint.name, bcm::DriverAvailableEvent,
                initial.payload, initial.length, initial.seconds, initial.microseconds);
            if (result == bcm::RingResult::Written) {
                __atomic_fetch_add(&bcm::counters.availabilityReplays, 1ULL, __ATOMIC_RELAXED);
                if (subscribed)
                    notifyAvailable();
            }
        }
    }
    IOLockUnlock(eventLock);
    return kIOReturnSuccess;
}

IOReturn IO80211APIUserClient::subscribe(IOExternalMethodArguments *arguments) {
    if (!arguments->asyncWakePort || !arguments->asyncReference || arguments->asyncReferenceCount != kOSAsyncRef64Count)
        return kIOReturnBadArgument;
    IOLockLock(eventLock);
    if (subscribed)
        releaseAsyncReference64(asyncReference);
    memcpy(asyncReference, arguments->asyncReference, sizeof(asyncReference));
    subscribed = true;
    if (monitoring && __atomic_load_n(&static_cast<bcm::EventState *>(stateMemory->getBytesNoCopy())->read, __ATOMIC_ACQUIRE) != writeOffset)
        notifyAvailable();
    IOLockUnlock(eventLock);
    return kIOReturnSuccess;
}

IOReturn IO80211APIUserClient::clientMemoryForType(UInt32 type, IOOptionBits *options, IOMemoryDescriptor **memory) {
    if (!options || !memory || !eventLock)
        return kIOReturnBadArgument;
    *memory = nullptr;
    IOLockLock(eventLock);
    auto descriptor = type == 1 ? ringMemory : type == 2 ? stateMemory : nullptr;
    IOReturn status = kIOReturnBadArgument;
    if (!closed && descriptor) {
        *options = type == 1 ? kIOMapReadOnly : 0;
        descriptor->retain();
        *memory = descriptor;
        status = kIOReturnSuccess;
    }
    IOLockUnlock(eventLock);
    return status;
}

void IO80211APIUserClient::receive(IOService *controller, const char *name, uint32_t event,
                                 const void *payload, size_t length, uint64_t seconds, uint64_t microseconds, uint64_t serial) {
    if (endpoint.controller != controller || strncmp(name, endpoint.name, sizeof(endpoint.name)))
        return;
    IOLockLock(eventLock);
    if (closed || !monitoring || serial <= monitorSerial || !filter.accepts(event)) {
        IOLockUnlock(eventLock);
        return;
    }
    const auto result = bcm::EventRing::append(static_cast<uint8_t *>(ringMemory->getBytesNoCopy()), bcm::EventCapacity,
        static_cast<bcm::EventState *>(stateMemory->getBytesNoCopy()), writeOffset, sequence,
        name, event, payload, length, seconds, microseconds);
    if (result != bcm::RingResult::Written) {
        __atomic_fetch_add(&bcm::counters.dropped, 1ULL, __ATOMIC_RELAXED);
    }
    if (event == bcm::ScanDoneEvent && result == bcm::RingResult::Written)
        __atomic_fetch_add(&bcm::counters.scanDoneRecords, 1ULL, __ATOMIC_RELAXED);
    if (subscribed && result != bcm::RingResult::Invalid)
        notifyAvailable();
    IOLockUnlock(eventLock);
}

void IO80211APIUserClient::notifyAvailable() {
    const auto status = sendAsyncResult64WithOptions(asyncReference, bcm::EventNotification, nullptr, 0, kIOUserNotifyOptionCanDrop);
    auto counter = status == kIOReturnSuccess ? &bcm::counters.notifications : &bcm::counters.notificationErrors;
    __atomic_fetch_add(counter, 1ULL, __ATOMIC_RELAXED);
}
