//
//  Bridge.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/9/19.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_BRIDGE_HPP
#define SIMPLEBCM_BRIDGE_HPP

#include "WirelessABI.hpp"
#include <Headers/kern_patcher.hpp>
#include <IOKit/IOService.h>

class IO80211APIUserClient;

namespace bcm {

enum class InterfaceKind : uint8_t { Classic, Virtual, Skywalk };

struct Endpoint {
    IOService *interface;
    IOService *controller;
    InterfaceKind kind;
    char name[16];
};

struct AvailabilityEvent {
    uint64_t seconds;
    uint64_t microseconds;
    uint32_t length;
    uint8_t payload[NativeDriverAvailableSize];
};

struct Counters {
    uint64_t opens;
    uint64_t denied;
    uint64_t commands;
    uint64_t errors;
    uint64_t events;
    uint64_t dropped;
    uint64_t notifications;
    uint64_t notificationErrors;
    uint64_t scanRecords;
    uint64_t scanDoneEvents;
    uint64_t scanDoneRecords;
    uint64_t associationRequests;
    uint64_t associationAccepted;
    uint64_t availabilityEvents;
    uint64_t availabilityReplays;
    uint64_t associationEvents;
    uint64_t associationEventConversions;
    uint64_t associationEventReadErrors;
    uint64_t powerAvailabilityEvents;
    uint32_t lastAssociationEventLength;
    uint32_t lastAssociationEventReadResult;
    uint32_t lastAvailabilityReadResult;
    uint64_t selectors[9];
    uint32_t lastRequest;
    uint32_t lastResult;
    uint32_t lastAssociationResult;
};

extern Counters counters;

class Bridge {
public:
    static void initialize();
    static bool ready();
    static const UserABI &abi();
    static uint64_t copyAvailability(const Endpoint &endpoint, AvailabilityEvent &event);
    static int refreshAvailability(const Endpoint &endpoint);
    static bool isScalarGet(uint32_t request);
    static bool identify(IOService *interface, InterfaceKind kind, Endpoint &endpoint);
    static bool addClient(IO80211APIUserClient *client);
    static void removeClient(IO80211APIUserClient *client);
    static int command(const Endpoint &endpoint, bool set, LegacyRequest &request, void *shadow, size_t size);
    static void publish(IOService *service);
private:
    static void patchKext(void *, KernelPatcher &patcher, size_t index, mach_vm_address_t address, size_t size);
};

}

#endif
