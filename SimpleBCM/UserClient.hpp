//
//  UserClient.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/9/15.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_USER_CLIENT_HPP
#define SIMPLEBCM_USER_CLIENT_HPP

#include "Bridge.hpp"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOWorkLoop.h>

class BCM80211UserClient final : public IOUserClient {
    OSDeclareDefaultStructors(BCM80211UserClient)
public:
    static IOReturn create(IOService *provider, task_t task, void *token,
                           OSDictionary *properties, bcm::InterfaceKind kind,
                           IOUserClient **result);
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
    void free() override;
    IOReturn clientClose() override;
    IOReturn clientDied() override;
    IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *arguments,
                            IOExternalMethodDispatch *dispatch = nullptr,
                            OSObject *target = nullptr, void *reference = nullptr) override;
    IOReturn clientMemoryForType(UInt32 type, IOOptionBits *options,
                                IOMemoryDescriptor **memory) override;
    void receive(IOService *controller, const char *name, uint32_t event,
                 const void *payload, size_t length, uint64_t seconds, uint64_t microseconds, uint64_t serial);
private:
    bcm::Endpoint endpoint {};
    task_t ownerTask {nullptr};
    IOWorkLoop *workLoop {nullptr};
    IOCommandGate *commandGate {nullptr};
    IOLock *eventLock {nullptr};
    IOBufferMemoryDescriptor *ringMemory {nullptr};
    IOBufferMemoryDescriptor *stateMemory {nullptr};
    OSAsyncReference64 asyncReference {};
    bcm::EventFilter filter {};
    uint32_t writeOffset {0};
    uint16_t sequence {0};
    uint64_t monitorSerial {0};
    bool subscribed {false};
    bool monitoring {false};
    bool registered {false};
    bool gateAdded {false};
    bool closed {false};

    static IOReturn dispatchAction(OSObject *owner, void *selector, void *arguments, void *, void *);
    static IOReturn closeAction(OSObject *owner, void *, void *, void *, void *);
    IOReturn dispatch(uint32_t selector, IOExternalMethodArguments *arguments);
    IOReturn runCommand(IOExternalMethodArguments *arguments, size_t capacity);
    IOReturn startMonitor();
    IOReturn subscribe(IOExternalMethodArguments *arguments);
    void notifyAvailable();
    void close();
    bool entitled(const char *entitlement) const;
};

#endif
