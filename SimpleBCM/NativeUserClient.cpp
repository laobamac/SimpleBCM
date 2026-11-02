//
//  NativeUserClient.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "NativeUserClient.hpp"
#include <IOKit/IOLib.h>
#include "NativeProfile.hpp"
#include "Payload.hpp"
#include <libkern/c++/OSBoolean.h>

namespace bcm {

struct ClientContext {
    IOUserClient *implementation;
    uint32_t profile;
    uint32_t closed;
};

static uintptr_t clientViews[2][302];
static bool prepared;

static ClientContext *context(IOUserClient *self) {
    ClientContext *result;
    memcpy(&result, reinterpret_cast<uint8_t *>(self) + 224, sizeof(result));
    return result;
}

static void setContext(IOUserClient *self, ClientContext *value) {
    memcpy(reinterpret_cast<uint8_t *>(self) + 224, &value, sizeof(value));
}

template<typename Method> static Method native(uint32_t index) {
    return reinterpret_cast<Method>(bcmNativeImports[index]);
}

static IOReturn close(IOUserClient *self, bool died) {
    auto state = context(self);
    if (!state || __atomic_exchange_n(&state->closed, 1U, __ATOMIC_ACQ_REL))
        return kIOReturnSuccess;
    return died ? state->implementation->clientDied() : state->implementation->clientClose();
}

static IOReturn clientClose(IOUserClient *self) {
    auto result = close(self, false);
    if (!self->isInactive())
        self->terminate();
    return result;
}

static IOReturn clientDied(IOUserClient *self) {
    auto result = close(self, true);
    if (!self->isInactive())
        self->terminate();
    return result;
}

static bool start(IOUserClient *self, IOService *provider) {
    return self->IOUserClient::start(provider);
}

static void stop(IOUserClient *self, IOService *provider) {
    close(self, false);
    self->IOUserClient::stop(provider);
}

static bool init(IOUserClient *self, task_t task, void *token, uint32_t type, OSDictionary *properties) {
    return self->IOUserClient::initWithTask(task, token, type, properties);
}

static void destruct(IOUserClient *self) {
    const auto profile = context(self)->profile;
    native<void (*)(IOUserClient *)>(nativeClientProfiles[profile].destructor)(self);
}

static void deleteObject(IOUserClient *self) {
    destruct(self);
    IOFree(self, 232);
}

static void freeObject(IOUserClient *self) {
    auto state = context(self);
    close(self, false);
    native<void (*)(IOUserClient *)>(nativeClientProfiles[state->profile].free)(self);
    state->implementation->release();
    IOFree(state, sizeof(*state));
}

static IOUserClient *activeImplementation(IOUserClient *self) {
    auto state = context(self);
    return state && !__atomic_load_n(&state->closed, __ATOMIC_ACQUIRE) ? state->implementation : nullptr;
}

static IOReturn externalMethod(IOUserClient *self, uint32_t selector, IOExternalMethodArguments *arguments,
                               IOExternalMethodDispatch *dispatch, OSObject *target, void *reference) {
    auto implementation = activeImplementation(self);
    return implementation ? implementation->externalMethod(selector, arguments, dispatch,
        target == self ? implementation : target, reference) : kIOReturnNotOpen;
}

static IOReturn clientMemory(IOUserClient *self, uint32_t type, IOOptionBits *options,
                             IOMemoryDescriptor **memory) {
    auto implementation = activeImplementation(self);
    return implementation ? implementation->clientMemoryForType(type, options, memory) : kIOReturnNotOpen;
}

static IOReturn notification64(IOUserClient *self, mach_port_t port, uint32_t type, uint64_t reference) {
    auto implementation = activeImplementation(self);
    return implementation ? implementation->registerNotificationPort(port, type, reference) : kIOReturnNotOpen;
}

static IOReturn notification32(IOUserClient *self, mach_port_t port, uint32_t type, uint32_t reference) {
    auto implementation = activeImplementation(self);
    return implementation ? implementation->registerNotificationPort(port, type, reference) : kIOReturnNotOpen;
}

static IOService *getService(IOUserClient *self) {
    return context(self)->implementation->getService();
}

bool prepareNativeUserClients() {
    if (prepared)
        return true;
    if (!nativeSystem)
        return false;
    for (uint32_t i = 0; i < 2; ++i) {
        const auto &profile = nativeClientProfiles[i];
        if (profile.slots != 300 || profile.constructor >= nativeImportCount ||
            profile.destructor >= nativeImportCount || profile.free >= nativeImportCount ||
            profile.meta >= nativeImportCount || profile.vtable >= nativeImportCount ||
            native<const OSMetaClass *>(profile.meta)->getClassSize() != 224)
            return false;
        auto view = clientViews[i];
        memcpy(view, native<const uintptr_t *>(profile.vtable), sizeof(clientViews[i]));
        view[2] = reinterpret_cast<uintptr_t>(destruct);
        view[3] = reinterpret_cast<uintptr_t>(deleteObject);
        view[2 + 0x90 / 8] = reinterpret_cast<uintptr_t>(freeObject);
        view[2 + 0x5c0 / 8] = reinterpret_cast<uintptr_t>(start);
        view[2 + 0x5c8 / 8] = reinterpret_cast<uintptr_t>(stop);
        view[2 + 0x850 / 8] = reinterpret_cast<uintptr_t>(externalMethod);
        view[2 + 0x858 / 8] = reinterpret_cast<uintptr_t>(notification64);
        view[2 + 0x8e0 / 8] = reinterpret_cast<uintptr_t>(init);
        view[2 + 0x8f0 / 8] = reinterpret_cast<uintptr_t>(clientClose);
        view[2 + 0x8f8 / 8] = reinterpret_cast<uintptr_t>(clientDied);
        view[2 + 0x900 / 8] = reinterpret_cast<uintptr_t>(getService);
        view[2 + 0x908 / 8] = reinterpret_cast<uintptr_t>(notification32);
        view[2 + 0x920 / 8] = reinterpret_cast<uintptr_t>(clientMemory);
    }
    prepared = true;
    return true;
}

IOReturn wrapNativeUserClient(IOReturn status, task_t task, void *token, uint32_t type,
                              OSDictionary *properties, IOUserClient **result) {
    if (status != kIOReturnSuccess || !result || !*result)
        return status;
    auto implementation = *result;
    uint32_t profile;
    if (implementation->metaCast("BCM80211UserClient"))
        profile = 0;
    else if (implementation->metaCast("SB80211AsyncEventUserClient"))
        profile = 1;
    else
        return status;
    *result = nullptr;
    auto state = prepared ? static_cast<ClientContext *>(IOMalloc(sizeof(ClientContext))) : nullptr;
    auto front = state ? static_cast<IOUserClient *>(IOMalloc(232)) : nullptr;
    if (!front) {
        if (state)
            IOFree(state, sizeof(*state));
        implementation->clientClose();
        implementation->release();
        return prepared ? kIOReturnNoMemory : kIOReturnNotReady;
    }
    *state = {implementation, profile, 0};
    bzero(static_cast<void *>(front), 232);
    const auto &spec = nativeClientProfiles[profile];
    auto meta = native<const OSMetaClass *>(spec.meta);
    native<void (*)(IOUserClient *, const OSMetaClass *)>(spec.constructor)(front, meta);
    setContext(front, state);
    *reinterpret_cast<uintptr_t **>(front) = clientViews[profile] + 2;
    meta->instanceConstructed();
    if (!init(front, task, token, type, properties)) {
        front->release();
        return kIOReturnError;
    }
    front->setProperty("IOUserClientDefaultLocking", kOSBooleanTrue);
    if (front->attach(implementation)) {
        if (front->start(implementation)) {
            *result = front;
            return kIOReturnSuccess;
        }
        front->detach(implementation);
    }
    front->release();
    return kIOReturnError;
}

}
