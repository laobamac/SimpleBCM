//
//  SimpleBCM.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "Bridge.hpp"
#include "Loader.hpp"
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>
#include <pexpert/pexpert.h>
#include <mach/kmod.h>

bool simpleBCMDebug;
static bool enabled;
static bool initialized;
static uint32_t loadDelayMS;

static uint32_t readLoadDelay() {
    uint64_t value = UINT64_MAX;
    if (!PE_parse_boot_argn("sbcmdelay", &value, sizeof(value)))
        return 0;
    if (value > UINT32_MAX) {
        SYSLOG("loader", "invalid sbcmdelay; expected 0..4294967295 milliseconds, using 0");
        return 0;
    }
    return static_cast<uint32_t>(value);
}

class SimpleBCM final : public IOService {
    OSDeclareDefaultStructors(SimpleBCM)
public:
    IOService *probe(IOService *provider, SInt32 *score) override {
        return enabled ? IOService::probe(provider, score) : nullptr;
    }
    bool start(IOService *provider) override {
        if (!IOService::start(provider))
            return false;
        if (!loadDelayMS)
            bcm::startPayloads();
        loop = IOWorkLoop::workLoop();
        timer = IOTimerEventSource::timerEventSource(this, tick);
        timerAttached = loop && timer && loop->addEventSource(timer) == kIOReturnSuccess;
        running = timerAttached;
        loadPending = loadDelayMS && timerAttached;
        loadDelayState = loadDelayMS ? (timerAttached ? "Waiting" : "SchedulingFailed") : "Disabled";
        update();
        registerService();
        if (timerAttached) {
            if (loadPending)
                SYSLOG("loader", "deferring embedded module loading by %u ms", loadDelayMS);
            auto result = timer->setTimeoutMS(loadPending ? loadDelayMS : 1000);
            if (result != kIOReturnSuccess) {
                running = false;
                loadPending = false;
                if (loadDelayMS)
                    loadDelayState = "SchedulingFailed";
                SYSLOG("loader", "timer scheduling failed (0x%08x)", result);
                update();
            }
        } else {
            SYSLOG("loader", "%s", loadDelayMS ? "load delay unavailable; embedded modules not started" :
                "periodic diagnostics unavailable");
        }
        return true;
    }
    void stop(IOService *provider) override {
        cancelTimer();
        update();
        IOService::stop(provider);
    }
    void free() override {
        cancelTimer();
        if (timer)
            timer->release();
        if (loop)
            loop->release();
        IOService::free();
    }
private:
    IOWorkLoop *loop {nullptr};
    IOTimerEventSource *timer {nullptr};
    bool timerAttached {false};
    bool running {false};
    bool loadPending {false};
    const char *loadDelayState {"Disabled"};
    void cancelTimer() {
        if (loop)
            loop->runAction(cancel, this);
        else
            cancel(this, nullptr, nullptr, nullptr, nullptr);
    }
    static IOReturn cancel(OSObject *owner, void *, void *, void *, void *) {
        auto self = static_cast<SimpleBCM *>(owner);
        self->running = false;
        if (self->loadPending) {
            self->loadPending = false;
            self->loadDelayState = "Cancelled";
        }
        if (self->timer) {
            self->timer->disable();
            self->timer->cancelTimeout();
            if (self->timerAttached && self->loop) {
                self->loop->removeEventSource(self->timer);
                self->timerAttached = false;
            }
        }
        return kIOReturnSuccess;
    }
    void update() {
        bcm::Bridge::publish(this);
        bcm::publishLoader(this);
        setProperty("LoadDelayMS", loadDelayMS, 32);
        setProperty("LoadDelayState", loadDelayState);
    }
    static void tick(OSObject *owner, IOTimerEventSource *source) {
        auto self = static_cast<SimpleBCM *>(owner);
        if (!self->running)
            return;
        if (self->loadPending) {
            self->loadPending = false;
            self->loadDelayState = "Loading";
            self->update();
            SYSLOG("loader", "load delay elapsed; starting embedded modules");
            self->loadDelayState = bcm::startPayloads() ? "Completed" : "Failed";
        }
        self->update();
        auto result = source->setTimeoutMS(1000);
        if (result != kIOReturnSuccess) {
            self->running = false;
            SYSLOG("loader", "periodic diagnostics scheduling failed (0x%08x)", result);
        }
    }
};

OSDefineMetaClassAndStructors(SimpleBCM, IOService)

extern "C" kern_return_t SimpleBCM_kern_start(kmod_info_t *, void *) {
    int value = 0;
    enabled = !PE_parse_boot_argn("-simplebcmoff", &value, sizeof(value));
#ifdef DEBUG
    simpleBCMDebug = true;
#else
    simpleBCMDebug = PE_parse_boot_argn("-simplebcmdbg", &value, sizeof(value));
#endif
    if (enabled) {
        initialized = true;
        loadDelayMS = readLoadDelay();
        bcm::preparePayloads();
    }
    return KERN_SUCCESS;
}

extern "C" kern_return_t SimpleBCM_kern_stop(kmod_info_t *, void *) {
    return initialized ? KERN_FAILURE : KERN_SUCCESS;
}
