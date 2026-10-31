//
//  Main.cpp
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

class SimpleBCM final : public IOService {
    OSDeclareDefaultStructors(SimpleBCM)
public:
    IOService *probe(IOService *provider, SInt32 *score) override {
        return enabled ? IOService::probe(provider, score) : nullptr;
    }
    bool start(IOService *provider) override {
        if (!IOService::start(provider))
            return false;
        bcm::startPayloads();
        loop = IOWorkLoop::workLoop();
        timer = IOTimerEventSource::timerEventSource(this, tick);
        update();
        if (loop && timer && loop->addEventSource(timer) == kIOReturnSuccess)
            timer->setTimeoutMS(1000);
        else
            SYSLOG("loader", "periodic diagnostics unavailable");
        registerService();
        return true;
    }
    void stop(IOService *provider) override {
        if (timer) {
            timer->cancelTimeout();
            if (loop)
                loop->removeEventSource(timer);
        }
        IOService::stop(provider);
    }
    void free() override {
        if (timer)
            timer->release();
        if (loop)
            loop->release();
        IOService::free();
    }
private:
    IOWorkLoop *loop {nullptr};
    IOTimerEventSource *timer {nullptr};
    void update() {
        bcm::Bridge::publish(this);
        bcm::publishLoader(this);
    }
    static void tick(OSObject *owner, IOTimerEventSource *source) {
        static_cast<SimpleBCM *>(owner)->update();
        source->setTimeoutMS(1000);
    }
};

OSDefineMetaClassAndStructors(SimpleBCM, IOService)

extern "C" kern_return_t SimpleBCM_kern_start(kmod_info_t *, void *) {
    int value = 0;
    enabled = !PE_parse_boot_argn("-simplebcmoff", &value, sizeof(value));
    simpleBCMDebug = PE_parse_boot_argn("-simplebcmdbg", &value, sizeof(value));
    if (enabled) {
        initialized = true;
        bcm::preparePayloads();
    }
    return KERN_SUCCESS;
}

extern "C" kern_return_t SimpleBCM_kern_stop(kmod_info_t *, void *) {
    return initialized ? KERN_FAILURE : KERN_SUCCESS;
}
