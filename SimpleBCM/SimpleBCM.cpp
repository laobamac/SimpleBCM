//
//  SimpleBCM.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/9/18.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "Bridge.hpp"
#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOWorkLoop.h>

class SimpleBCM final : public IOService {
    OSDeclareDefaultStructors(SimpleBCM)
public:
    IOService *probe(IOService *provider, SInt32 *score) override {
        return ADDPR(startSuccess) ? IOService::probe(provider, score) : nullptr;
    }

    bool start(IOService *provider) override {
        if (!IOService::start(provider))
            return false;
        loop = IOWorkLoop::workLoop();
        timer = IOTimerEventSource::timerEventSource(this, tick);
        if (!loop || !timer || loop->addEventSource(timer) != kIOReturnSuccess)
            return false;
        bcm::Bridge::publish(this);
        timer->setTimeoutMS(1000);
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

    static void tick(OSObject *owner, IOTimerEventSource *source) {
        auto service = static_cast<SimpleBCM *>(owner);
        bcm::Bridge::publish(service);
        source->setTimeoutMS(1000);
    }
};

OSDefineMetaClassAndStructors(SimpleBCM, IOService)

static const char *disableArgs[] = {"-simplebcmoff"};
static const char *debugArgs[] = {"-simplebcmdbg"};

static void initialize() {
    bcm::Bridge::initialize();
}

PluginConfiguration ADDPR(config) {
    xStringify(PRODUCT_NAME),
    parseModuleVersion(xStringify(MODULE_VERSION)),
    LiluAPI::AllowNormal | LiluAPI::AllowInstallerRecovery,
    disableArgs, arrsize(disableArgs),
    debugArgs, arrsize(debugArgs),
    nullptr, 0,
    KernelVersion::Sequoia,
    KernelVersion::Tahoe,
    initialize
};
