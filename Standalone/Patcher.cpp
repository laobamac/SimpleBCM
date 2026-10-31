//
//  Patcher.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "Patcher.hpp"
#include <sys/systm.h>

uintptr_t KernelPatcher::branchTarget(uintptr_t target, uintptr_t pc) {
    auto delta = static_cast<int64_t>(target - pc);
    return delta >= INT32_MIN && delta <= INT32_MAX ? target : bcm::allocateStub(image, target);
}

uintptr_t KernelPatcher::solveSymbol(size_t index, const char *name) {
    if (index != KernelID)
        return bcm::findSymbol(image, name);
    if (!strcmp(name, "_copyin"))
        return reinterpret_cast<uintptr_t>(copyin);
    if (!strcmp(name, "_copyout"))
        return reinterpret_cast<uintptr_t>(copyout);
    return 0;
}

bool KernelPatcher::routeMultipleLong(size_t, RouteRequest *routes, size_t count, uintptr_t, size_t) {
    if (!image.editable)
        return false;
    for (size_t i = 0; i < count; ++i) {
        auto address = bcm::findSymbol(image, routes[i].name);
        uint32_t prefix = 0;
        for (uint32_t j = 0; j < image.payload->routeCount; ++j) {
            const auto &r = image.payload->routes[j];
            if (image.address + r.offset == address)
                prefix = r.length;
        }
        if (prefix < 14 || prefix > 32 || address < image.address ||
            address - image.address + prefix > image.payload->size)
            return false;
        const auto offset = image.payload->stubOffset + image.stubUsed;
        const auto needed = (prefix + 14 + 15) & ~15U;
        if (image.stubUsed > image.payload->stubSize || needed > image.payload->stubSize - image.stubUsed)
            return false;
        uint8_t *stub = image.memory + offset;
        memcpy(stub, reinterpret_cast<void *>(address), prefix);
        const uint8_t jump[] = {0xFF, 0x25, 0, 0, 0, 0};
        auto continuation = address + prefix;
        memcpy(stub + prefix, jump, sizeof(jump));
        memcpy(stub + prefix + sizeof(jump), &continuation, sizeof(continuation));
        *routes[i].original = image.address + offset;
        image.stubUsed += needed;
        memcpy(reinterpret_cast<void *>(address), jump, sizeof(jump));
        memcpy(reinterpret_cast<void *>(address + sizeof(jump)), &routes[i].target, sizeof(uintptr_t));
    }
    return true;
}
