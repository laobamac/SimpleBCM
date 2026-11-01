//
//  Patcher.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_PATCHER_HPP
#define SIMPLEBCM_PATCHER_HPP

#include "Payload.hpp"
#include <IOKit/IOLib.h>
#include <mach/mach_types.h>

extern "C" int version_major;
extern bool simpleBCMDebug;

#define SYSLOG(module, format, ...) IOLog("SimpleBCM: " module " " format "\n", ##__VA_ARGS__)
#ifdef DEBUG
#define DBGLOG(module, format, ...) do { if (simpleBCMDebug) SYSLOG(module, format, ##__VA_ARGS__); } while (0)
#else
#define DBGLOG(module, format, ...) do {} while (0)
#endif

template <typename T, size_t N> constexpr size_t arrsize(const T (&)[N]) { return N; }
inline unsigned getKernelVersion() { return static_cast<unsigned>(version_major); }

class KernelPatcher {
public:
    static constexpr size_t KernelID = static_cast<size_t>(-1);
    struct RouteRequest {
        const char *name;
        uintptr_t target;
        uintptr_t *original;
        template <typename T> RouteRequest(const char *symbol, T replacement, T &saved) :
            name(symbol), target(reinterpret_cast<uintptr_t>(replacement)),
            original(reinterpret_cast<uintptr_t *>(&saved)) {}
    };

    explicit KernelPatcher(bcm::LinkedImage &value) : image(value) {}
    uintptr_t solveSymbol(size_t index, const char *name);
    uintptr_t branchTarget(uintptr_t target, uintptr_t pc);
    bool routeMultipleLong(size_t, RouteRequest *routes, size_t count, uintptr_t, size_t);
    template <size_t N> bool routeMultipleLong(size_t index, RouteRequest (&routes)[N], uintptr_t address, size_t size) {
        return routeMultipleLong(index, routes, N, address, size);
    }
    void clearError() {}
private:
    bcm::LinkedImage &image;
};

#endif
