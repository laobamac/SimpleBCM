//
//  Payload.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_PAYLOAD_HPP
#define SIMPLEBCM_PAYLOAD_HPP

#include <stddef.h>
#include <stdint.h>

namespace bcm {

struct Relocation {
    uint32_t offset;
    uint32_t target;
    int64_t addend;
    uint8_t image;
    uint8_t width;
    uint8_t reserved[6];
};

struct Symbol {
    const char *name;
    uint32_t offset;
};

struct RoutePrefix {
    uint32_t offset;
    uint32_t length;
};

struct NativeVtableGuard {
    uint32_t parent;
    uint32_t offset;
    uint32_t method;
};

struct Payload {
    const char *identifier;
    const char *sha256;
    const uint8_t *bytes;
    uint32_t size;
    uint32_t mappedSize;
    uint32_t stubOffset;
    uint32_t stubSize;
    uint32_t kmodOffset;
    const char *plist;
    const Relocation *relocations;
    uint32_t relocationCount;
    const uint32_t *symbolValues;
    uint32_t symbolValueCount;
    const Symbol *symbols;
    uint32_t symbolCount;
    const RoutePrefix *routes;
    uint32_t routeCount;
    uint64_t checksum;
};

struct LinkedImage {
    const Payload *payload;
    uint8_t *memory;
    uintptr_t address;
    uint32_t stubUsed;
    bool registered;
    bool editable;
};

extern const Payload payloads[4];
extern "C" const uintptr_t bcmNativeImports[];
extern const uint32_t nativeImportCount;
extern const char *const nativeImportNames[];
extern const NativeVtableGuard nativeVtableGuards[];
extern const uint32_t nativeVtableGuardCount;

bool relocateImage(LinkedImage &image, const LinkedImage *images, size_t imageCount,
                   const uintptr_t *imports, size_t importCount);
uintptr_t allocateStub(LinkedImage &image, uintptr_t target);
uintptr_t findSymbol(const LinkedImage &image, const char *name);
uint64_t payloadChecksum(const uint8_t *bytes, size_t length);

}

#endif
