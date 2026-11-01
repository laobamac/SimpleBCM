//
//  Relocate.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "Payload.hpp"
#include <string.h>

namespace bcm {

uint64_t payloadChecksum(const uint8_t *bytes, size_t length) {
    uint64_t value = 14695981039346656037ULL;
    for (size_t i = 0; i < length; ++i)
        value = (value ^ bytes[i]) * 1099511628211ULL;
    return value;
}

uintptr_t findSymbol(const LinkedImage &image, const char *name) {
    size_t begin = 0, end = image.payload->symbolCount;
    while (begin < end) {
        auto middle = begin + (end - begin) / 2;
        auto &entry = image.payload->symbols[middle];
        int order = strcmp(name, entry.name);
        if (!order)
            return entry.offset < image.payload->size ? image.address + entry.offset : 0;
        if (order < 0)
            end = middle;
        else
            begin = middle + 1;
    }
    return 0;
}

uintptr_t allocateStub(LinkedImage &image, uintptr_t target) {
    const auto &p = *image.payload;
    if (!image.editable || image.stubUsed > p.stubSize || p.stubSize - image.stubUsed < 16 ||
        p.stubOffset > p.mappedSize || p.stubSize > p.mappedSize - p.stubOffset)
        return 0;
    const auto offset = p.stubOffset + image.stubUsed;
    const uint8_t jump[] = {0xFF, 0x25, 0, 0, 0, 0};
    memcpy(image.memory + offset, jump, sizeof(jump));
    memcpy(image.memory + offset + sizeof(jump), &target, sizeof(target));
    image.stubUsed += 16;
    return image.address + offset;
}

bool relocateImage(LinkedImage &image, const LinkedImage *images, size_t imageCount,
                   const uintptr_t *imports, size_t importCount) {
    if (!image.payload || !image.memory || !image.editable)
        return false;
    const auto &p = *image.payload;
    if (p.size > p.mappedSize || p.stubOffset < p.size || p.stubOffset > p.mappedSize ||
        p.stubSize > p.mappedSize - p.stubOffset || image.address > UINTPTR_MAX - p.mappedSize ||
        payloadChecksum(image.memory, p.size) != p.checksum)
        return false;
    for (uint32_t i = 0; i < p.relocationCount; ++i) {
        const auto &r = p.relocations[i];
        if ((r.width != 4 && r.width != 8) || r.offset > p.size || r.width > p.size - r.offset)
            return false;
        uintptr_t target;
        if (r.image == 255) {
            if (r.target >= importCount || !imports[r.target])
                return false;
            target = imports[r.target];
        } else {
            if (r.image >= imageCount || !images[r.image].memory ||
                r.target >= images[r.image].payload->size)
                return false;
            target = images[r.image].address + r.target;
        }
        target += static_cast<uint64_t>(r.addend);
        if (r.width == 8) {
            memcpy(image.memory + r.offset, &target, 8);
        } else {
            auto pc = image.address + r.offset + 4;
            int64_t delta = static_cast<int64_t>(target - pc);
            if (delta < INT32_MIN || delta > INT32_MAX) {
                target = allocateStub(image, target);
                if (!target)
                    return false;
                delta = static_cast<int64_t>(target - pc);
                if (delta < INT32_MIN || delta > INT32_MAX)
                    return false;
            }
            int32_t value = static_cast<int32_t>(delta);
            memcpy(image.memory + r.offset, &value, 4);
        }
    }
    for (uint32_t i = 0; i < p.symbolValueCount; ++i) {
        auto offset = p.symbolValues[i];
        if (offset > p.size || 8 > p.size - offset)
            return false;
        uint64_t value;
        memcpy(&value, image.memory + offset, 8);
        if (value >= p.size)
            return false;
        value += image.address;
        memcpy(image.memory + offset, &value, 8);
    }
    return true;
}

}
