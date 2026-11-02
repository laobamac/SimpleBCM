//
//  HardwareIdentity.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_HARDWARE_IDENTITY_HPP
#define SIMPLEBCM_HARDWARE_IDENTITY_HPP

#include <stddef.h>
#include <stdint.h>

namespace bcm {

struct HardwareIdentity {
    uint32_t vendor;
    uint32_t device;
    uint32_t chip;
    uint32_t board;
    uint32_t boardVendor;
};

inline bool hardwareValue(const char *text, size_t length, const char *key, uint32_t &value) {
    for (size_t offset = 0; offset < length; ++offset) {
        if (offset && text[offset - 1] != '\n')
            continue;
        size_t index = 0;
        while (key[index] && offset + index < length && key[index] == text[offset + index])
            ++index;
        if (key[index])
            continue;
        auto cursor = offset + index;
        uint32_t result = 0;
        unsigned digits = 0;
        while (cursor < length && text[cursor] != '\n' && text[cursor] != '\r' && text[cursor]) {
            const char character = text[cursor++];
            const int digit = character >= '0' && character <= '9' ? character - '0' :
                character >= 'a' && character <= 'f' ? character - 'a' + 10 :
                character >= 'A' && character <= 'F' ? character - 'A' + 10 : -1;
            if (digit < 0 || ++digits > 8)
                return false;
            result = (result << 4) | static_cast<uint32_t>(digit);
        }
        if (!digits)
            return false;
        value = result;
        return true;
    }
    return false;
}

inline bool decodeHardwareIdentity(const char *text, size_t length, HardwareIdentity &identity) {
    HardwareIdentity result {};
    if (!text || length > 2048 ||
        !hardwareValue(text, length, "vendorid: 0x", result.vendor) ||
        !hardwareValue(text, length, "deviceid: 0x", result.device) ||
        !hardwareValue(text, length, "chipnum: 0x", result.chip) ||
        !hardwareValue(text, length, "boardid: 0x", result.board) ||
        !hardwareValue(text, length, "boardvendor: 0x", result.boardVendor) ||
        result.vendor != 0x14e4 || !result.device || !result.chip || !result.board)
        return false;
    identity = result;
    return true;
}

}

#endif
