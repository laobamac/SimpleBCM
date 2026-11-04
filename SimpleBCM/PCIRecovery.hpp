//
//  PCIRecovery.hpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/5.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef SIMPLEBCM_PCI_RECOVERY_HPP
#define SIMPLEBCM_PCI_RECOVERY_HPP

#include <stdint.h>
#include <stddef.h>

class KernelPatcher;
class IOService;

namespace bcm {

bool preparePCIRecovery(KernelPatcher &, size_t, uintptr_t, size_t);
void publishPCIRecovery(IOService *, IOService *);

struct PCIConfiguration {
    uint32_t words[64];
    uint64_t registryID;

    uint16_t word(unsigned offset) const {
        return static_cast<uint16_t>(words[offset / 4] >> ((offset & 2) * 8));
    }
    uint8_t byte(unsigned offset) const {
        return static_cast<uint8_t>(words[offset / 4] >> ((offset & 3) * 8));
    }
    bool valid() const {
        if ((words[0] & 0xffff) != 0x14e4 || (words[0] >> 16) == 0xffff ||
            !(words[0] >> 16) || (byte(0x0e) & 0x7f) || (words[2] >> 24) != 2 ||
            (word(4) & 6) != 6 || !registryID || !(words[4] & ~15U) ||
            words[4] == UINT32_MAX || (words[4] & 7) != 4)
            return false;
        uint64_t visited = 0;
        for (unsigned offset = byte(0x34); offset; offset = byte(offset + 1)) {
            if (offset < 0x40 || offset > 0xfc || (offset & 3) || (visited & (1ULL << (offset / 4))))
                return false;
            visited |= 1ULL << (offset / 4);
            const auto kind = byte(offset);
            const auto control = word(offset + 2);
            if ((kind == 1 && (offset > 0xf8 || (word(offset + 4) & 3))) ||
                (kind == 5 && offset + ((control & 0x100) ? ((control & 0x80) ? 24 : 20) :
                                                        ((control & 0x80) ? 14 : 10)) > 256) ||
                (kind == 0x10 && offset + ((control & 15) >= 2 ? 0x34 : 0x14) > 256) ||
                (kind == 0x11 && (control & 0x8000)))
                return false;
        }
        return true;
    }
};

enum class PCIRecoveryResult : uint32_t {
    Unchanged, Restored, InvalidSnapshot, IdentityChanged, ResourceChanged,
    ResetRefused, LinkUnavailable, RestoreFailed
};

template <typename Bus> bool pciConfigurationMatches(Bus &bus, const PCIConfiguration &saved) {
    if (bus.read32(0) != saved.words[0] || (bus.read16(4) & 6) != (saved.word(4) & 6))
        return false;
    for (unsigned i = 0; i < 6; ++i)
        if (bus.read32(0x10 + 4 * i) != saved.words[4 + i])
            return false;
    return true;
}

template <typename Bus> PCIRecoveryResult recoverPCIConfiguration(Bus &bus, const PCIConfiguration &saved) {
    if (!saved.valid())
        return PCIRecoveryResult::InvalidSnapshot;
    if (pciConfigurationMatches(bus, saved))
        return PCIRecoveryResult::Unchanged;
    auto identity = bus.read32(0);
    if (identity == UINT32_MAX || !identity) {
        if (!bus.reset())
            return PCIRecoveryResult::ResetRefused;
        for (unsigned i = 0; i < 100; ++i) {
            bus.wait(10);
            identity = bus.read32(0);
            if (identity && identity != UINT32_MAX)
                break;
        }
        if (!identity || identity == UINT32_MAX)
            return PCIRecoveryResult::LinkUnavailable;
    }
    if (identity != saved.words[0])
        return PCIRecoveryResult::IdentityChanged;
    bool upper = false;
    for (unsigned i = 0; i < 6; ++i) {
        const auto current = bus.read32(0x10 + i * 4);
        if (current != saved.words[4 + i] && current != 0 &&
            (upper || current != (saved.words[4 + i] & 15)))
            return PCIRecoveryResult::ResourceChanged;
        upper = !upper && (saved.words[4 + i] & 7) == 4;
    }
    bus.write16(4, static_cast<uint16_t>((saved.word(4) & ~7U) | 0x400));
    if (bus.read16(4) & 7)
        return PCIRecoveryResult::RestoreFailed;
    for (unsigned offset = saved.byte(0x34); offset; offset = saved.byte(offset + 1)) {
        if (saved.byte(offset) == 1) {
            bus.write16(offset + 4, static_cast<uint16_t>(saved.word(offset + 4) & 0x7ffc));
            bus.wait(10);
        }
    }
    for (int i = 5; i >= 0; --i)
        bus.write32(0x10 + 4 * i, saved.words[4 + i]);
    bus.write16(0x0c, saved.word(0x0c));
    bus.write8(0x3c, saved.byte(0x3c));
    for (unsigned offset = saved.byte(0x34); offset; offset = saved.byte(offset + 1)) {
        const auto kind = saved.byte(offset);
        const auto control = saved.word(offset + 2);
        if (kind == 5) {
            bus.write16(offset + 2, control & ~1U);
            bus.write32(offset + 4, saved.words[(offset + 4) / 4]);
            unsigned data = offset + 8;
            if (control & 0x80) {
                bus.write32(data, saved.words[data / 4]);
                data += 4;
            }
            bus.write16(data, saved.word(data));
            if (control & 0x100)
                bus.write32(data + 4, saved.words[(data + 4) / 4]);
            if (bus.read32(offset + 4) != saved.words[(offset + 4) / 4] ||
                ((control & 0x80) && bus.read32(offset + 8) != saved.words[(offset + 8) / 4]) ||
                bus.read16(data) != saved.word(data) ||
                ((control & 0x100) && bus.read32(data + 4) != saved.words[(data + 4) / 4]))
                return PCIRecoveryResult::RestoreFailed;
            bus.write16(offset + 2, control);
            if (bus.read16(offset + 2) != control)
                return PCIRecoveryResult::RestoreFailed;
        } else if (kind == 0x10) {
            bus.write16(offset + 8, saved.word(offset + 8) & ~0x8000U);
            bus.write16(offset + 0x10, saved.word(offset + 0x10) & ~0x30U);
            if ((control & 15) >= 2) {
                bus.write16(offset + 0x28, saved.word(offset + 0x28));
                bus.write16(offset + 0x30, saved.word(offset + 0x30));
            }
        }
    }
    for (unsigned i = 0; i < 6; ++i)
        if (bus.read32(0x10 + i * 4) != saved.words[4 + i])
            return PCIRecoveryResult::RestoreFailed;
    if (bus.read32(0) != saved.words[0])
        return PCIRecoveryResult::RestoreFailed;
    bus.write16(4, saved.word(4));
    return pciConfigurationMatches(bus, saved) ? PCIRecoveryResult::Restored : PCIRecoveryResult::RestoreFailed;
}

}

#endif
