//
//  RadioPolicy.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/6.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "RadioPolicy.hpp"
#include "../build/Embedded/RadioPolicyData.hpp"

namespace bcm {
namespace {

struct CountrySet {
    uint32_t count;
    uint32_t reserved;
    const uint8_t *records;
};

static_assert(sizeof(CountrySet) == 16, "CLM country set layout");
static const CountrySet countries {radiodata::CountryCount, 0, radiodata::Countries};
static bool installed;

template <typename T> T value(const LinkedImage &image, uint32_t offset) {
    T result;
    memcpy(&result, image.memory + offset, sizeof(result));
    return result;
}

static bool applyTables(LinkedImage &image) {
    if (!image.editable || image.registered || !image.payload || !image.payload->sha256 ||
        !image.memory || image.address != reinterpret_cast<uintptr_t>(image.memory))
        return false;
    const radiodata::Guard *guard = nullptr;
    for (const auto &candidate : radiodata::Guards)
        if (!strcmp(image.payload->sha256, candidate.sha256))
            guard = &candidate;
    if (!guard)
        return false;
    auto contains = [&](uint32_t offset, size_t length) {
        return offset <= image.payload->size && length <= image.payload->size - offset;
    };
    if (!contains(guard->header, 120) || !contains(guard->data, 108) ||
        !contains(guard->countrySet, 16) || !contains(guard->countries, sizeof(radiodata::Countries)) ||
        !contains(guard->locales, radiodata::SourceLocaleSize) || !contains(guard->dataSources, 656))
        return false;
    if (memcmp(image.memory + guard->header, "CLM DATA\0\0\x0c\0\x01\0", 14) ||
        value<uintptr_t>(image, guard->header + 48) != image.address + guard->header ||
        value<uintptr_t>(image, guard->header + 56) != image.address + guard->data ||
        value<uint32_t>(image, guard->data + 104) != 0x2600B27F ||
        value<uintptr_t>(image, guard->data + 72) != image.address + guard->locales ||
        value<uintptr_t>(image, guard->data + 80) != image.address + guard->countrySet ||
        value<uint32_t>(image, guard->countrySet) != radiodata::CountryCount ||
        value<uintptr_t>(image, guard->countrySet + 8) != image.address + guard->countries ||
        value<uintptr_t>(image, guard->dataSources) || value<uintptr_t>(image, guard->dataSources + 328) ||
        payloadChecksum(image.memory + guard->countries, sizeof(radiodata::Countries)) != radiodata::CountryChecksum ||
        payloadChecksum(image.memory + guard->locales, radiodata::SourceLocaleSize) != radiodata::LocaleChecksum)
        return false;
    const auto localePointer = reinterpret_cast<uintptr_t>(radiodata::Locales);
    const auto countryPointer = reinterpret_cast<uintptr_t>(&countries);
    memcpy(image.memory + guard->data + 72, &localePointer, sizeof(localePointer));
    memcpy(image.memory + guard->data + 80, &countryPointer, sizeof(countryPointer));
    return true;
}

}

bool RadioPolicy::prepare(LinkedImage &image) {
    if (installed || !applyTables(image))
        return false;
    installed = true;
    return true;
}

void RadioPolicy::publish(IOService *service) {
    service->setProperty("RadioPolicyVersion", RadioPolicyVersion);
    service->setProperty("RadioPolicyStatus", installed ? "CN80Center42" : "NotInstalled");
    service->setProperty("RadioPolicyScope", radiodata::Scope);
    service->setProperty("RadioPolicyRuleCount", radiodata::RuleCount, 32);
    service->setProperty("RadioPolicyLocaleSHA256", radiodata::LocaleSHA256);
}

}
