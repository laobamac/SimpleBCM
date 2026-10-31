//
//  Loader.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "Loader.hpp"
#include "Payload.hpp"
#include "Bridge.hpp"
#include <IOKit/IOCatalogue.h>
#include <libkern/c++/OSUnserialize.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSArray.h>
#include <mach-o/loader.h>
#include <mach/kmod.h>

extern "C" kern_return_t kext_alloc(vm_offset_t *, vm_size_t, boolean_t);
extern "C" void kext_free(vm_offset_t, vm_size_t);
extern "C" uintptr_t vm_kernel_slide;
extern "C" uintptr_t PE_get_kc_slide(int);
extern "C" void *kext_get_vm_map(kmod_info_t *);
extern "C" kern_return_t vm_map_wire(void *, uintptr_t, uintptr_t, vm_prot_t, boolean_t);
extern "C" OSObject *bcmLookupKext(const char *) asm("__ZN6OSKext24lookupKextWithIdentifierEPKc");
extern "C" OSObject *bcmRegisterKext(OSDictionary *, bool, int) asm("__ZN6OSKext21withPrelinkedInfoDictEP12OSDictionaryb7kc_kind");
extern "C" OSReturn bcmProtectKext(OSObject *, bool, bool) asm("__ZN6OSKext15setVMAttributesEbb");
extern "C" OSReturn bcmValidateKextMapping(OSObject *, bool) asm("__ZN6OSKext19validateKextMappingEb");
extern "C" bool bcmSetAutounloadEnabled(OSObject *, bool) asm("__ZN6OSKext20setAutounloadEnabledEb");
extern "C" OSReturn bcmLoadKext(const char *, bool, bool, uint8_t, uint8_t, OSArray *)
    asm("__ZN6OSKext22loadKextWithIdentifierEPKcbbhhP7OSArray");

namespace bcm {

static constexpr int KCKindUnknown = 0;
static LinkedImage images[4];
static OSObject *modules[4];
static uint32_t selected[3];
static const char *status = "NotPrepared";
static const char *failedModule = "";
static uint32_t lastError;
static uint32_t loadedCount;
static uint32_t validatedCount;
static bool prepared;
static bool started;

static bool fail(const char *reason, const char *module, uint32_t error = 0) {
    Bridge::disable(reason);
    status = reason;
    failedModule = module;
    lastError = error;
    SYSLOG("loader", "%s: %s (0x%08x)", reason, module, error);
    for (auto &image : images) {
        if (image.memory && !image.registered) {
            kext_free(image.address, image.payload->mappedSize);
            image.memory = nullptr;
        }
    }
    return false;
}

static bool setNumber(OSDictionary *dictionary, const char *key, uint64_t value) {
    auto number = OSNumber::withNumber(value, 64);
    if (!number)
        return false;
    auto result = dictionary->setObject(key, number);
    number->release();
    return result;
}

static bool setString(OSDictionary *dictionary, const char *key, const char *value) {
    auto string = OSString::withCString(value);
    if (!string)
        return false;
    auto result = dictionary->setObject(key, string);
    string->release();
    return result;
}

static bool registerImage(uint32_t index) {
    auto &image = images[index];
    auto &p = *image.payload;
    auto object = OSUnserializeXML(p.plist);
    auto dictionary = OSDynamicCast(OSDictionary, object);
    if (!dictionary) {
        if (object)
            object->release();
        return false;
    }
    char path[256];
    snprintf(path, sizeof(path), "/Library/Extensions/SimpleBCM.kext/Embedded/%s", p.identifier);
    const auto slide = PE_get_kc_slide(KCKindUnknown);
    auto kmod = reinterpret_cast<kmod_info_t *>(image.memory + p.kmodOffset);
    kmod->next = nullptr;
    kmod->id = 0;
    kmod->reference_count = 0;
    kmod->reference_list = nullptr;
    kmod->address = 0;
    kmod->size = p.mappedSize;
    kmod->hdr_size = 0;
    bool valid = setString(dictionary, "_PrelinkBundlePath", path) &&
        setString(dictionary, "_PrelinkExecutableRelativePath", "Contents/MacOS/Embedded") &&
        setNumber(dictionary, "_PrelinkExecutableLoadAddr", image.address - slide) &&
        setNumber(dictionary, "_PrelinkExecutableSize", p.mappedSize) &&
        setNumber(dictionary, "_PrelinkKmodInfo", reinterpret_cast<uintptr_t>(kmod) - slide);
    if (!valid) {
        dictionary->release();
        return false;
    }
    auto header = reinterpret_cast<mach_header_64 *>(image.memory);
    auto command = reinterpret_cast<load_command *>(header + 1);
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if (command->cmd == LC_SEGMENT_64) {
            auto segment = reinterpret_cast<segment_command_64 *>(command);
            segment->vmaddr += image.address - vm_kernel_slide;
            auto section = reinterpret_cast<section_64 *>(segment + 1);
            for (uint32_t j = 0; j < segment->nsects; ++j)
                section[j].addr += image.address - vm_kernel_slide;
        }
        command = reinterpret_cast<load_command *>(reinterpret_cast<uint8_t *>(command) + command->cmdsize);
    }
    image.registered = true;
    modules[index] = bcmRegisterKext(dictionary, true, KCKindUnknown);
    dictionary->release();
    if (!modules[index])
        return false;
    bcmSetAutounloadEnabled(modules[index], false);
    image.editable = false;
    auto result = bcmProtectKext(modules[index], true, false);
    if (result != KERN_SUCCESS) {
        lastError = result;
        return false;
    }
    command = reinterpret_cast<load_command *>(header + 1);
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if (command->cmd == LC_SEGMENT_64) {
            auto segment = reinterpret_cast<segment_command_64 *>(command);
            if (!strncmp(segment->segname, "__LINKEDIT", 16)) {
                result = vm_map_wire(kext_get_vm_map(kmod), segment->vmaddr,
                                     segment->vmaddr + segment->vmsize, VM_PROT_READ, false);
                if (result != KERN_SUCCESS) {
                    lastError = result;
                    return false;
                }
            }
        }
        command = reinterpret_cast<load_command *>(reinterpret_cast<uint8_t *>(command) + command->cmdsize);
    }
    SYSLOG("loader", "registered %s, %u bytes", p.identifier, p.mappedSize);
    return true;
}

bool preparePayloads() {
    if (prepared)
        return true;
    auto kernel = getKernelVersion();
    if (kernel < 23 || kernel > 25)
        return fail("UnsupportedKernel", "SimpleBCM", kernel);
    selected[0] = 0;
    selected[1] = 1;
    selected[2] = kernel == 25 ? 3 : 2;
    for (auto index : selected) {
        auto existing = bcmLookupKext(payloads[index].identifier);
        if (existing) {
            existing->release();
            return fail("ConflictingModule", payloads[index].identifier);
        }
    }
    for (uint32_t i = 0; i < nativeVtableGuardCount; ++i) {
        const auto &guard = nativeVtableGuards[i];
        if (guard.parent >= nativeImportCount || guard.method >= nativeImportCount)
            return fail("InvalidVtableGuard", "SimpleBCM", i);
        uintptr_t method;
        memcpy(&method, reinterpret_cast<void *>(bcmNativeImports[guard.parent] + guard.offset), sizeof(method));
        if (method != bcmNativeImports[guard.method])
            return fail("NativeVtableMismatch", nativeImportNames[guard.parent], guard.offset);
    }
    status = "Mapping";
    for (auto index : selected) {
        auto &image = images[index];
        image.payload = &payloads[index];
        vm_offset_t address = 0;
        auto result = kext_alloc(&address, image.payload->mappedSize, false);
        if (result != KERN_SUCCESS)
            return fail("AllocationFailed", image.payload->identifier, result);
        image.address = address;
        image.memory = reinterpret_cast<uint8_t *>(address);
        image.editable = true;
        bzero(image.memory, image.payload->mappedSize);
        memcpy(image.memory, image.payload->bytes, image.payload->size);
    }
    status = "Linking";
    for (auto index : selected) {
        if (!relocateImage(images[index], images, 4, bcmNativeImports, nativeImportCount))
            return fail("LinkFailed", images[index].payload->identifier);
    }
    Bridge::initialize();
    status = "Patching";
    if (!Bridge::prepareImage(images[1], 0) || !Bridge::prepareImage(images[0], 1) ||
        !Bridge::prepareImage(images[selected[2]], 2) || !Bridge::ready())
        return fail("BridgeFailed", "SimpleBCM");
    status = "Registering";
    for (auto index : selected) {
        if (!registerImage(index))
            return fail("RegistrationFailed", images[index].payload->identifier, lastError);
    }
    prepared = true;
    status = "Prepared";
    return true;
}

bool startPayloads() {
    if (started)
        return true;
    if (!prepared)
        return false;
    status = "Loading";
    for (auto index : selected) {
        auto result = bcmLoadKext(payloads[index].identifier, false, true, 2, 2, nullptr);
        if (result != KERN_SUCCESS)
            return fail("LoadFailed", payloads[index].identifier, result);
        ++loadedCount;
    }
    status = "ValidatingMappings";
    for (auto index : selected) {
        auto result = bcmValidateKextMapping(modules[index], true);
        if (result != KERN_SUCCESS)
            return fail("MappingValidationFailed", payloads[index].identifier, result);
        ++validatedCount;
    }
    status = "Starting";
    for (auto index : selected) {
        auto result = bcmLoadKext(payloads[index].identifier, false, true, 0, 2, nullptr);
        if (result != KERN_SUCCESS)
            return fail("StartFailed", payloads[index].identifier, result);
    }
    status = "Matching";
    for (auto index : selected) {
        auto result = bcmLoadKext(payloads[index].identifier, false, true, 0, 0, nullptr);
        if (result != KERN_SUCCESS)
            return fail("MatchingFailed", payloads[index].identifier, result);
        gIOCatalogue->moduleHasLoaded(payloads[index].identifier);
    }
    started = true;
    status = "StartedAwaitingHardware";
    SYSLOG("loader", "embedded stack started on Darwin %u", getKernelVersion());
    return true;
}

void publishLoader(IOService *service) {
    service->setProperty("Status", status);
    service->setProperty("LoaderStatus", status);
    service->setProperty("LoaderFailedModule", failedModule);
    service->setProperty("LoaderError", lastError, 32);
    char error[11];
    snprintf(error, sizeof(error), "0x%08x", lastError);
    service->setProperty("LoaderErrorHex", error);
    service->setProperty("LoaderKCType", "KCKindUnknown");
    service->setProperty("DriverLoading", "Embedded");
    service->setProperty("ExternalLiluRequired", false);
    service->setProperty("EmbeddedModulesStarted", started);
    service->setProperty("EmbeddedModulesLoaded", loadedCount, 32);
    service->setProperty("EmbeddedMappingsValidated", validatedCount, 32);
    service->setProperty("AirPortSHA256", payloads[selected[2]].sha256);
}

}
