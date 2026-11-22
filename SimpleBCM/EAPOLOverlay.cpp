//
//  EAPOLOverlay.cpp
//  SimpleBCM
//
//  Created by laobamac on 2026/11/22.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "EAPOLOverlay.hpp"

#include "Bridge.hpp"
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/ubc.h>
#include <sys/uio.h>
#include <sys/vnode.h>

extern "C" {
void bsdinit_task(void);
void load_init_program(proc_t);
boolean_t ml_set_interrupts_enabled(boolean_t);
vfs_context_t vfs_context_kernel(void);
int vfs_mount_at_path(const char *, const char *, vnode_t, vnode_t, void *, size_t, int, int);
}

namespace bcm {
namespace {

struct Entry {
    const char *name;
    size_t parent;
    mode_t mode;
    bool directory;
    size_t offset;
    size_t size;
};

struct Bundle {
    const char *path;
    const char *executable;
    const char *name;
    size_t first;
    size_t end;
    const char *state {"NotMounted"};
    int error {};
};

#include "../build/Embedded/EAPOLPayload.hpp"
#include "../build/Embedded/EAPOLKernelABI.hpp"

static constexpr char fsType[] = "sbcmeapol";
static vnode_t nodes[arrsize(entries)];
static int (**vnodeOperations)(void *);
static vfstable_t fsHandle;
static uint32_t *initCallDisplacement;
static uint32_t originalInitDisplacement;
static uint32_t overlayInitDisplacement;
static const char *overlayState = "NotPrepared";
static int overlayError;
static Bundle *registeringBundle;
using KernelMount = int (*)(const char *, vnode_t, vnode_t, const char *, void *, int, uint32_t, vfs_context_t);

static int noOperation(void *) {
    return 0;
}

static int unsupported(void *) {
    return ENOTSUP;
}

static size_t indexFor(vnode_t vnode) {
    return static_cast<const Entry *>(vnode_fsnode(vnode)) - entries;
}

static int acquire(size_t index, vnode_t *out) {
    auto node = nodes[index];
    if (!node)
        return ENOENT;
    auto result = vnode_get(node);
    if (!result)
        *out = node;
    return result;
}

static int lookup(void *parameters) {
    auto args = static_cast<vnop_lookup_args *>(parameters);
    const auto index = indexFor(args->a_dvp);
    const auto bundle = static_cast<const Bundle *>(vfs_fsprivate(vnode_mount(args->a_dvp)));
    if (!bundle)
        return ENOENT;
    const auto component = args->a_cnp;
    const auto name = component->cn_nameptr;
    const auto size = static_cast<size_t>(component->cn_namelen);
    if (size == 1 && name[0] == '.')
        return acquire(index, args->a_vpp);
    if (size == 2 && name[0] == '.' && name[1] == '.')
        return acquire(entries[index].parent, args->a_vpp);
    for (size_t i = bundle->first + 1; i < bundle->end; ++i) {
        if (entries[i].parent == index && strlen(entries[i].name) == size && !memcmp(entries[i].name, name, size))
            return acquire(i, args->a_vpp);
    }
    return ENOENT;
}

static int attributes(void *parameters) {
    auto args = static_cast<vnop_getattr_args *>(parameters);
    const auto index = indexFor(args->a_vp);
    const auto &entry = entries[index];
    const timespec stamp = {1, 0};
    auto attrs = args->a_vap;
    VATTR_RETURN(attrs, va_type, entry.directory ? VDIR : VREG);
    VATTR_RETURN(attrs, va_mode, entry.mode);
    VATTR_RETURN(attrs, va_uid, 0);
    VATTR_RETURN(attrs, va_gid, 0);
    VATTR_RETURN(attrs, va_flags, 0);
    VATTR_RETURN(attrs, va_nlink, entry.directory ? 2 : 1);
    VATTR_RETURN(attrs, va_fileid, index + 2);
    VATTR_RETURN(attrs, va_linkid, index + 2);
    VATTR_RETURN(attrs, va_parentid, entry.parent + 2);
    VATTR_RETURN(attrs, va_data_size, entry.size);
    VATTR_RETURN(attrs, va_total_size, entry.size);
    VATTR_RETURN(attrs, va_data_alloc, round_page(entry.size));
    VATTR_RETURN(attrs, va_total_alloc, round_page(entry.size));
    VATTR_RETURN(attrs, va_iosize, PAGE_SIZE);
    VATTR_RETURN(attrs, va_create_time, stamp);
    VATTR_RETURN(attrs, va_access_time, stamp);
    VATTR_RETURN(attrs, va_modify_time, stamp);
    VATTR_RETURN(attrs, va_change_time, stamp);
    VATTR_RETURN(attrs, va_fsid, vfs_statfs(vnode_mount(args->a_vp))->f_fsid.val[0]);
    if (VATTR_IS_ACTIVE(attrs, va_name) && attrs->va_name) {
        strlcpy(attrs->va_name, entry.name, NAME_MAX + 1);
        VATTR_SET_SUPPORTED(attrs, va_name);
    }
    return 0;
}

static int readFile(void *parameters) {
    auto args = static_cast<vnop_read_args *>(parameters);
    const auto &entry = entries[indexFor(args->a_vp)];
    if (entry.directory)
        return EISDIR;
    const auto offset = uio_offset(args->a_uio);
    if (offset < 0 || uio_resid(args->a_uio) < 0)
        return EINVAL;
    if (static_cast<uint64_t>(offset) >= entry.size)
        return 0;
    const auto available = entry.size - static_cast<size_t>(offset);
    const auto remaining = static_cast<size_t>(uio_resid(args->a_uio));
    return uiomove(reinterpret_cast<const char *>(payload + entry.offset + offset),
                   static_cast<int>(available < remaining ? available : remaining), args->a_uio);
}

static int readDirectory(void *parameters) {
    auto args = static_cast<vnop_readdir_args *>(parameters);
    const auto index = indexFor(args->a_vp);
    const auto bundle = static_cast<const Bundle *>(vfs_fsprivate(vnode_mount(args->a_vp)));
    if (!bundle)
        return ENOENT;
    const auto cursor = uio_offset(args->a_uio);
    if (cursor < 0)
        return EINVAL;
    size_t seen = 0;
    if (args->a_eofflag)
        *args->a_eofflag = 0;
    if (args->a_numdirent)
        *args->a_numdirent = 0;
    for (size_t i = 0; i <= bundle->end - bundle->first; ++i) {
        const auto child = i == 0 ? index : i == 1 ? entries[index].parent : bundle->first + i - 1;
        if (i > 1 && entries[child].parent != index)
            continue;
        if (seen++ < static_cast<size_t>(cursor))
            continue;
        const auto name = i == 0 ? "." : i == 1 ? ".." : entries[child].name;
        const auto nameSize = strlen(name);
        const auto type = static_cast<uint8_t>(entries[child].directory ? DT_DIR : DT_REG);
        int result;
        if (args->a_flags & VNODE_READDIR_EXTENDED) {
            struct direntry out {};
            out.d_ino = child + 2;
            out.d_seekoff = seen;
            out.d_type = type;
            out.d_namlen = static_cast<uint16_t>(nameSize);
            out.d_reclen = static_cast<uint16_t>((offsetof(struct direntry, d_name) + nameSize + 1 + 7) & ~7U);
            if (uio_resid(args->a_uio) < out.d_reclen)
                return 0;
            memcpy(out.d_name, name, nameSize + 1);
            result = uiomove(reinterpret_cast<char *>(&out), out.d_reclen, args->a_uio);
        } else {
            struct dirent out {};
            out.d_ino = static_cast<ino_t>(child + 2);
            out.d_type = type;
            out.d_namlen = static_cast<uint8_t>(nameSize);
            out.d_reclen = static_cast<uint16_t>((offsetof(struct dirent, d_name) + nameSize + 1 + 3) & ~3U);
            if (uio_resid(args->a_uio) < out.d_reclen)
                return 0;
            memcpy(out.d_name, name, nameSize + 1);
            result = uiomove(reinterpret_cast<char *>(&out), out.d_reclen, args->a_uio);
        }
        if (result)
            return result;
        uio_setoffset(args->a_uio, seen);
        if (args->a_numdirent)
            ++*args->a_numdirent;
    }
    if (args->a_eofflag)
        *args->a_eofflag = 1;
    return 0;
}

static int pageIn(void *parameters) {
    auto args = static_cast<vnop_pagein_args *>(parameters);
    const auto &entry = entries[indexFor(args->a_vp)];
    vm_offset_t address = 0;
    int result = EINVAL;
    if (args->a_pl && args->a_f_offset >= 0 && !entry.directory) {
        result = ubc_upl_map(args->a_pl, &address);
        if (!result) {
            const auto offset = static_cast<uint64_t>(args->a_f_offset);
            const auto available = offset < entry.size ? entry.size - offset : 0;
            const auto copied = available < args->a_size ? available : args->a_size;
            auto output = reinterpret_cast<uint8_t *>(address + args->a_pl_offset);
            if (copied)
                memcpy(output, payload + entry.offset + offset, copied);
            if (copied < args->a_size)
                bzero(output + copied, args->a_size - copied);
            result = ubc_upl_unmap(args->a_pl);
        }
    }
    if (args->a_pl && !(args->a_flags & UPL_NOCOMMIT)) {
        const auto offset = args->a_pl_offset;
        const auto size = static_cast<upl_size_t>(args->a_size);
        if (result)
            ubc_upl_abort_range(args->a_pl, offset, size, UPL_ABORT_ERROR | UPL_ABORT_FREE_ON_EMPTY);
        else
            ubc_upl_commit_range(args->a_pl, offset, size, UPL_COMMIT_CLEAR_DIRTY | UPL_COMMIT_FREE_ON_EMPTY);
    }
    return result;
}

static int openFile(void *parameters) {
    auto args = static_cast<vnop_open_args *>(parameters);
    return (args->a_mode & FWRITE) ? EROFS : 0;
}

static const vnodeopv_entry_desc vnodeEntries[] = {
    {&vnop_default_desc, unsupported}, {&vnop_lookup_desc, lookup}, {&vnop_getattr_desc, attributes},
    {&vnop_open_desc, openFile}, {&vnop_close_desc, noOperation}, {&vnop_read_desc, readFile},
    {&vnop_readdir_desc, readDirectory}, {&vnop_mmap_desc, noOperation}, {&vnop_pagein_desc, pageIn},
    {&vnop_inactive_desc, noOperation}, {&vnop_reclaim_desc, noOperation}, {&vnop_fsync_desc, noOperation},
    {nullptr, nullptr},
};
static vnodeopv_desc vnodeDescriptor = {&vnodeOperations, vnodeEntries};
static vnodeopv_desc *descriptors[] = {&vnodeDescriptor, nullptr};

static void releaseNodes(mount_t mount, const Bundle &bundle) {
    for (size_t i = bundle.end; i > bundle.first; --i) {
        if (nodes[i - 1]) {
            vnode_rele(nodes[i - 1]);
            nodes[i - 1] = nullptr;
        }
    }
    vflush(mount, nullptr, FORCECLOSE);
}

static int mountOverlay(mount_t mount, vnode_t device, user_addr_t data, vfs_context_t context) {
    const auto bundle = registeringBundle;
    if (!bundle || context != vfs_context_kernel() || strcmp(vfs_statfs(mount)->f_mntonname, bundle->path) ||
        device || data || !vfs_isrdonly(mount) || nodes[bundle->first])
        return EINVAL;
    vfs_setfsprivate(mount, bundle);
    for (size_t i = bundle->first; i < bundle->end; ++i) {
        const auto &entry = entries[i];
        vnode_fsparam parameters {};
        parameters.vnfs_mp = mount;
        parameters.vnfs_vtype = entry.directory ? VDIR : VREG;
        parameters.vnfs_str = fsType;
        parameters.vnfs_dvp = i == bundle->first ? nullptr : nodes[entry.parent];
        parameters.vnfs_fsnode = const_cast<Entry *>(&entry);
        parameters.vnfs_vops = vnodeOperations;
        parameters.vnfs_markroot = i == bundle->first;
        parameters.vnfs_filesize = entry.size;
        vnode_t node = nullptr;
        auto result = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &parameters, &node);
        if (!result) {
            result = vnode_ref(node);
            if (!result) {
                nodes[i] = node;
                if (i != bundle->first)
                    vnode_update_identity(node, nodes[entry.parent], entry.name,
                        static_cast<int>(strlen(entry.name)), 0, VNODE_UPDATE_NAME);
            } else {
                vnode_recycle(node);
            }
            vnode_put(node);
        }
        if (result) {
            releaseNodes(mount, *bundle);
            vfs_setfsprivate(mount, nullptr);
            return result;
        }
    }
    vfs_getnewfsid(mount);
    return 0;
}

static int unmountOverlay(mount_t mount, int flags, vfs_context_t) {
    if (!(flags & MNT_FORCE))
        return EBUSY;
    auto bundle = static_cast<const Bundle *>(vfs_fsprivate(mount));
    if (bundle)
        releaseNodes(mount, *bundle);
    vfs_setfsprivate(mount, nullptr);
    return 0;
}

static int root(mount_t mount, vnode_t *out, vfs_context_t) {
    auto bundle = static_cast<const Bundle *>(vfs_fsprivate(mount));
    return bundle ? acquire(bundle->first, out) : ENOENT;
}

static int fsAttributes(mount_t mount, vfs_attr *attributes, vfs_context_t) {
    auto bundle = static_cast<const Bundle *>(vfs_fsprivate(mount));
    if (!bundle)
        return ENOENT;
    const auto &last = entries[bundle->end - 1];
    const auto size = last.offset + last.size - entries[bundle->first].offset;
    VFSATTR_RETURN(attributes, f_bsize, PAGE_SIZE);
    VFSATTR_RETURN(attributes, f_iosize, PAGE_SIZE);
    VFSATTR_RETURN(attributes, f_blocks, atop(round_page(size)));
    VFSATTR_RETURN(attributes, f_bfree, 0);
    VFSATTR_RETURN(attributes, f_bavail, 0);
    VFSATTR_RETURN(attributes, f_files, bundle->end - bundle->first);
    VFSATTR_RETURN(attributes, f_ffree, 0);
    return 0;
}

static vfsops filesystem;

static KernelMount resolveKernelMount() {
    auto origin = reinterpret_cast<const uint8_t *>(vfs_mount_at_path);
    if (memcmp(origin, mountEntryBytes, sizeof(mountEntryBytes)))
        return nullptr;
    auto target = origin + kernelMountDelta;
    if (memcmp(target, kernelMountBytes, sizeof(kernelMountBytes)))
        return nullptr;
    return reinterpret_cast<KernelMount>(const_cast<uint8_t *>(target));
}

static int registerOverlay() {
    filesystem.vfs_mount = mountOverlay;
    filesystem.vfs_unmount = unmountOverlay;
    filesystem.vfs_root = root;
    filesystem.vfs_getattr = fsAttributes;
    vfs_fsentry registration {};
    registration.vfe_vfsops = &filesystem;
    registration.vfe_vopcnt = 1;
    registration.vfe_opvdescs = descriptors;
    strlcpy(registration.vfe_fsname, fsType, sizeof(registration.vfe_fsname));
    registration.vfe_flags = VFS_TBLTHREADSAFE | VFS_TBLNOTYPENUM | VFS_TBLLOCALVOL | VFS_TBL64BITREADY |
                             VFS_TBLGENERICMNTARGS | VFS_TBLREADDIR_EXTENDED;
    return vfs_fsadd(&registration, &fsHandle);
}

static void mountBundle(Bundle &bundle, KernelMount kernelMount, vfs_context_t context) {
    registeringBundle = &bundle;
    auto result = kernelMount(fsType, nullptr, nullptr, bundle.path, nullptr,
        MNT_RDONLY | MNT_NOSUID | MNT_NODEV | MNT_DONTBROWSE, 0, context);
    registeringBundle = nullptr;
    if (result) {
        bundle.error = result;
        bundle.state = "MountFailed";
        return;
    }
    vnode_t executable = nullptr;
    result = vnode_lookup(bundle.executable, 0, &executable, context);
    if (!result) {
        if (vfs_fsprivate(vnode_mount(executable)) != &bundle || !vnode_isreg(executable))
            result = ENOEXEC;
        vnode_put(executable);
    }
    bundle.error = result;
    bundle.state = result ? "ExecutableLookupFailed" : "Mounted";
}

static void setOverlayState(const char *state, int error) {
    __atomic_store_n(&overlayError, error, __ATOMIC_RELAXED);
    __atomic_store_n(&overlayState, state, __ATOMIC_RELEASE);
}

static void mountBootBundles() {
    auto kernelMount = resolveKernelMount();
    auto context = vfs_context_kernel();
    const auto error = kernelMount && context ? registerOverlay() : ENOTSUP;
    for (auto &bundle : bundles) {
        if (error) {
            bundle.error = error;
            bundle.state = "FilesystemUnavailable";
        } else {
            mountBundle(bundle, kernelMount, context);
        }
        SYSLOG("eapol", "%s before launchd: %s (%d)", bundle.name, bundle.state, bundle.error);
    }
    if (!error) {
        bool hasMount = false;
        for (const auto &bundle : bundles)
            hasMount = hasMount || nodes[bundle.first];
        if (!hasMount)
            vfs_fsremove(fsHandle);
    }
    setOverlayState(bundles[0].state, bundles[0].error);
}

static bool replaceInitDisplacement(uint32_t expected, uint32_t replacement) {
    const auto interrupts = ml_set_interrupts_enabled(false);
    uintptr_t cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0) :: "memory");
    const auto writable = cr0 & ~(uintptr_t {1} << 16);
    asm volatile("mov %0, %%cr0" :: "r"(writable) : "memory");
    const auto replaced = __atomic_compare_exchange_n(initCallDisplacement, &expected, replacement, false,
                                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    asm volatile("mov %0, %%cr0" :: "r"(cr0) : "memory");
    ml_set_interrupts_enabled(interrupts);
    return replaced;
}

static void loadInitWithBundles(proc_t process) {
    if (!replaceInitDisplacement(overlayInitDisplacement, originalInitDisplacement)) {
        setOverlayState("InitCallChanged", EBUSY);
    } else if (proc_pid(process) != 1) {
        setOverlayState("UnexpectedInitProcess", EINVAL);
    } else {
        mountBootBundles();
    }
    load_init_program(process);
}

}

void prepareEAPOLOverlay() {
    if (getKernelVersion() != GoldenGateABI.kernel)
        return;
    if (!resolveKernelMount()) {
        setOverlayState("KernelMountABIUnavailable", ENOTSUP);
        return;
    }
    if (auto rootNode = vfs_rootvnode()) {
        vnode_put(rootNode);
        setOverlayState("RootAlreadyMounted", EBUSY);
        return;
    }
    const auto call = reinterpret_cast<uintptr_t>(bsdinit_task) + initCallOffset;
    const auto next = call + 5;
    const auto displacement = static_cast<intptr_t>(reinterpret_cast<uintptr_t>(loadInitWithBundles) - next);
    const auto original = static_cast<intptr_t>(reinterpret_cast<uintptr_t>(load_init_program) - next);
    if ((call + 1) % alignof(uint32_t) || displacement != static_cast<int32_t>(displacement) ||
        original != initCallOriginal || memcmp(reinterpret_cast<const void *>(call - 3), initCallBytes, sizeof(initCallBytes))) {
        setOverlayState("InitCallABIUnavailable", ENOTSUP);
        return;
    }
    initCallDisplacement = reinterpret_cast<uint32_t *>(call + 1);
    originalInitDisplacement = static_cast<uint32_t>(original);
    overlayInitDisplacement = static_cast<uint32_t>(displacement);
    setOverlayState("WaitingForInit", 0);
    if (!replaceInitDisplacement(originalInitDisplacement, overlayInitDisplacement))
        setOverlayState("InitCallChanged", EBUSY);
}

void publishEAPOLOverlay(IOService *service) {
    if (getKernelVersion() == GoldenGateABI.kernel) {
        const auto state = __atomic_load_n(&overlayState, __ATOMIC_ACQUIRE);
        service->setProperty("EAPOLOverlayState", state);
        service->setProperty("EAPOLOverlayError", __atomic_load_n(&overlayError, __ATOMIC_RELAXED), 32);
        if (strcmp(state, "WaitingForInit")) {
            service->setProperty("AWDLOverlayState", bundles[1].state);
            service->setProperty("AWDLOverlayError", bundles[1].error, 32);
        }
    }
}

}
