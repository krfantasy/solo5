/*
 * Copyright (c) 2015-2019 Contributors as noted in the AUTHORS file
 *
 * This file is part of Solo5, a sandboxed execution environment.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * hvt_hvf.c: Darwin Hypervisor.framework backend - host-independent part.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <grp.h>
#include <pwd.h>
#include <sandbox.h>
#include <sys/ptrace.h>

#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vm.h>

#include "hvt.h"
#include "hvt_hvf.h"
#include "hvt_cpu_aarch64.h"

struct hvt *hvt_init(size_t mem_size)
{
    hv_return_t ret;
    struct hvt *hvt = malloc(sizeof(struct hvt));
    if (hvt == NULL)
        err(1, "malloc");
    memset(hvt, 0, sizeof(struct hvt));
    struct hvt_b *hvb = malloc(sizeof(struct hvt_b));
    if (hvb == NULL)
        err(1, "malloc");
    memset(hvb, 0, sizeof(struct hvt_b));

    ret = hv_vm_create(NULL);
    if (ret != HV_SUCCESS) {
#ifndef HV_DENIED
#define HV_DENIED ((hv_return_t)0xfae94007)
#endif
        if (ret == HV_DENIED)
            errx(1,
                 "hv_vm_create failed: 0x%x (HV_DENIED) — binary lacks "
                 "com.apple.security.hypervisor entitlement. Fix: "
                 "codesign -s - --entitlements "
                 "tenders/hvt/solo5-hvt.entitlements "
                 "--force %s (see docs/building.md)",
                 ret, "tenders/hvt/solo5-hvt");
        errx(1, "hv_vm_create failed: 0x%x", ret);
    }

    hvt->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (hvt->mem == MAP_FAILED)
        err(1, "mmap guest memory failed");

    hvt->guest_mem_size = mem_size;
    hvt->mem_alloc_size = mem_size;

    ret = hv_vm_map(hvt->mem, 0, mem_size,
                    HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
    if (ret != HV_SUCCESS)
        errx(1, "hv_vm_map failed: 0x%x", ret);

    hvb->has_ioeventfd = 0;
    hvb->kick_net_efd = -1;
    hvb->net_ring_gpa = 0;

    hvt->b = hvb;
    return hvt;
}

#if defined(HVT_DROP_PRIVILEGES) && HVT_DROP_PRIVILEGES == 1
void hvt_drop_privileges(void)
{
    /*
     * Layer 1: drop root. Tender is normally run as the invoking user,
     * but operators sometimes run as root for /dev/disk* block images.
     * Refuse to keep UID 0 into the run loop: switch to "nobody"
     * (UID -2 on macOS). Check both real and effective UIDs so a
     * hypothetical setuid-root install cannot slip through with
     * ruid != 0. Non-root invokers skip this. Note: without privilege
     * supplementary groups cannot be cleared, so group-readable files
     * stay readable post-escape -- covered by the residual-risk note
     * in docs/building.md.
     */
    if (getuid() == 0 || geteuid() == 0) {
        struct passwd *pw = getpwnam("nobody");
        if (pw == NULL)
            errx(1, "getpwnam(nobody) failed");
        /* XNU setuid() does not clear supplementary groups; drop them. */
        if (setgroups(0, NULL) == -1)
            err(1, "setgroups() failed");
        if (setgid(pw->pw_gid) == -1)
            err(1, "setgid(nobody) failed");
        if (setuid(pw->pw_uid) == -1)
            err(1, "setuid(nobody) failed");
    }

    /*
     * Layer 2: Seatbelt sandbox. Applied after all setup (hv_vm_create,
     * mmap, hv_vm_map, vcpu_create, module setup, boot_info) so only the
     * run loop is confined. sandbox_init(2) accepts only named profiles
     * (custom profile strings return "profile not found"). Of those,
     * kSBXProfilePureComputation blocks the most for this tender: new
     * path-based file writes AND new network socket use are both
     * prohibited, while everything the run loop needs still works --
     * descriptors already open when the sandbox is applied (console
     * stdio, pre-opened block image pwrite/pread, AF_UNIX @fd
     * socketpairs), kqueue/kevent, and Hypervisor.framework calls all
     * succeed under it (probed on Darwin/arm64; the full test suite
     * and a MirageOS/cohttp unikernel serving HTTP over @fd run green
     * with this profile). The weaker named profiles each leave one
     * axis open: kSBXProfileNoWrite still allows new network sockets;
     * kSBXProfileNoInternet/NoNetwork still allow new path-based file
     * writes. No path writes are needed after this point: dumpcore is
     * only built into the debug tender, which is not sandboxed
     * (HVT_DROP_PRIVILEGES=0).
     * NOTE: <sandbox.h> and the kSBXProfile* constants are marked
     * deprecated by the SDK ("No longer supported" since the 10.8
     * annotations; header warns it "may be removed in a future
     * release") yet still enforced on current macOS. If removed,
     * revisit via App Sandbox bundling or Hardened Runtime /
     * library-validation hardening (see docs/building.md, Darwin
     * tender sandbox).
     */
    {
        char *errbuf = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (sandbox_init(kSBXProfilePureComputation, SANDBOX_NAMED, &errbuf) ==
            -1) {
            if (errbuf != NULL) {
                warnx("sandbox_init failed: %s", errbuf);
                sandbox_free_error(errbuf);
            } else {
                warnx("sandbox_init failed: unknown error");
            }
            errx(1, "sandbox_init failed");
        }
        if (errbuf != NULL)
            sandbox_free_error(errbuf);
#pragma clang diagnostic pop
    }

    /*
     * Layer 3: anti-debug. PT_DENY_ATTACH prevents same-UID debugger
     * attach (lldb/dtrace) for the rest of the process lifetime, so a
     * same-UID attacker cannot attach to dump guest memory or file
     * descriptors. It does NOT prevent exec-time DYLD_* injection; that
     * requires Hardened Runtime/library validation in the code-signing
     * step, which is not enabled (see docs/building.md, Darwin tender
     * sandbox). Debug binary is built with HVT_DROP_PRIVILEGES=0 so
     * lldb still works there; this only affects the production tender.
     */
    if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1)
        errx(1, "ptrace(PT_DENY_ATTACH) failed");
}
#endif

int hvt_guest_mprotect(void *t_arg, uint64_t addr_start, uint64_t addr_end,
                       int prot)
{
    struct hvt *hvt = t_arg;

    assert(addr_start <= hvt->guest_mem_size);
    assert(addr_end <= hvt->guest_mem_size);
    assert(addr_start < addr_end);

    uint8_t *vaddr_start = hvt->mem + addr_start;
    assert(vaddr_start >= hvt->mem);
    size_t size = addr_end - addr_start;
    assert(size > 0 && size <= hvt->guest_mem_size);
    assert((addr_start & 0xfff) == 0);
    assert((size & 0xfff) == 0);

    if (prot & PROT_WRITE && prot & PROT_EXEC) {
        warnx("hvt_guest_mprotect: W+X rejected");
        errno = EINVAL;
        return -1;
    }

    /* Defer actual protections until after aarch64_setup_memory_mapping()
     * (which zeroes page tables) and after all ELF segments are loaded
     * (host mprotect at 16K would otherwise make next pread fail due to
     * read-only host page sharing a 16K host page with the next RW segment).
     * Just record the range; hvt_hvf_apply_deferred_protections() in
     * hvt_vcpu_init() will enforce host, stage-2, and guest stage-1 at the
     * appropriate granularities. */
    (void)vaddr_start;
    (void)size;
    /* Defer to apply after page tables and ELF loads (see deferred apply) */
    extern int hvt_hvf_record_prot(uint64_t s, uint64_t e, int p);
    if (hvt_hvf_record_prot(addr_start, addr_end, prot) == -1)
        return -1;
    return 0;
}

#define HVT_HVF_MAX_PROT_RANGES 16
struct hvf_range {
    uint64_t start;
    uint64_t end;
    int prot;
};
static struct hvf_range hvf_prot_ranges[HVT_HVF_MAX_PROT_RANGES];
static int hvf_nprot = 0;

int hvt_hvf_record_prot(uint64_t s, uint64_t e, int p)
{
    if (hvf_nprot >= HVT_HVF_MAX_PROT_RANGES) {
        warnx("hvt_guest_mprotect: too many ranges");
        errno = ENOMEM;
        return -1;
    }
    hvf_prot_ranges[hvf_nprot].start = s;
    hvf_prot_ranges[hvf_nprot].end = e;
    hvf_prot_ranges[hvf_nprot].prot = p;
    hvf_nprot++;
    return 0;
}

/*
 * Returns the recorded protection of the 4K page at (pa) (which must be
 * 4K-aligned), or -1 if the page is not covered by any ELF segment. A 4K
 * page belongs to at most one range: elf_load() rejects segments that are
 * not 4K-aligned and ranges do not overlap.
 */
static int hvf_pa_prot(uint64_t pa)
{
    for (int i = 0; i < hvf_nprot; i++)
        if (hvf_prot_ranges[i].start <= pa && pa < hvf_prot_ranges[i].end)
            return hvf_prot_ranges[i].prot;
    return -1;
}

/*
 * Maps POSIX prot flags to guest stage-1 PTE flags. 0 means "unmapped"
 * (PROT_NONE segment); mapped results always include PGT_DESC_TYPE_PAGE.
 */
static uint64_t hvf_prot_to_pte(int prot)
{
    if (prot & PROT_WRITE)
        return PROT_PAGE_NORMAL; /* RW, non-exec */
    if (prot & PROT_EXEC)
        return PROT_PAGE_NORMAL_EXEC_RO; /* RX (EL1-executable, RO) */
    if (prot & PROT_READ)
        return PROT_PAGE_NORMAL_RO; /* R, non-exec */
    return 0; /* unmapped */
}

/*
 * Stage-2 W^X sweep: all guest RAM not covered by an ELF segment (heap,
 * stack, boot-info and page-table areas) becomes RW, non-executable, in one
 * bulk hv_vm_protect per contiguous region. Regions are 16K-aligned because
 * hv_vm_protect operates on host pages; a host page partially covered by a
 * recorded range keeps its union permissions here and is refined by the
 * guest stage-1 tables instead.
 */
static void hvt_hvf_nx_sweep(struct hvt *hvt)
{
    size_t host_ps = (size_t)getpagesize();

    /* Ranges arrive sorted by ascending p_vaddr with no overlaps: elf_load()
     * rejects anything else, so no local sort is needed. */
    uint64_t pos = 0;
    for (int i = 0; i <= hvf_nprot; i++) {
        uint64_t s = (i < hvf_nprot)
                         ? (hvf_prot_ranges[i].start & ~(host_ps - 1))
                         : hvt->guest_mem_size;
        if (s > pos) {
            hv_return_t ret = hv_vm_protect((hv_ipa_t)pos, (size_t)(s - pos),
                                            HV_MEMORY_READ | HV_MEMORY_WRITE);
            if (ret != HV_SUCCESS)
                errx(1,
                     "hv_vm_protect (W^X sweep) [0x%llx-0x%llx) failed: "
                     "0x%x",
                     (unsigned long long)pos, (unsigned long long)s, ret);
        }
        if (i < hvf_nprot) {
            uint64_t e =
                (hvf_prot_ranges[i].end + host_ps - 1) & ~(host_ps - 1);
            if (e > pos)
                pos = e;
        }
    }
}

/*
 * Guest stage-1 page tables for 2MB blocks above the first, giving 4K-precise
 * W^X for ELF images that extend past 2MB (where the initial mapping is
 * coarse RWX 2MB sections and stage-2 unions are 16K host pages). The table
 * pages are placed in the read-only hvt-to-guest area [0x20000, 0x100000):
 * the guest can read but not write them, and no guest-visible memory layout
 * changes. Blocks beyond the image (heap) keep their 2MB sections; stage 2
 * already makes them RW/NX.
 */
#define HVT_HVF_PTE_REGION_BASE 0x20000UL
#define HVT_HVF_PTE_REGION_END  AARCH64_GUEST_MIN_BASE /* 0x100000 */
#define HVT_HVF_PTE_MAX_TABLES                                                 \
    ((HVT_HVF_PTE_REGION_END - HVT_HVF_PTE_REGION_BASE) / PAGE_SIZE) /* 224 */

static void hvt_hvf_wire_block_ptes(struct hvt *hvt, uint64_t max_end)
{
    const uint64_t block_size = AARCH64_GUEST_BLOCK_SIZE; /* 2MB */
    uint64_t nblocks = (max_end + block_size - 1) / block_size;

    if (nblocks <= 1)
        return; /* image entirely below 2MB: the first-block PTEs suffice */

    if (nblocks - 1 > HVT_HVF_PTE_MAX_TABLES)
        errx(1,
             "hvt_hvf: image end 0x%llx exceeds precise W^X capacity "
             "(%d blocks); refusing to run with coarse RWX tail",
             (unsigned long long)max_end, (int)HVT_HVF_PTE_MAX_TABLES);

    uint64_t *pmd = (uint64_t *)(hvt->mem + AARCH64_PMD_PGT_BASE);
    for (uint64_t b = 1; b < nblocks; b++) {
        uint64_t tbl_gpa = HVT_HVF_PTE_REGION_BASE + (b - 1) * PAGE_SIZE;
        uint64_t *tbl = (uint64_t *)(hvt->mem + tbl_gpa);

        memset(tbl, 0, PAGE_SIZE);
        for (uint64_t off = 0; off < block_size; off += PAGE_SIZE) {
            uint64_t pa = b * block_size + off;
            int prot = hvf_pa_prot(pa);
            if (prot == -1)
                /* Uncovered page inside the image block: heap gap. RW, NX. */
                tbl[off / PAGE_SIZE] = pa | PROT_PAGE_NORMAL;
            else {
                uint64_t flags = hvf_prot_to_pte(prot);
                if (flags == 0)
                    tbl[off / PAGE_SIZE] = 0; /* PROT_NONE segment */
                else
                    tbl[off / PAGE_SIZE] = pa | flags;
            }
        }
        pmd[b] = tbl_gpa | PGT_DESC_TYPE_TABLE;
    }
}

/* Called from hvt_vcpu_init() after page tables are set up. */
void hvt_hvf_apply_deferred_protections(struct hvt *hvt)
{
    if (hvf_nprot == 0)
        return;
    size_t host_ps = (size_t)getpagesize();
    uint64_t min_start = hvf_prot_ranges[0].start;
    uint64_t max_end = hvf_prot_ranges[0].end;
    for (int i = 1; i < hvf_nprot; i++) {
        if (hvf_prot_ranges[i].start < min_start)
            min_start = hvf_prot_ranges[i].start;
        if (hvf_prot_ranges[i].end > max_end)
            max_end = hvf_prot_ranges[i].end;
    }
    uint64_t host_start = min_start & ~(host_ps - 1);
    uint64_t host_end = (max_end + host_ps - 1) & ~(host_ps - 1);
    for (uint64_t hpa = host_start; hpa < host_end; hpa += host_ps) {
        int need_write = 0, need_exec = 0, need_read = 0, covered = 0;
        for (int i = 0; i < hvf_nprot; i++) {
            uint64_t s = hvf_prot_ranges[i].start;
            uint64_t e = hvf_prot_ranges[i].end;
            int prot = hvf_prot_ranges[i].prot;
            if (hpa + host_ps <= s || hpa >= e)
                continue;
            covered = 1;
            if (prot & PROT_WRITE)
                need_write = 1;
            if (prot & PROT_EXEC)
                need_exec = 1;
            if (prot & PROT_READ)
                need_read = 1;
            if (prot & PROT_EXEC)
                need_read = 1;
        }
        if (!covered)
            continue;
        int host_prot = 0;
        if (need_read || need_exec || need_write)
            host_prot |= PROT_READ;
        if (need_write)
            host_prot |= PROT_WRITE;
        if (host_prot == 0)
            /* Keep the page readable for tender-side accesses (e.g. dumpcore
             * pwrite of guest memory); stage-1 patching handles revocation. */
            host_prot = PROT_READ;
        uint8_t *hva = hvt->mem + hpa;
        if (mprotect(hva, host_ps, host_prot) == -1)
            warn("mprotect deferred host page 0x%llx", (unsigned long long)hpa);
        hv_memory_flags_t hv_flags = 0;
        if (need_read || need_exec)
            hv_flags |= HV_MEMORY_READ;
        if (need_write)
            hv_flags |= HV_MEMORY_WRITE;
        if (need_exec)
            hv_flags |= HV_MEMORY_EXEC;
        if (hv_flags & HV_MEMORY_EXEC)
            hv_flags |= HV_MEMORY_READ;
        hv_return_t ret = hv_vm_protect((hv_ipa_t)hpa, host_ps, hv_flags);
        if (ret != HV_SUCCESS)
            errx(1,
                 "hv_vm_protect deferred host page 0x%llx flags 0x%llx failed: "
                 "0x%x",
                 (unsigned long long)hpa, (unsigned long long)hv_flags, ret);
    }
    /* Stage-2: everything not covered by an ELF segment (heap, stack, boot
     * info, page tables) becomes RW, non-executable. */
    hvt_hvf_nx_sweep(hvt);
    /* Guest stage-1 4K PTE patching for precise W^X inside the first 2MB.
     * Ranges entirely above 2MB get no stage-1 patching here. */
    {
        uint64_t *pte = (uint64_t *)(hvt->mem + AARCH64_PTE_PGT_BASE);
        for (int i = 0; i < hvf_nprot; i++) {
            uint64_t s = hvf_prot_ranges[i].start;
            uint64_t e = hvf_prot_ranges[i].end;
            uint64_t pte_flags = hvf_prot_to_pte(hvf_prot_ranges[i].prot);
            uint64_t ps =
                s < AARCH64_GUEST_BLOCK_SIZE ? s : AARCH64_GUEST_BLOCK_SIZE;
            uint64_t pe =
                e < AARCH64_GUEST_BLOCK_SIZE ? e : AARCH64_GUEST_BLOCK_SIZE;
            if (ps >= pe)
                continue;
            for (uint64_t pa = ps & ~(uint64_t)(PAGE_SIZE - 1); pa < pe;
                 pa += PAGE_SIZE) {
                if (pa < AARCH64_PGT_MAP_START)
                    continue;
                size_t idx = pa / PAGE_SIZE;
                if (pte_flags == 0)
                    pte[idx] = 0;
                else
                    pte[idx] = pa | pte_flags;
            }
        }
        /* Uncovered pages below 2MB are heap: RW, non-executable. (Below
         * AARCH64_GUEST_MIN_BASE the initial mapping is already read-only
         * hvt-to-guest input; the sweep covers those in stage 2.) */
        for (uint64_t pa = AARCH64_GUEST_MIN_BASE;
             pa < AARCH64_GUEST_BLOCK_SIZE; pa += PAGE_SIZE) {
            if (hvf_pa_prot(pa) != -1)
                continue;
            pte[pa / PAGE_SIZE] = pa | PROT_PAGE_NORMAL;
        }
    }
    /* Guest stage-1 above 2MB: 4K tables for the blocks containing the ELF
     * image, refining the coarse 16K stage-2 unions to precise W^X. */
    hvt_hvf_wire_block_ptes(hvt, max_end);

    /*
     * The spill tables are live guest stage-1 state from here on and no
     * tender code writes them again. Make the host mapping read-only so
     * a hypercall path that ever skips the GPA floors (or a hypercall
     * struct parked inside the window, which the struct floor permits)
     * cannot corrupt live page tables via hvt->mem: such a write now
     * fails loudly (SIGSEGV on a direct store, EFAULT -> exit(1) on
     * pread/read) instead of silently flipping PTE flags. Guest-visible
     * mappings are unchanged: stage-1 already maps the window read-only.
     */
    {
        uint64_t s = HVT_HVF_PTE_REGION_BASE & ~(host_ps - 1);
        uint64_t e = (HVT_HVF_PTE_REGION_END + host_ps - 1) & ~(host_ps - 1);
        if (mprotect(hvt->mem + s, e - s, PROT_READ) == -1)
            errx(1,
                 "mprotect PTE spill window [0x%llx, 0x%llx) read-only "
                 "failed",
                 (unsigned long long)s, (unsigned long long)e);
    }
}
