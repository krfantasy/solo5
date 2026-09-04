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
 * hvt_hvf_aarch64.c: Darwin Hypervisor.framework aarch64 backend.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <string.h>
#include <sys/mman.h>

#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vcpu.h>
#include <Hypervisor/hv_vm.h>

#include "hvt.h"
#include "hvt_hvf.h"
#include "hvt_cpu_aarch64.h"

/* Helper to handle hv errors */
static void hv_check(hv_return_t ret, const char *msg)
{
    if (ret != HV_SUCCESS)
        errx(1, "%s failed: 0x%x", msg, ret);
}

void hvt_mem_size(size_t *mem_size)
{
    aarch64_mem_size(mem_size);
}

void hvt_mem_size_roundup(size_t *mem_size)
{
    size_t mem = ((*mem_size + AARCH64_GUEST_BLOCK_SIZE - 1) /
                  AARCH64_GUEST_BLOCK_SIZE) *
                 AARCH64_GUEST_BLOCK_SIZE;
    if (mem > AARCH64_MMIO_BASE)
        mem = AARCH64_MMIO_BASE;
    *mem_size = mem;
}

void hvt_vcpu_init(struct hvt *hvt, hvt_gpa_t gpa_ep)
{
    hv_return_t ret;
    struct hvt_b *hvb = hvt->b;

    /* Set up guest page tables (1:1 VA=PA, 4GB RAM + MMIO) */
    aarch64_setup_memory_mapping(hvt->mem, hvt->mem_alloc_size);

    /* Apply deferred W^X protections recorded during elf_load().
     * Host and stage-2 are 16K-granular (union per host page); guest
     * stage-1 is 4K via PTE patching below 2MB and via block PTE wiring
     * for the ELF image above 2MB — 4K-precise W^X across the whole
     * image. */
    extern void hvt_hvf_apply_deferred_protections(struct hvt * hvt);
    hvt_hvf_apply_deferred_protections(hvt);

    /* Create vCPU */
    ret = hv_vcpu_create(&hvb->vcpu, &hvb->vcpu_exit, NULL);
    hv_check(ret, "hv_vcpu_create");

    /* Enable FP/SIMD via CPACR */
    uint64_t cpacr;
    ret = hv_vcpu_get_sys_reg(hvb->vcpu, HV_SYS_REG_CPACR_EL1, &cpacr);
    /* If get fails, start from 0 */
    if (ret != HV_SUCCESS)
        cpacr = 0;
    cpacr &= ~((uint64_t)0x3 << 20);
    cpacr |= ((uint64_t)0x3 << 20);
    ret = hv_vcpu_set_sys_reg(hvb->vcpu, HV_SYS_REG_CPACR_EL1, cpacr);
    hv_check(ret, "hv_vcpu_set_sys_reg(CPACR_EL1)");

    /* MAIR */
    /* Use the same value as KVM path */
    uint64_t mair = 0;
    mair |= (0x00ULL << (0 * 8));
    mair |= (0x04ULL << (1 * 8));
    mair |= (0x0CULL << (2 * 8));
    mair |= (0x44ULL << (3 * 8));
    mair |= (0xFFULL << (4 * 8));
    mair |= (0xBBULL << (5 * 8));
    ret = hv_vcpu_set_sys_reg(hvb->vcpu, HV_SYS_REG_MAIR_EL1, mair);
    hv_check(ret, "hv_vcpu_set_sys_reg(MAIR_EL1)");

    /* TCR */
    uint64_t tcr = 0;
    /* VA_BITS 40, 1TB, same as KVM */
    tcr |= ((64ULL - 40) << 0); /* T0SZ */
    tcr |= ((64ULL - 40) << 16); /* T1SZ */
    tcr |= (1ULL << 8) | (1ULL << 24); /* IRGN WBWA */
    tcr |= (1ULL << 10) | (1ULL << 26); /* ORGN WBWA */
    tcr |= (3ULL << 12) | (3ULL << 28); /* SH inner */
    tcr |= (0ULL << 14) | (2ULL << 30); /* TG0 4K, TG1 4K */
    tcr |= (1ULL << 36); /* ASID16 */
    tcr |= (1ULL << 37); /* TBI0 */
    tcr |= (2ULL << 32); /* IPS 1TB */
    ret = hv_vcpu_set_sys_reg(hvb->vcpu, HV_SYS_REG_TCR_EL1, tcr);
    hv_check(ret, "hv_vcpu_set_sys_reg(TCR_EL1)");

    /* TTBR0 */
    ret = hv_vcpu_set_sys_reg(hvb->vcpu, HV_SYS_REG_TTBR0_EL1,
                              AARCH64_PGD_PGT_BASE);
    hv_check(ret, "hv_vcpu_set_sys_reg(TTBR0_EL1)");

    /* SCTLR */
    uint64_t sctlr = (1ULL << 0) | (1ULL << 2) | (1ULL << 12); /* M | C | I */
    ret = hv_vcpu_set_sys_reg(hvb->vcpu, HV_SYS_REG_SCTLR_EL1, sctlr);
    hv_check(ret, "hv_vcpu_set_sys_reg(SCTLR_EL1)");

    /* PSTATE: EL1h, DAIF masked */
    uint64_t cpsr = 0x3c5; /* D|A|I|F + EL1h */
    ret = hv_vcpu_set_reg(hvb->vcpu, HV_REG_CPSR, cpsr);
    hv_check(ret, "hv_vcpu_set_reg(CPSR)");

    /* Stack pointer EL1 */
    ret = hv_vcpu_set_sys_reg(hvb->vcpu, HV_SYS_REG_SP_EL1,
                              hvt->guest_mem_size - 16);
    hv_check(ret, "hv_vcpu_set_sys_reg(SP_EL1)");

    /* Boot info in X0 */
    ret = hv_vcpu_set_reg(hvb->vcpu, HV_REG_X0, AARCH64_BOOT_INFO);
    hv_check(ret, "hv_vcpu_set_reg(X0)");
    hvt->cpu_boot_info_base = AARCH64_BOOT_INFO;

    /* PC */
    ret = hv_vcpu_set_reg(hvb->vcpu, HV_REG_PC, gpa_ep);
    hv_check(ret, "hv_vcpu_set_reg(PC)");

    /* Cycle frequency via cntfrq_el0 */
    uint64_t frq;
    __asm__ __volatile__("mrs %0, cntfrq_el0" : "=r"(frq)::"memory");
    hvt->cpu_cycle_freq = frq;
}

/* Syndrome decoding helpers for Data Abort */
#define ESR_EC_SHIFT      26
#define ESR_EC_MASK       0x3F
#define ESR_ISS_ISV       (1ULL << 24)
#define ESR_ISS_SAS_SHIFT 22
#define ESR_ISS_SAS_MASK  3
#define ESR_ISS_SRT_SHIFT 16
#define ESR_ISS_SRT_MASK  0x1F
#define ESR_ISS_WnR       (1ULL << 6)
#define ESR_EC_DABT_LOWER 0x24
#define ESR_EC_DABT_CUR   0x25
#define ESR_EC_IABT_LOWER 0x20
#define ESR_EC_IABT_CUR   0x21

int hvt_vcpu_loop(struct hvt *hvt)
{
    struct hvt_b *hvb = hvt->b;
    hv_return_t ret;
    unsigned ncanceled = 0;

    while (1) {
        ret = hv_vcpu_run(hvb->vcpu);
        if (ret != HV_SUCCESS) {
            if (ret == HV_BUSY)
                continue;
            errx(1, "hv_vcpu_run failed: 0x%x", ret);
        }

        /* Check for pending vm exits via registered handlers */
        int handled = 0;
        for (hvt_vmexit_fn_t *fn = hvt_core_vmexits; *fn && !handled; fn++)
            handled = ((*fn)(hvt) == 0);
        if (handled)
            continue;

        hv_vcpu_exit_t *exit = hvb->vcpu_exit;
        if (exit->reason == HV_EXIT_REASON_CANCELED) {
            /* Expected when the vCPU is preempted externally (e.g. a future
             * hv_vcpu_interrupt() from a debugger thread); without a bound,
             * a stuck cancel state would busy-loop a core. */
            if (++ncanceled >= 100000) {
                sched_yield();
                ncanceled = 0;
            }
            continue;
        }
        ncanceled = 0;
        if (exit->reason == HV_EXIT_REASON_VTIMER_ACTIVATED) {
            /* VTimer not used by Solo5, just clear mask and continue */
            hv_vcpu_set_vtimer_mask(hvb->vcpu, false);
            continue;
        } else if (exit->reason != HV_EXIT_REASON_EXCEPTION) {
            uint64_t pc;
            hv_vcpu_get_reg(hvb->vcpu, HV_REG_PC, &pc);
            errx(1, "Unexpected HV exit reason %d pc=0x%llx syndrome=0x%llx",
                 exit->reason, (unsigned long long)pc,
                 (unsigned long long)exit->exception.syndrome);
        }

        uint64_t syndrome = exit->exception.syndrome;
        uint64_t ec = (syndrome >> ESR_EC_SHIFT) & ESR_EC_MASK;

        if (ec == ESR_EC_DABT_LOWER || ec == ESR_EC_DABT_CUR) {
            bool isv = (syndrome >> 24) & 1;
            bool wnr = (syndrome >> 6) & 1;
            uint64_t far = exit->exception.virtual_address;
            uint64_t ipa = exit->exception.physical_address;

            if (!isv) {
                /* Syndrome not valid, need to decode instruction */
                uint64_t pc;
                hv_vcpu_get_reg(hvb->vcpu, HV_REG_PC, &pc);
                errx(1,
                     "Data abort with invalid syndrome: pc=0x%llx far=0x%llx "
                     "ipa=0x%llx esr=0x%llx",
                     (unsigned long long)pc, (unsigned long long)far,
                     (unsigned long long)ipa, (unsigned long long)syndrome);
            }

            if (!wnr) {
                uint64_t pc;
                hv_vcpu_get_reg(hvb->vcpu, HV_REG_PC, &pc);
                errx(1, "Unexpected data abort read: pc=0x%llx ipa=0x%llx",
                     (unsigned long long)pc, (unsigned long long)ipa);
            }

            uint64_t srt = (syndrome >> 16) & 0x1F;
            uint64_t sas = (syndrome >> 22) & 0x3;

            /* Solo5 hypercalls and ring kicks are 32-bit stores; the stored
             * value is read from register srt (xzr reads as zero). This
             * matches the KVM backend's strict 32-bit MMIO length check. */
            if (sas != 2) {
                uint64_t pc_dbg;
                hv_vcpu_get_reg(hvb->vcpu, HV_REG_PC, &pc_dbg);
                errx(1,
                     "Invalid guest mmio access: ipa=0x%llx len=%d "
                     "pc=0x%llx esr=0x%llx far=0x%llx",
                     (unsigned long long)ipa, 1 << sas,
                     (unsigned long long)pc_dbg, (unsigned long long)syndrome,
                     (unsigned long long)far);
            }
            uint64_t reg_val = 0;
            if (srt < 31) {
                hv_vcpu_get_reg(hvb->vcpu, HV_REG_X0 + srt, &reg_val);
                if (sas == 2) /* 32-bit */
                    reg_val &= 0xffffffffULL;
            } else {
                /* xzr */
                reg_val = 0;
            }

            /* Check if this is a hypercall MMIO */
            if (ipa >= HVT_HYPERCALL_MMIO_BASE &&
                ipa < HVT_HYPERCALL_MMIO_BASE + (HVT_HYPERCALL_MAX << 3)) {
                int nr = (int)((ipa - HVT_HYPERCALL_MMIO_BASE) >> 3);
                if (nr == HVT_HYPERCALL_HALT) {
                    hvt_gpa_t gpa = (hvt_gpa_t)(reg_val & 0xffffffffULL);
                    return hvt_core_hypercall_halt(hvt, gpa);
                }
                hvt_hypercall_fn_t fn = hvt_core_hypercalls[nr];
                if (fn == NULL) {
                    uint64_t pc;
                    hv_vcpu_get_reg(hvb->vcpu, HV_REG_PC, &pc);
                    errx(1, "Invalid guest hypercall %d pc=0x%llx", nr,
                         (unsigned long long)pc);
                }
                hvt_gpa_t gpa = (hvt_gpa_t)(reg_val & 0xffffffffULL);
                fn(hvt, gpa);
                /* Advance PC */
                uint64_t pc;
                hv_vcpu_get_reg(hvb->vcpu, HV_REG_PC, &pc);
                hv_vcpu_set_reg(hvb->vcpu, HV_REG_PC, pc + 4);
                continue;
            } else if (ipa == HVT_RING_KICK_MMIO_BASE) {
                /* Ring kick - ignore for now, just advance */
                uint64_t pc;
                hv_vcpu_get_reg(hvb->vcpu, HV_REG_PC, &pc);
                hv_vcpu_set_reg(hvb->vcpu, HV_REG_PC, pc + 4);
                continue;
            } else if (ipa < hvt->guest_mem_size) {
                /* Stage-2 permission fault on guest RAM (W^X violation) */
                uint64_t pc;
                hv_vcpu_get_reg(hvb->vcpu, HV_REG_PC, &pc);
                errx(1, "HVF: host/guest translation fault: pc=0x%lx",
                     (unsigned long)pc);
            } else {
                uint64_t pc;
                hv_vcpu_get_reg(hvb->vcpu, HV_REG_PC, &pc);
                errx(1, "Unhandled MMIO write: ipa=0x%llx pc=0x%llx esr=0x%llx",
                     (unsigned long long)ipa, (unsigned long long)pc,
                     (unsigned long long)syndrome);
            }
        } else if (ec == ESR_EC_IABT_LOWER || ec == ESR_EC_IABT_CUR) {
            /* Stage-2 EXEC permission fault (NX) */
            uint64_t pc;
            hv_vcpu_get_reg(hvb->vcpu, HV_REG_PC, &pc);
            errx(1, "HVF: host/guest translation fault: pc=0x%lx",
                 (unsigned long)pc);
        } else {
            uint64_t pc;
            hv_vcpu_get_reg(hvb->vcpu, HV_REG_PC, &pc);
            errx(1, "Unhandled exception: ec=0x%llx pc=0x%llx syndrome=0x%llx",
                 (unsigned long long)ec, (unsigned long long)pc,
                 (unsigned long long)syndrome);
        }
    }
}
