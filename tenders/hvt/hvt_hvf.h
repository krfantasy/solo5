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
 * hvt_hvf.h: Hypervisor.framework backend definitions for Darwin.
 */

#ifndef HVT_HVF_H
#define HVT_HVF_H

#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vcpu.h>
#include <Hypervisor/hv_vm.h>
#include <pthread.h>

struct hvt_b {
    hv_vcpu_t vcpu;
    hv_vcpu_exit_t *vcpu_exit;
    int has_ioeventfd;
    int kick_net_efd;
    hvt_gpa_t net_ring_gpa;
    pthread_t io_thread_net;
};

/*
 * Tender-owned guest low-memory regions (full layout in
 * hvt_cpu_aarch64.h; the producer is hvt_hvf.c):
 *   [0, AARCH64_BOOT_INFO)          zero page + boot-time stage-1 tables
 *   [AARCH64_BOOT_INFO, HVT_HVF_PTE_REGION_BASE)
 *                                    boot window (boot_info/mft/cmdline)
 *   [HVT_HVF_PTE_REGION_BASE, HVT_HVF_PTE_REGION_END)
 *                                    PTE spill tables for >2MB images
 * The production tender makes all three host-read-only before the
 * vcpu loop runs (see hvt_hvf_apply_deferred_protections() and
 * hvt_drop_privileges()); the debug build compiles out only the
 * boot-window freeze -- the table and spill freezes are unconditional.
 */
#define HVT_HVF_PTE_REGION_BASE 0x20000UL
#define HVT_HVF_PTE_REGION_END AARCH64_GUEST_MIN_BASE /* 0x100000 */

#endif /* HVT_HVF_H */
