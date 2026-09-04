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

#include "solo5.h"
#include "../../bindings/lib.c"
#include <hvt_abi.h>

static void puts(const char *s)
{
    solo5_console_write(s, strlen(s));
}

/*
 * Issue a hypercall with full control of the argument register, as a
 * malicious guest would. The in-tree bindings always pass a stack
 * address; these helpers exist to aim the tender at attacker-chosen
 * guest physical addresses.
 */
#if defined(__aarch64__)
static void raw_hypercall(int nr, uint32_t arg)
{
    uint64_t addr = HVT_HYPERCALL_ADDRESS(nr);
    __asm__ __volatile__("str %w0, [%1]" : : "rZ"(arg), "r"(addr) : "memory");
}
/*
 * Explicitly encode wzr (srt=31): the tender must treat this exactly
 * like a zero argument (gpa=0), never read an arbitrary register.
 */
static void raw_hypercall_zero(int nr)
{
    uint64_t addr = HVT_HYPERCALL_ADDRESS(nr);
    __asm__ __volatile__("str wzr, [%0]" : : "r"(addr) : "memory");
}
#elif defined(__x86_64__)
static void raw_hypercall(int nr, uint32_t arg)
{
    __asm__ __volatile__("outl %0, %1"
                         :
                         : "a"(arg),
                           "d"((uint16_t)(HVT_HYPERCALL_PIO_BASE + nr))
                         : "memory");
}
static void raw_hypercall_zero(int nr)
{
    raw_hypercall(nr, 0);
}
#else
#error Unsupported architecture
#endif

static const uint8_t pattern[512] = "hcfloor";

/* Every case needs the numeric handle; the elftool-generated manifest
 * puts a MFT_RESERVED_FIRST entry at index 0, so the acquired handle is
 * typically 1 — derive it at runtime, never hardcode it. */
static int acquire(solo5_handle_t *h)
{
    struct solo5_block_info bi;
    return solo5_block_acquire("storage", h, &bi) == SOLO5_R_OK ? 0 : -1;
}

/* Legit roundtrip through the solo5 API into heap buffers. */
static int case_ok(void)
{
    uint8_t rbuf[512];
    size_t i;
    solo5_handle_t h;

    if (acquire(&h) == -1)
        return -1;
    if (solo5_block_write(h, 512, pattern, sizeof pattern) != SOLO5_R_OK)
        return -1;
    if (solo5_block_read(h, 512, rbuf, sizeof rbuf) != SOLO5_R_OK)
        return -1;
    for (i = 0; i < sizeof pattern; i++)
        if (rbuf[i] != pattern[i])
            return -1;
    return 0;
}

/* puts struct parked on the PGD (0x1000): tender must errx. */
static void case_pgd(void)
{
    puts("hcfloor: aiming puts struct at GPA 0x1000\n");
    raw_hypercall(HVT_HYPERCALL_PUTS, 0x1000);
    puts("hcfloor: ERROR - tender accepted struct gpa=0x1000\n");
}

/*
 * block_read data buffer aimed at the HVF PTE spill window (0x20000):
 * the host-side pread would overwrite guest stage-1 page tables behind
 * the guest's read-only stage-1 mapping. Tender must errx.
 */
static void case_spill(void)
{
    volatile struct hvt_hc_block_read rd;
    solo5_handle_t h;

    if (acquire(&h) == -1) {
        puts("hcfloor: ERROR - block_acquire failed\n");
        return;
    }
    if (solo5_block_write(h, 512, pattern, sizeof pattern) != SOLO5_R_OK) {
        puts("hcfloor: ERROR - block_write failed\n");
        return;
    }
    rd.handle = h;
    rd.offset = 512;
    rd.len = sizeof pattern;
    rd.data = (void *)0x20000UL;
    puts("hcfloor: aiming block_read data at GPA 0x20000\n");
    raw_hypercall(HVT_HYPERCALL_BLOCK_READ, (uint32_t)(uintptr_t)&rd);
    puts("hcfloor: ERROR - tender accepted data gpa=0x20000\n");
}

/*
 * handle = 2^32 + h aliases to the valid device h via unsigned
 * truncation in mft_get_by_index(); the tender must return
 * SOLO5_R_EINVAL instead. (Do NOT use plain 2^32: it truncates to
 * index 0, the reserved manifest entry, which fails the type check
 * and returns EINVAL even without the fix.)
 */
static int case_handle(void)
{
    volatile struct hvt_hc_block_read rd;
    uint8_t rbuf[512];
    solo5_handle_t h;

    if (acquire(&h) == -1)
        return -1;
    rd.handle = 0x100000000ULL + h;
    rd.offset = 0;
    rd.len = sizeof rbuf;
    rd.data = rbuf;
    raw_hypercall(HVT_HYPERCALL_BLOCK_READ, (uint32_t)(uintptr_t)&rd);
    return rd.ret == SOLO5_R_EINVAL ? 0 : -1;
}

int solo5_app_main(const struct solo5_start_info *si)
{
    puts("\n**** Solo5 standalone test_hcfloor ****\n\n");

    if (strcmp(si->cmdline, "ok") == 0) {
        if (case_ok() == 0) {
            puts("SUCCESS\n");
            return SOLO5_EXIT_SUCCESS;
        }
        puts("ERROR: legit block roundtrip failed\n");
        return SOLO5_EXIT_FAILURE;
    }
    if (strcmp(si->cmdline, "zero") == 0) {
        puts("hcfloor: issuing puts hypercall with xzr (gpa=0)\n");
        raw_hypercall_zero(HVT_HYPERCALL_PUTS);
        puts("hcfloor: ERROR - tender accepted gpa=0\n");
        return SOLO5_EXIT_FAILURE;
    }
    if (strcmp(si->cmdline, "pgd") == 0) {
        case_pgd();
        return SOLO5_EXIT_FAILURE;
    }
    if (strcmp(si->cmdline, "spill") == 0) {
        case_spill();
        return SOLO5_EXIT_FAILURE;
    }
    if (strcmp(si->cmdline, "handle") == 0) {
        if (case_handle() == 0) {
            puts("SUCCESS\n");
            return SOLO5_EXIT_SUCCESS;
        }
        puts("ERROR: handle=2^32 was aliased to a valid device\n");
        return SOLO5_EXIT_FAILURE;
    }
    puts("ERROR: unknown case (pass one of: ok zero pgd spill handle)\n");
    return SOLO5_EXIT_FAILURE;
}
