/*
 * Solo5 standalone test_heapnx: verifies that writable memory which is not
 * part of a loaded ELF segment (heap, stack) is not executable.
 *
 * Mode is selected by the guest command line:
 *   (empty)  execute a page of heap (first page after the loaded image)
 *   "stack"  execute a page on the stack
 *
 * Both probe pages are filled with an infinite loop (branch-to-self on
 * aarch64/RISC-V, jmp $ on x86_64) and the I-cache is synchronised before
 * the fetch, so a fetch the hardware permits always loops until the harness
 * timeout — "executed" is unambiguous (zero-filled targets would instead
 * hit UDF and produce a Fatal trap that is byte-identical to a legitimate
 * permission trap). The run can therefore only end by enforcement: the
 * tender blocks the fetch either at guest stage 1 (NX PTE -> Solo5 Fatal
 * trap, exit 255) or at stage 2 ("host/guest translation fault", exit 1).
 * The heap probe targets the first heap page below 2MB, which carries a
 * wired stage-1 RW/NX PTE; ARM checks stage-1 first, so it must trap 255
 * (proving 4K precision rather than the 16K stage-2 union). The stack
 * probe lives above the wired image blocks, so either layer may win
 * (exit 1 or 255) — both are legitimate enforcement there, and both are
 * strictly finer than executing the page.
 */
#include "solo5.h"
#include "../../bindings/lib.c"

#if defined(__aarch64__)
#define LOOP_INSN 0x14000000u /* b . */
#elif defined(__x86_64__)
#define LOOP_INSN 0xFEEBFEEBu /* jmp $; jmp $ */
#elif defined(__riscv) && (__riscv_xlen == 64)
#define LOOP_INSN 0x0000006fu /* j . */
#else
#error Unsupported architecture
#endif

static void puts(const char *s)
{
    solo5_console_write(s, strlen(s));
}

extern char _end[]; /* linker script: end of the loaded image */

static void sync_icache(uintptr_t start, size_t len)
{
#if defined(__aarch64__)
    for (uintptr_t p = start; p < start + len; p += 64) {
        __asm__ __volatile__("dc cvau, %0" ::"r"(p) : "memory");
        __asm__ __volatile__("ic ivau, %0" ::"r"(p) : "memory");
    }
    __asm__ __volatile__("dsb ish" ::: "memory");
    __asm__ __volatile__("isb" ::: "memory");
#elif defined(__riscv) && (__riscv_xlen == 64)
    __asm__ __volatile__("fence.i" ::: "memory");
    (void)start;
    (void)len;
#elif defined(__x86_64__)
    /* x86 I/D caches are coherent; nothing to do. */
    (void)start;
    (void)len;
#else
#error Unsupported architecture
#endif
}

static void __attribute__((noinline)) exec_at(void *addr)
{
    void (*f)(void) = (void *)(uintptr_t)addr;
    f();
}

int solo5_app_main(const struct solo5_start_info *si)
{
    puts("\n**** Solo5 standalone test_heapnx ****\n\n");

    if (si->cmdline[0] == 's') {
        /* Probe: execute a page on the stack. Filled with an infinite loop
         * so a permitted fetch loops (harness timeout) instead of
         * executing something else. */
        volatile char buf[4096] __attribute__((aligned(16)));
        volatile uint32_t *words = (volatile uint32_t *)(uintptr_t)buf;
        for (size_t i = 0; i < sizeof(buf) / sizeof(*words); i++)
            words[i] = LOOP_INSN;
        puts("executing stack page\n");
        sync_icache((uintptr_t)buf, sizeof(buf));
        exec_at((void *)(uintptr_t)buf);
    } else {
        /* Probe: execute the first heap page. The fill proves the page is
         * still writable (W must keep working); the fetch must be blocked. */
        volatile uint32_t *heap_page =
            (volatile uint32_t *)(((uintptr_t)_end + 0xfff) & ~0xfffUL);
        for (int i = 0; i < 4096 / 4; i++)
            heap_page[i] = LOOP_INSN;
        puts("heap page is writable: OK\n");
        sync_icache((uintptr_t)heap_page, 4096);
        puts("executing heap page\n");
        exec_at((void *)(uintptr_t)heap_page);
    }

    puts("FAILURE: executed non-executable memory\n");
    return SOLO5_EXIT_FAILURE;
}
