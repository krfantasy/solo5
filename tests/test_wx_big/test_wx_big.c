/*
 * Solo5 standalone test_wx_big: W^X probes with an ELF image that extends
 * well above the first 2MB of guest memory, where the Darwin HVF tender
 * historically had only coarse (16K host-page union) stage-2 permissions
 * and RWX 2MB stage-1 blocks.
 *
 * Layout produced below: ~3MB of .text padding ending just past 2MB, then
 * a small rodata, then a ~3MB .bss. With TEXT_PAD tuned so that
 * (text_end & 0x3fff) == 0x1000, the end of .text, the rodata and the start
 * of .data share one 16K host page: the tender's coarse stage-2 union is
 * RWX there, and only precise guest stage-1 tables can enforce W^X.
 *
 * Modes (guest command line):
 *   (empty)  positive: clear the .bss (proves data is writable) -> SUCCESS
 *   "xnow"   write to a .text page above 2MB -> must trap
 *   "wnox"   execute the first .data page (in the straddle window) -> must trap
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

static void puthex(uint64_t v)
{
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; i++) {
        int nib = (int)((v >> ((15 - i) * 4)) & 0xf);
        buf[2 + i] = (nib < 10) ? ('0' + nib) : ('a' + nib - 10);
    }
    buf[18] = '\n';
    solo5_console_write(buf, 19);
}

/* Tuned so text ends at offset 0x1000 within a 16K window. Adjust this
 * value (by the delta needed to make (text_end & 0x3fff) == 0x1000) if the
 * printed check below differs. */
#define TEXT_PAD_BYTES (3 * 1024 * 1024 + 18684)
__attribute__((section(".text")))
const char text_pad[TEXT_PAD_BYTES] = {1, 1, 1, 1};

static volatile char
    bss_pad[3 * 1024 * 1024]; /* .bss: part of the data PT_LOAD */

/* Initialized-data W^X target: pinned to .data so it lands in the FIRST
 * .data page, inside the same 16K host-page window as the end of .text and
 * rodata (the .bss arrays cannot: bindings' 2MB write_bufs precedes them).
 * The tender's coarse stage-2 union for that window is RWX, and only
 * precise guest stage-1 tables can enforce W^X there.
 *
 * Initialized with an infinite loop so that an instruction fetch at this
 * address loops even if it races the in-guest store below (ARM I-/D-caches
 * are not coherent; a fresh fetch can read the image-loaded value rather
 * than the just-stored one — both are LOOP_INSN). */
__attribute__((section(".data"))) static volatile uint32_t wx_target =
    LOOP_INSN;

static void __attribute__((noinline)) exec_at(void *addr)
{
    void (*f)(void) = (void *)(uintptr_t)addr;
    f();
}

int solo5_app_main(const struct solo5_start_info *si)
{
    const uint64_t text_end = (uint64_t)&text_pad[sizeof(text_pad)];

    puts("\n**** Solo5 standalone test_wx_big ****\n\n");
    puts("text end:           ");
    puthex(text_end);
    puts("bss start:          ");
    puthex((uint64_t)&bss_pad[0]);
    puts("wx target:          ");
    puthex((uint64_t)&wx_target);
    puts("text end & 0x3fff:  ");
    puthex(text_end & 0x3fff);

    /* The 16K straddle window only matters for the wnox probe below (which
     * executes .data in the same host page as the end of .text). The
     * positive run and the xnow probe must pass on all hosts/arches
     * regardless of where the linker placed text_end, so only enforce the
     * tuning there. The wnox case runs Darwin-only where the tuning holds. */
    if (si->cmdline[0] == 'w' && (text_end & 0x3fff) != 0x1000) {
        puts("FAILURE: straddle precondition lost (text_end & 0x3fff != "
             "0x1000)\n");
        return SOLO5_EXIT_FAILURE;
    }

    if (si->cmdline[0] == 'x') {
        /* Write to executable memory near the end of .text, above 2MB. */
        puts("writing to text\n");
        *(volatile char *)(uintptr_t)&text_pad[sizeof(text_pad) - 4096] = 1;
        puts("FAILURE: wrote to executable memory\n");
        return SOLO5_EXIT_FAILURE;
    }

    /* Positive check: the multi-MB data segment must remain writable. */
    puts("clearing bss\n");
    for (size_t i = 0; i < sizeof(bss_pad); i++)
        bss_pad[i] = 0;

    if (si->cmdline[0] == 'w') {
        /* Execute the first .data page, inside the 16K straddle window that
         * also holds the end of .text and rodata (see the printed
         * addresses). Store an infinite loop so that a successful fetch
         * loops until the harness timeout instead of randomly trapping. */
        puts("executing data\n");
        wx_target = LOOP_INSN;
        exec_at((void *)(uintptr_t)&wx_target);
        puts("FAILURE: executed writable memory\n");
        return SOLO5_EXIT_FAILURE;
    }

    puts("SUCCESS\n");
    return SOLO5_EXIT_SUCCESS;
}
