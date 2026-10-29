/* Original PE text AND read-only table bytes, at their original relative RVAs.
 * Rosetta is used only by this reference process. No instruction is replaced
 * with a C model. Capture assembly is the pinned scalar_oracle.S fixture.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include "oracle_image.h"

typedef struct { uint64_t gpr[16], rflags; } InputFrame;
typedef struct { uint64_t gpr[16], rflags, rip; } OutputFrame;
uint64_t oracle_host_rsp, oracle_entry_address;
OutputFrame oracle_output;
extern void oracle_run(InputFrame *);
extern void oracle_capture(void);
static void fail(const char *message) {
    fprintf(stderr, "oracle failure: %s (errno %d)\n", message, errno);
    exit(2);
}
static void read_exact(void *p, size_t size) {
    if (fread(p, 1, size, stdin) != size) fail("truncated request");
}
static void write_exact(const void *p, size_t size) {
    if (fwrite(p, 1, size, stdout) != size) fail("response write");
}
static void same_image(const unsigned char *image) {
    for (size_t n = 0; n < sizeof kPermissions; ++n) {
        if ((kPermissions[n] & 1) && memcmp(image + 4096*n, kImage + 4096*n, 4096))
            fail("raw PE image changed");
    }
}
int main(void) {
    int translated = 0;
    size_t size = sizeof translated;
    if (sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0) || translated != 1)
        fail("expected Rosetta x86 reference process");
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || page > 4096 || 4096 % (unsigned long)page) fail("page granularity");
    if (sizeof kImage != 4096 * sizeof kPermissions || kEntryRva >= sizeof kImage)
        fail("image shape");
    unsigned char *image = mmap(NULL, sizeof kImage, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANON, -1, 0);
    if (image == MAP_FAILED) fail("mmap");
    memcpy(image, kImage, sizeof kImage);
    if (mprotect(image, sizeof kImage, PROT_NONE)) fail("protect image");
    for (size_t n = 0; n < sizeof kPermissions; ++n) {
        if ((kPermissions[n] & ~7u) || !(kPermissions[n] & 1) || (kPermissions[n] & 2))
            fail("reference image must be entirely readable and not writable");
        int flags = PROT_READ | ((kPermissions[n] & 4) ? PROT_EXEC : 0);
        if (mprotect(image + 4096*n, 4096, flags)) fail("set image permissions");
    }
    oracle_entry_address = (uint64_t)(uintptr_t)(image + kEntryRva);
    unsigned char allocation[65536 + 16], before[65536], normalized[65536];
    unsigned char *stack = (unsigned char *)(((uintptr_t)allocation + 15) & ~(uintptr_t)15);
    unsigned count = 0;
    for (;;) {
        char magic[8];
        size_t got = fread(magic, 1, 8, stdin);
        if (!got && feof(stdin)) break;
        if (got != 8 || memcmp(magic, "SWIN0001", 8)) fail("request magic");
        InputFrame input;
        read_exact(&input, sizeof input);
        if (input.gpr[4] != UINT64_C(0x7000fef8) || input.rflags != 2) fail("input frame");
        memset(stack, 0x5a, 65536);
        uint64_t host_rsp = (uint64_t)(uintptr_t)(stack + 0xfef8);
        uint64_t capture = (uint64_t)(uintptr_t)&oracle_capture;
        memcpy((void *)(uintptr_t)host_rsp, &capture, 8);
        memcpy(before, stack, 65536);
        same_image(image);
        input.gpr[4] = host_rsp;
        memset(&oracle_output, 0, sizeof oracle_output);
        oracle_run(&input);
        if (oracle_output.rip != capture || oracle_output.gpr[4] != host_rsp + 8)
            fail("actual guest RET/capture");
        if (memcmp(before, stack, 65536)) fail("guest modified stack");
        same_image(image);
        memcpy(normalized, stack, 65536);
        uint64_t logical_exit = UINT64_C(0x7fff00000000);
        memcpy(normalized + 0xfef8, &logical_exit, 8);
        uint64_t mappings[4] = {(uint64_t)(uintptr_t)image, (uint64_t)(uintptr_t)stack,
                                host_rsp, capture};
        write_exact("SWOUT001", 8);
        write_exact(&oracle_output, sizeof oracle_output);
        write_exact(mappings, sizeof mappings);
        write_exact(image, sizeof kImage);
        write_exact(normalized, sizeof normalized);
        ++count;
    }
    if (fflush(stdout)) fail("flush");
    fprintf(stderr, "{\"status\":\"RAW_PE_SWITCH_X86_PASS\",\"cases\":%u,"
                    "\"translated\":1,\"raw_image_identity\":true,\"stack_unchanged\":true}\n", count);
    if (munmap(image, sizeof kImage)) fail("munmap");
    return 0;
}
