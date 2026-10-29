/* Native timing of identical array work; Python only builds and collects. */
#include "runtime.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if BENCH_MODE == 0
#include "fixture.h"
extern void *aot_entry(void *, uint64_t, void *);
#elif BENCH_MODE == 1
__attribute__((ms_abi)) uint32_t guest_entry(uint8_t *, uint32_t);
#elif BENCH_MODE == 2
uint32_t source_kernel(uint8_t *, uint32_t);
#else
#error Unsupported benchmark mode
#endif

static uint64_t now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value)) abort();
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static uint64_t buffer_hash(const uint8_t *data, size_t size) {
    uint64_t hash = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < size; i++) {
        hash ^= data[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint32_t reference(uint8_t *data, uint32_t count) {
    uint32_t value = 0;
    for (uint32_t i = 0; i < count; i++) {
        size_t offset = (size_t)i * 4 + 1;
        uint32_t word = (uint32_t)data[offset]
            | (uint32_t)data[offset + 1] << 8
            | (uint32_t)data[offset + 2] << 16
            | (uint32_t)data[offset + 3] << 24;
        value ^= word;
        value = (value << 5) | (value >> 27);
        for (unsigned byte = 0; byte < 4; byte++)
            data[offset + byte] = (uint8_t)(value >> (byte * 8));
    }
    return value;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    uint64_t requested_count = strtoull(argv[1], NULL, 10);
    unsigned calls = (unsigned)strtoul(argv[2], NULL, 10);
    unsigned warmups = (unsigned)strtoul(argv[3], NULL, 10);
    if (!requested_count || requested_count > (1u << 20)
        || !calls || calls > 1024 || warmups > 10) return 2;
    uint32_t count = (uint32_t)requested_count;
    size_t size = (size_t)count * 4 + 17;
    uint8_t *initial = malloc(size), *expected = malloc(size), *data = malloc(size);
    uint64_t *samples = calloc(calls, sizeof *samples);
    if (!initial || !expected || !data || !samples) return 3;
    uint32_t seed = 20261027;
    for (size_t i = 0; i < size; i++) {
        seed = seed * 1664525u + 1013904223u;
        initial[i] = (uint8_t)(seed >> 24);
    }
    memcpy(expected, initial, size);
    uint32_t expected_value = reference(expected, count);
    uint64_t initial_hash = buffer_hash(initial, size);
    uint64_t expected_hash = buffer_hash(expected, size);
    uint64_t elapsed = 0, checksum = 0, guest_steps = 0;

#if BENCH_MODE == 0
    enum { STACK_SIZE = 65536 };
    const uint64_t data_base = UINT64_C(0x500000000);
    const uint64_t stack_base = UINT64_C(0x70000000);
    const uint64_t entry_rsp = stack_base + STACK_SIZE - 0x108;
    const uint64_t exit_pc = UINT64_C(0x7fff00000000);
    uint8_t *image = malloc(sizeof kImage);
    uint8_t *stack = malloc(STACK_SIZE);
    size_t pages = (size + GM_PAGE - 1) / GM_PAGE;
    uint8_t *data_permissions = malloc(pages);
    uint8_t stack_permissions[STACK_SIZE / GM_PAGE];
    if (!image || !stack || !data_permissions) return 3;
    if ((uintptr_t)data == data_base || (uintptr_t)stack == stack_base) return 4;
    memcpy(image, kImage, sizeof kImage);
    memset(data_permissions, GM_READ | GM_WRITE, pages);
    memset(stack_permissions, GM_READ | GM_WRITE, sizeof stack_permissions);
    GuestMemory mappings[] = {
        {data_base, size, data, data_permissions, pages},
        {kImageBase, sizeof kImage, image, kImagePermissions, sizeof kImagePermissions},
        {stack_base, STACK_SIZE, stack, stack_permissions, sizeof stack_permissions}
    };
#endif

    for (unsigned trial = 0; trial < warmups + calls; trial++) {
        /* Identical fresh input on every call; preparation is outside timing. */
        memcpy(data, initial, size);
#if BENCH_MODE == 0
        memset(stack, 0xa5, STACK_SIZE);
        memcpy(stack + (entry_rsp - stack_base), &exit_pc, sizeof exit_pc);
        AotState *state = aot_state_create();
        AotContext *context = aot_context_create(kImageBase, kInstructions,
            sizeof kInstructions / sizeof *kInstructions,
            (uint64_t)count * 8 + 64, exit_pc, entry_rsp);
        if (!state || !context) return 3;
        aot_set_register(state, AOT_RCX, data_base + 1);
        aot_set_register(state, AOT_RDX, count);
        aot_set_register(state, AOT_RSP, entry_rsp);
        for (unsigned i = 0; i < sizeof mappings / sizeof *mappings; i++)
            if (aot_add_region(context, &mappings[i]) != AOT_OK) return 5;
        uint64_t start = now_ns();
        uint32_t status = aot_execute(aot_entry, state, context, kEntryPC);
        uint64_t raw_value = aot_get_register(state, AOT_RAX);
        uint64_t duration = now_ns() - start;
        AotResult result;
        aot_result(context, &result);
        if (status != AOT_OK || !result.returned || result.call_depth
            || raw_value > UINT32_MAX || aot_get_register(state, AOT_RSP) != entry_rsp + 8) {
            fprintf(stderr, "AOT failed status=%u pc=%" PRIx64 " steps=%" PRIu64 "\n",
                status, result.fault.pc, result.steps);
            return 6;
        }
        uint32_t value = (uint32_t)raw_value;
        if (trial >= warmups) guest_steps += result.steps;
        aot_context_destroy(context);
        aot_state_destroy(state);
#elif BENCH_MODE == 1
        uint64_t start = now_ns();
        uint32_t value = guest_entry(data + 1, count);
        uint64_t duration = now_ns() - start;
#else
        uint64_t start = now_ns();
        uint32_t value = source_kernel(data + 1, count);
        uint64_t duration = now_ns() - start;
#endif
        /* Full output validation, including both guards, is outside timing. */
        if (value != expected_value || memcmp(data, expected, size)) {
            fprintf(stderr, "result/buffer mismatch mode=%d trial=%u\n", BENCH_MODE, trial);
            return 7;
        }
        if (trial >= warmups) {
            samples[trial - warmups] = duration;
            elapsed += duration;
            checksum += value;
        }
    }
    uint64_t elements = (uint64_t)count * calls;
    printf("{\"mode\":%d,\"count\":%u,\"calls\":%u,\"warmup_calls\":%u,"
           "\"elapsed_ns\":%" PRIu64 ",\"elements\":%" PRIu64 ","
           "\"ns_per_element\":%.9f,\"checksum\":\"%016" PRIx64 "\","
           "\"return_value\":%u,\"initial_buffer_hash\":\"%016" PRIx64 "\","
           "\"final_buffer_hash\":\"%016" PRIx64 "\","
           "\"full_buffer_checked_calls\":%u,\"guest_steps\":%" PRIu64 ",\"call_elapsed_ns\":[",
           BENCH_MODE, count, calls, warmups, elapsed, elements,
           (double)elapsed / (double)elements, checksum, expected_value,
           initial_hash, expected_hash, calls + warmups, guest_steps);
    for (unsigned i = 0; i < calls; i++) printf("%s%" PRIu64, i ? "," : "", samples[i]);
    puts("]}");
#if BENCH_MODE == 0
    free(image); free(stack); free(data_permissions);
#endif
    free(initial); free(expected); free(data); free(samples);
    return 0;
}
