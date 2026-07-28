#include "sm3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_to_bytes(const char *hex, uint8_t out[32])
{
    for (size_t i = 0; i < 32u; ++i) {
        unsigned value = 0u;
        if (sscanf(hex + 2u * i, "%2x", &value) != 1) {
            return -1;
        }
        out[i] = (uint8_t)value;
    }
    return 0;
}

static void print_hex(const uint8_t d[32])
{
    for (size_t i = 0; i < 32u; ++i) {
        printf("%02x", d[i]);
    }
}

static int test_vector(const uint8_t *msg, size_t len, const char *expected_hex,
                       const char *name)
{
    uint8_t got[32];
    uint8_t expected[32];
    sm3_digest(msg, len, got);
    if (hex_to_bytes(expected_hex, expected) != 0 || memcmp(got, expected, 32u) != 0) {
        fprintf(stderr, "[FAIL] scalar vector %s\n  got: ", name);
        print_hex(got);
        fprintf(stderr, "\n");
        return 1;
    }
    printf("[PASS] scalar vector %s\n", name);
    return 0;
}

static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);

static uint32_t rng32(void)
{
    rng_state ^= rng_state << 7;
    rng_state ^= rng_state >> 9;
    rng_state ^= rng_state << 8;
    return (uint32_t)rng_state;
}

static int backend_available(sm3_backend backend)
{
    switch (backend) {
    case SM3_BACKEND_SCALAR: return 1;
#if defined(__x86_64__) || defined(_M_X64)
    case SM3_BACKEND_AVX2: return sm3_cpu_has_avx2();
    case SM3_BACKEND_AVX512: return sm3_cpu_has_avx512f();
#endif
#if defined(__aarch64__)
    case SM3_BACKEND_NEON: return sm3_cpu_has_neon();
#endif
    case SM3_BACKEND_AUTO: return 1;
    default: return 0;
    }
}

static int run_differential(sm3_backend backend, size_t count, unsigned rounds)
{
    static const size_t edges[] = {
        0u, 1u, 2u, 3u, 31u, 55u, 56u, 57u,
        63u, 64u, 65u, 119u, 120u, 121u, 127u, 128u
    };
    uint8_t **owned = calloc(count, sizeof(*owned));
    const uint8_t **msg = calloc(count, sizeof(*msg));
    size_t *len = calloc(count, sizeof(*len));
    uint8_t (*got)[32] = calloc(count, sizeof(*got));
    uint8_t (*ref)[32] = calloc(count, sizeof(*ref));
    if (owned == NULL || msg == NULL || len == NULL || got == NULL || ref == NULL) {
        fprintf(stderr, "allocation failure\n");
        free(owned); free(msg); free(len); free(got); free(ref);
        return 1;
    }

    for (unsigned round = 0; round < rounds; ++round) {
        for (size_t lane = 0; lane < count; ++lane) {
            len[lane] = (round == 0u)
                ? edges[lane % (sizeof(edges) / sizeof(edges[0]))]
                : (size_t)(rng32() % 4097u);
            owned[lane] = malloc(len[lane] == 0u ? 1u : len[lane]);
            if (owned[lane] == NULL) {
                fprintf(stderr, "allocation failure\n");
                return 1;
            }
            for (size_t i = 0; i < len[lane]; ++i) {
                owned[lane][i] = (uint8_t)rng32();
            }
            msg[lane] = owned[lane];
            sm3_digest(msg[lane], len[lane], ref[lane]);
        }

        if (sm3_hash_many(backend, msg, len, got, count) != 0) {
            fprintf(stderr, "[FAIL] backend %s returned error\n", sm3_backend_name(backend));
            return 1;
        }
        for (size_t lane = 0; lane < count; ++lane) {
            if (memcmp(got[lane], ref[lane], 32u) != 0) {
                fprintf(stderr, "[FAIL] %s differential round=%u lane=%zu len=%zu\n",
                        sm3_backend_name(backend), round, lane, len[lane]);
                return 1;
            }
            free(owned[lane]);
            owned[lane] = NULL;
        }
    }

    printf("[PASS] %-13s edge/random differential (%u rounds, %zu messages)\n",
           sm3_backend_name(backend), rounds, count);
    free(owned); free(msg); free(len); free(got); free(ref);
    return 0;
}

int main(void)
{
    int failed = 0;
    static const uint8_t abc[] = {'a', 'b', 'c'};
    uint8_t abcd64[64];
    for (size_t i = 0; i < sizeof(abcd64); ++i) {
        abcd64[i] = (uint8_t)"abcd"[i & 3u];
    }

    failed |= test_vector((const uint8_t *)"", 0u,
        "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
        "empty");
    failed |= test_vector(abc, sizeof(abc),
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        "abc");
    failed |= test_vector(abcd64, sizeof(abcd64),
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
        "abcd x 16");

#if defined(__x86_64__) || defined(_M_X64)
    printf("CPU AVX2:    %s\n", sm3_cpu_has_avx2() ? "yes" : "no");
    printf("CPU AVX-512: %s\n", sm3_cpu_has_avx512f() ? "yes" : "no");
    if (backend_available(SM3_BACKEND_AVX2)) {
        failed |= run_differential(SM3_BACKEND_AVX2, 8u, 101u);
    } else {
        printf("[SKIP] AVX2 unsupported\n");
    }
    if (backend_available(SM3_BACKEND_AVX512)) {
        failed |= run_differential(SM3_BACKEND_AVX512, 16u, 101u);
    } else {
        printf("[SKIP] AVX-512 unsupported\n");
    }
#endif

#if defined(__aarch64__)
    printf("CPU NEON:    %s\n", sm3_cpu_has_neon() ? "yes" : "no");
    failed |= run_differential(SM3_BACKEND_NEON, 4u, 101u);
#endif

    failed |= run_differential(SM3_BACKEND_AUTO, 37u, 51u);
    printf("Best backend: %s\n", sm3_backend_name(sm3_best_backend()));

    if (failed != 0) {
        fprintf(stderr, "SM3 tests failed.\n");
        return 1;
    }
    printf("All SM3 tests passed.\n");
    return 0;
}
