#define _POSIX_C_SOURCE 200809L
#include "sm3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BENCH_MESSAGES 16u
#define BENCH_SAMPLES 7u

static volatile uint8_t bench_sink;

static double now_seconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static int compare_double(const void *a, const void *b)
{
    const double da = *(const double *)a;
    const double db = *(const double *)b;
    return (da > db) - (da < db);
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
    default: return 0;
    }
}

static double bench_backend(sm3_backend backend,
                            const uint8_t *const msg[BENCH_MESSAGES],
                            const size_t len[BENCH_MESSAGES],
                            uint8_t out[BENCH_MESSAGES][32],
                            size_t iterations,
                            size_t message_bytes)
{
    double samples[BENCH_SAMPLES];

    for (unsigned warm = 0; warm < 3u; ++warm) {
        (void)sm3_hash_many(backend, msg, len, out, BENCH_MESSAGES);
        bench_sink ^= out[warm % BENCH_MESSAGES][warm & 31u];
    }

    for (unsigned sample = 0; sample < BENCH_SAMPLES; ++sample) {
        const double begin = now_seconds();
        for (size_t it = 0; it < iterations; ++it) {
            if (sm3_hash_many(backend, msg, len, out, BENCH_MESSAGES) != 0) {
                fprintf(stderr, "backend unavailable: %s\n", sm3_backend_name(backend));
                exit(3);
            }
            bench_sink ^= out[it & (BENCH_MESSAGES - 1u)][it & 31u];
        }
        const double elapsed = now_seconds() - begin;
        const double bytes = (double)iterations * (double)BENCH_MESSAGES * (double)message_bytes;
        samples[sample] = bytes / elapsed / (1024.0 * 1024.0);
    }

    qsort(samples, BENCH_SAMPLES, sizeof(samples[0]), compare_double);
    return samples[BENCH_SAMPLES / 2u];
}

int main(int argc, char **argv)
{
    size_t message_bytes = 4096u;
    size_t total_mib = 256u;
    if (argc >= 2) {
        message_bytes = (size_t)strtoull(argv[1], NULL, 10);
    }
    if (argc >= 3) {
        total_mib = (size_t)strtoull(argv[2], NULL, 10);
    }
    if (message_bytes == 0u) {
        fprintf(stderr, "message_bytes must be positive\n");
        return 1;
    }

    uint8_t *owned[BENCH_MESSAGES] = {0};
    const uint8_t *msg[BENCH_MESSAGES];
    size_t len[BENCH_MESSAGES];
    uint8_t out[BENCH_MESSAGES][32];
    for (size_t lane = 0; lane < BENCH_MESSAGES; ++lane) {
        owned[lane] = malloc(message_bytes);
        if (owned[lane] == NULL) {
            fprintf(stderr, "allocation failure\n");
            return 1;
        }
        for (size_t i = 0; i < message_bytes; ++i) {
            owned[lane][i] = (uint8_t)(i * 131u + lane * 17u + 23u);
        }
        msg[lane] = owned[lane];
        len[lane] = message_bytes;
    }

    const double target_bytes = (double)total_mib * 1024.0 * 1024.0;
    const double bytes_per_iteration = (double)BENCH_MESSAGES * (double)message_bytes;
    size_t iterations = (size_t)(target_bytes / bytes_per_iteration);
    if (iterations < 1u) {
        iterations = 1u;
    }

    printf("SM3 multi-buffer benchmark\n");
    printf("message_bytes=%zu messages=%u iterations=%zu samples=%u\n",
           message_bytes, BENCH_MESSAGES, iterations, BENCH_SAMPLES);
    printf("%-16s %14s %12s %12s\n", "backend", "MiB/s", "ns/byte", "speedup");

    const double scalar = bench_backend(SM3_BACKEND_SCALAR, msg, len, out,
                                        iterations, message_bytes);
    printf("%-16s %14.3f %12.4f %12.3f\n", "scalar", scalar,
           1.0e9 / (scalar * 1024.0 * 1024.0), 1.0);

#if defined(__x86_64__) || defined(_M_X64)
    const sm3_backend candidates[] = {SM3_BACKEND_AVX2, SM3_BACKEND_AVX512};
#elif defined(__aarch64__)
    const sm3_backend candidates[] = {SM3_BACKEND_NEON};
#else
    const sm3_backend candidates[] = {SM3_BACKEND_SCALAR};
#endif

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        if (!backend_available(candidates[i]) || candidates[i] == SM3_BACKEND_SCALAR) {
            continue;
        }
        const double rate = bench_backend(candidates[i], msg, len, out,
                                          iterations, message_bytes);
        printf("%-16s %14.3f %12.4f %12.3f\n",
               sm3_backend_name(candidates[i]), rate, 1.0e9 / (rate * 1024.0 * 1024.0), rate / scalar);
    }

    printf("sink=%u\n", (unsigned)bench_sink);
    for (size_t lane = 0; lane < BENCH_MESSAGES; ++lane) {
        free(owned[lane]);
    }
    return 0;
}
