#include "sm3.h"

#if defined(__x86_64__) || defined(_M_X64)
int sm3_cpu_has_avx2(void)
{
#if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2") != 0;
#else
    return 0;
#endif
}

int sm3_cpu_has_avx512f(void)
{
#if defined(__GNUC__) || defined(__clang__)
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx512f") != 0;
#else
    return 0;
#endif
}
#endif

#if defined(__aarch64__)
int sm3_cpu_has_neon(void)
{
    return 1;
}
#endif

const char *sm3_backend_name(sm3_backend backend)
{
    switch (backend) {
    case SM3_BACKEND_SCALAR: return "scalar";
    case SM3_BACKEND_AVX2: return "avx2-8way";
    case SM3_BACKEND_AVX512: return "avx512-16way";
    case SM3_BACKEND_NEON: return "neon-4way";
    case SM3_BACKEND_AUTO: return "auto";
    default: return "unknown";
    }
}

size_t sm3_backend_lanes(sm3_backend backend)
{
    switch (backend) {
    case SM3_BACKEND_AVX2: return 8u;
    case SM3_BACKEND_AVX512: return 16u;
    case SM3_BACKEND_NEON: return 4u;
    default: return 1u;
    }
}

sm3_backend sm3_best_backend(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    if (sm3_cpu_has_avx512f()) {
        return SM3_BACKEND_AVX512;
    }
    if (sm3_cpu_has_avx2()) {
        return SM3_BACKEND_AVX2;
    }
#elif defined(__aarch64__)
    if (sm3_cpu_has_neon()) {
        return SM3_BACKEND_NEON;
    }
#endif
    return SM3_BACKEND_SCALAR;
}

static void sm3_scalar_many(const uint8_t *const *msg, const size_t *len,
                            uint8_t (*out)[SM3_DIGEST_SIZE], size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        sm3_digest(msg[i], len[i], out[i]);
    }
}

int sm3_hash_many(sm3_backend backend,
                  const uint8_t *const *msg,
                  const size_t *len,
                  uint8_t (*out)[SM3_DIGEST_SIZE],
                  size_t count)
{
    if (count == 0u) {
        return 0;
    }
    if (msg == NULL || len == NULL || out == NULL) {
        return -1;
    }
    if (backend == SM3_BACKEND_AUTO) {
        backend = sm3_best_backend();
    }

    size_t offset = 0u;
    switch (backend) {
    case SM3_BACKEND_SCALAR:
        sm3_scalar_many(msg, len, out, count);
        return 0;

#if defined(__x86_64__) || defined(_M_X64)
    case SM3_BACKEND_AVX512:
        if (!sm3_cpu_has_avx512f()) {
            return -2;
        }
        while (count - offset >= 16u) {
            sm3_avx512_hash16(msg + offset, len + offset, out + offset);
            offset += 16u;
        }
        if (count - offset >= 8u && sm3_cpu_has_avx2()) {
            sm3_avx2_hash8(msg + offset, len + offset, out + offset);
            offset += 8u;
        }
        sm3_scalar_many(msg + offset, len + offset, out + offset, count - offset);
        return 0;

    case SM3_BACKEND_AVX2:
        if (!sm3_cpu_has_avx2()) {
            return -2;
        }
        while (count - offset >= 8u) {
            sm3_avx2_hash8(msg + offset, len + offset, out + offset);
            offset += 8u;
        }
        sm3_scalar_many(msg + offset, len + offset, out + offset, count - offset);
        return 0;
#endif

#if defined(__aarch64__)
    case SM3_BACKEND_NEON:
        while (count - offset >= 4u) {
            sm3_neon_hash4(msg + offset, len + offset, out + offset);
            offset += 4u;
        }
        sm3_scalar_many(msg + offset, len + offset, out + offset, count - offset);
        return 0;
#endif

    default:
        return -3;
    }
}
