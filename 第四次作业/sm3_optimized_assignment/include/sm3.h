#ifndef SM3_OPTIMIZED_SM3_H
#define SM3_OPTIMIZED_SM3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM3_DIGEST_SIZE 32u
#define SM3_BLOCK_SIZE 64u

typedef enum sm3_backend {
    SM3_BACKEND_SCALAR = 0,
    SM3_BACKEND_AVX2,
    SM3_BACKEND_AVX512,
    SM3_BACKEND_NEON,
    SM3_BACKEND_AUTO
} sm3_backend;

void sm3_digest(const uint8_t *msg, size_t len, uint8_t out[SM3_DIGEST_SIZE]);

#if defined(__x86_64__) || defined(_M_X64)
void sm3_avx2_hash8(const uint8_t *const msg[8], const size_t len[8],
                    uint8_t out[8][SM3_DIGEST_SIZE]);
void sm3_avx512_hash16(const uint8_t *const msg[16], const size_t len[16],
                       uint8_t out[16][SM3_DIGEST_SIZE]);
int sm3_cpu_has_avx2(void);
int sm3_cpu_has_avx512f(void);
#endif

#if defined(__aarch64__)
void sm3_neon_hash4(const uint8_t *const msg[4], const size_t len[4],
                    uint8_t out[4][SM3_DIGEST_SIZE]);
int sm3_cpu_has_neon(void);
#endif

const char *sm3_backend_name(sm3_backend backend);
size_t sm3_backend_lanes(sm3_backend backend);
sm3_backend sm3_best_backend(void);
int sm3_hash_many(sm3_backend backend,
                  const uint8_t *const *msg,
                  const size_t *len,
                  uint8_t (*out)[SM3_DIGEST_SIZE],
                  size_t count);

#ifdef __cplusplus
}
#endif

#endif
