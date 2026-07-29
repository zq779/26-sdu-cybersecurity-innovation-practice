#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <immintrin.h>
#include <tmmintrin.h>
#include <smmintrin.h>

static const uint8_t SBOX[16] = {
    0xc, 0x0, 0xf, 0xa, 0x2, 0xb, 0x9, 0x5,
    0x8, 0x3, 0xd, 0x7, 0x1, 0xe, 0x6, 0x4
};

static const uint8_t SHUFFLE[8] = {5, 0, 1, 4, 7, 12, 3, 8};

static const uint8_t RCON[36] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x03,0x06,
    0x0c,0x18,0x30,0x23,0x05,0x0a,0x14,0x28,
    0x13,0x26,0x0f,0x1e,0x3d,0x39,0x31,0x21,
    0x01,0x02,0x04,0x08,0x10,0x20,0x03,0x06,
    0x0c,0x18,0x30,0x23
};

#define ROUNDS 36

void twine_key_schedule(const uint8_t key[10], uint64_t rk[ROUNDS]) {
    uint8_t K[20];
    for (int i = 0; i < 10; i++) {
        K[2*i] = (key[i] >> 4) & 0xF;
        K[2*i+1] = key[i] & 0xF;
    }
    for (int r = 0; r < ROUNDS; r++) {
        uint64_t rk_val = 0;
        int idx = r % 20;
        for (int i = 0; i < 8; i++)
            rk_val |= ((uint64_t)K[(idx + i) % 20]) << (4 * i);
        rk_val ^= ((uint64_t)RCON[r]) << 12;
        rk[r] = rk_val & 0xFFFFFFFF;
    }
}

typedef void (*block_enc_fn)(const uint8_t*, uint8_t*, const uint64_t*);

void twine_encrypt_base(const uint8_t in[8], uint8_t out[8], const uint64_t rk[ROUNDS]) {
    uint64_t X = 0;
    for (int i = 0; i < 8; i++) X |= ((uint64_t)in[i]) << (8 * i);
    for (int r = 0; r < ROUNDS; r++) {
        uint32_t L = (uint32_t)(X >> 32), R = (uint32_t)X;
        uint32_t F = R ^ (uint32_t)rk[r];
        uint32_t new_R = 0;
        if (SHUFFLE[0] < 8) new_R |= ((uint32_t)SBOX[F & 0xF]) << (4 * SHUFFLE[0]);
        if (SHUFFLE[1] < 8) new_R |= ((uint32_t)SBOX[(F >> 4) & 0xF]) << (4 * SHUFFLE[1]);
        if (SHUFFLE[2] < 8) new_R |= ((uint32_t)SBOX[(F >> 8) & 0xF]) << (4 * SHUFFLE[2]);
        if (SHUFFLE[3] < 8) new_R |= ((uint32_t)SBOX[(F >> 12) & 0xF]) << (4 * SHUFFLE[3]);
        if (SHUFFLE[4] < 8) new_R |= ((uint32_t)SBOX[(F >> 16) & 0xF]) << (4 * SHUFFLE[4]);
        if (SHUFFLE[5] < 8) new_R |= ((uint32_t)SBOX[(F >> 20) & 0xF]) << (4 * SHUFFLE[5]);
        if (SHUFFLE[6] < 8) new_R |= ((uint32_t)SBOX[(F >> 24) & 0xF]) << (4 * SHUFFLE[6]);
        if (SHUFFLE[7] < 8) new_R |= ((uint32_t)SBOX[(F >> 28) & 0xF]) << (4 * SHUFFLE[7]);
        X = ((uint64_t)R << 32) | (L ^ new_R);
    }
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(X >> (8*i));
}

static uint32_t TT[8][16];
void twine_init_ttable(void) {
    for (int pos = 0; pos < 8; pos++)
        for (int v = 0; v < 16; v++)
            TT[pos][v] = (SHUFFLE[pos] < 8) ? ((uint32_t)SBOX[v] << (4 * SHUFFLE[pos])) : 0;
}

void twine_encrypt_ttable(const uint8_t in[8], uint8_t out[8], const uint64_t rk[ROUNDS]) {
    uint64_t X = 0;
    for (int i = 0; i < 8; i++) X |= ((uint64_t)in[i]) << (8 * i);
    for (int r = 0; r < ROUNDS; r++) {
        uint32_t L = (uint32_t)(X >> 32), R = (uint32_t)X;
        uint32_t F = R ^ (uint32_t)rk[r];
        uint32_t new_R = TT[0][F & 0xF] ^ TT[1][(F >> 4) & 0xF] ^
                         TT[2][(F >> 8) & 0xF] ^ TT[3][(F >> 12) & 0xF] ^
                         TT[4][(F >> 16) & 0xF] ^ TT[5][(F >> 20) & 0xF] ^
                         TT[6][(F >> 24) & 0xF] ^ TT[7][(F >> 28) & 0xF];
        X = ((uint64_t)R << 32) | (L ^ new_R);
    }
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(X >> (8*i));
}

static __m128i SBOX_TABLES[16];
static void init_ssse3_tables(void) {
    for (int hi = 0; hi < 16; hi++) {
        uint8_t tbl[16];
        for (int lo = 0; lo < 16; lo++)
            tbl[lo] = SBOX[(hi << 4) | lo];
        SBOX_TABLES[hi] = _mm_loadu_si128((__m128i*)tbl);
    }
}

static inline void twine_round_ssse3(uint32_t *L, uint32_t *R, uint32_t rk32) {
    uint32_t F = *R ^ rk32;
    __m128i f = _mm_set_epi32(0, 0, 0, F);
    __m128i hi = _mm_srli_epi32(f, 4);
    __m128i lo = _mm_and_si128(f, _mm_set1_epi8(0x0f));
    __m128i res = _mm_setzero_si128();
    for (int i = 0; i < 4; i++) {
        __m128i mask = _mm_cmpeq_epi32(hi, _mm_set1_epi32(i));
        __m128i shuffled = _mm_shuffle_epi8(SBOX_TABLES[i], lo);
        res = _mm_or_si128(res, _mm_and_si128(mask, shuffled));
    }
    uint32_t new_R = (uint32_t)_mm_cvtsi128_si32(res);
    *R = new_R;
    uint32_t tmp = *L;
    *L = *R;
    *R = tmp ^ new_R;
}

void twine_encrypt_ssse3(const uint8_t in[8], uint8_t out[8], const uint64_t rk[ROUNDS]) {
    uint64_t X = 0;
    for (int i = 0; i < 8; i++) X |= ((uint64_t)in[i]) << (8 * i);
    uint32_t L = (uint32_t)(X >> 32), R = (uint32_t)X;
    for (int r = 0; r < ROUNDS; r++) {
        uint32_t rk32 = (uint32_t)rk[r];
        twine_round_ssse3(&L, &R, rk32);
    }
    X = ((uint64_t)R << 32) | L;
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(X >> (8*i));
}

static inline void twine_round_avx2(uint32_t *L, uint32_t *R, uint32_t rk32) {
    uint32_t F = *R ^ rk32;
    __m256i f = _mm256_set1_epi32(F);
    __m256i hi = _mm256_srli_epi16(f, 4);
    __m256i lo = _mm256_and_si256(f, _mm256_set1_epi8(0x0f));
    __m256i res = _mm256_setzero_si256();
    for (int i = 0; i < 4; i++) {
        __m256i mask = _mm256_cmpeq_epi32(hi, _mm256_set1_epi32(i));
        __m256i table = _mm256_broadcastsi128_si256(SBOX_TABLES[i]);
        __m256i shuffled = _mm256_shuffle_epi8(table, lo);
        res = _mm256_or_si256(res, _mm256_and_si256(mask, shuffled));
    }
    uint32_t new_R = (uint32_t)_mm_cvtsi128_si32(_mm256_castsi256_si128(res));
    *R = new_R;
    uint32_t tmp = *L;
    *L = *R;
    *R = tmp ^ new_R;
}

void twine_encrypt_avx2(const uint8_t in[8], uint8_t out[8], const uint64_t rk[ROUNDS]) {
    uint64_t X = 0;
    for (int i = 0; i < 8; i++) X |= ((uint64_t)in[i]) << (8 * i);
    uint32_t L = (uint32_t)(X >> 32), R = (uint32_t)X;
    for (int r = 0; r < ROUNDS; r++) {
        uint32_t rk32 = (uint32_t)rk[r];
        twine_round_avx2(&L, &R, rk32);
    }
    X = ((uint64_t)R << 32) | L;
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(X >> (8*i));
}

static inline void twine_encrypt_2x_ssse3(const uint8_t in0[8], const uint8_t in1[8],
                                          uint8_t out0[8], uint8_t out1[8],
                                          const uint64_t rk[ROUNDS]) {
    uint64_t x0 = 0, x1 = 0;
    for (int i = 0; i < 8; i++) {
        x0 |= ((uint64_t)in0[i]) << (8*i);
        x1 |= ((uint64_t)in1[i]) << (8*i);
    }
    uint32_t L0 = (uint32_t)(x0 >> 32), R0 = (uint32_t)x0;
    uint32_t L1 = (uint32_t)(x1 >> 32), R1 = (uint32_t)x1;
    for (int r = 0; r < ROUNDS; r++) {
        uint32_t rk32 = (uint32_t)rk[r];
        twine_round_ssse3(&L0, &R0, rk32);
        twine_round_ssse3(&L1, &R1, rk32);
    }
    x0 = ((uint64_t)R0 << 32) | L0;
    x1 = ((uint64_t)R1 << 32) | L1;
    for (int i = 0; i < 8; i++) {
        out0[i] = (uint8_t)(x0 >> (8*i));
        out1[i] = (uint8_t)(x1 >> (8*i));
    }
}

static inline void twine_encrypt_2x_avx2(const uint8_t in0[8], const uint8_t in1[8],
                                         uint8_t out0[8], uint8_t out1[8],
                                         const uint64_t rk[ROUNDS]) {
    uint64_t x0 = 0, x1 = 0;
    for (int i = 0; i < 8; i++) {
        x0 |= ((uint64_t)in0[i]) << (8*i);
        x1 |= ((uint64_t)in1[i]) << (8*i);
    }
    uint32_t L0 = (uint32_t)(x0 >> 32), R0 = (uint32_t)x0;
    uint32_t L1 = (uint32_t)(x1 >> 32), R1 = (uint32_t)x1;
    for (int r = 0; r < ROUNDS; r++) {
        uint32_t rk32 = (uint32_t)rk[r];
        twine_round_avx2(&L0, &R0, rk32);
        twine_round_avx2(&L1, &R1, rk32);
    }
    x0 = ((uint64_t)R0 << 32) | L0;
    x1 = ((uint64_t)R1 << 32) | L1;
    for (int i = 0; i < 8; i++) {
        out0[i] = (uint8_t)(x0 >> (8*i));
        out1[i] = (uint8_t)(x1 >> (8*i));
    }
}

static void twine_ctr_ssse3_4x(const uint8_t *in, uint8_t *out, size_t nblocks,
                               const uint8_t *ctr_init, const uint64_t rk[ROUNDS]) {
    uint64_t base = 0;
    for (int i = 0; i < 8; i++) base |= ((uint64_t)ctr_init[i]) << (8*i);
    for (size_t b = 0; b < nblocks; b += 4) {
        uint8_t ctrs[4][8], ks[4][8] __attribute__((aligned(16)));
        for (int k = 0; k < 4; k++) {
            uint64_t ctr = base + b + k;
            for (int i = 0; i < 8; i++) ctrs[k][i] = (uint8_t)(ctr >> (8*i));
        }
        twine_encrypt_2x_ssse3(ctrs[0], ctrs[1], ks[0], ks[1], rk);
        twine_encrypt_2x_ssse3(ctrs[2], ctrs[3], ks[2], ks[3], rk);
        __m128i pt0 = _mm_loadu_si128((__m128i*)(in + b*8));
        __m128i pt1 = _mm_loadu_si128((__m128i*)(in + (b+2)*8));
        _mm_storeu_si128((__m128i*)(out + b*8), _mm_xor_si128(pt0, _mm_load_si128((__m128i*)ks)));
        _mm_storeu_si128((__m128i*)(out + (b+2)*8), _mm_xor_si128(pt1, _mm_load_si128((__m128i*)(ks+2))));
    }
}

#ifdef __AVX2__
static void twine_ctr_avx2_8x(const uint8_t *in, uint8_t *out, size_t nblocks,
                               const uint8_t *ctr_init, const uint64_t rk[ROUNDS]) {
    uint64_t base = 0;
    for (int i = 0; i < 8; i++) base |= ((uint64_t)ctr_init[i]) << (8*i);
    for (size_t b = 0; b < nblocks; b += 8) {
        uint8_t ctrs[8][8], ks[8][8] __attribute__((aligned(32)));
        for (int k = 0; k < 8; k++) {
            uint64_t ctr = base + b + k;
            for (int i = 0; i < 8; i++) ctrs[k][i] = (uint8_t)(ctr >> (8*i));
        }
        twine_encrypt_2x_avx2(ctrs[0], ctrs[1], ks[0], ks[1], rk);
        twine_encrypt_2x_avx2(ctrs[2], ctrs[3], ks[2], ks[3], rk);
        twine_encrypt_2x_avx2(ctrs[4], ctrs[5], ks[4], ks[5], rk);
        twine_encrypt_2x_avx2(ctrs[6], ctrs[7], ks[6], ks[7], rk);
        __m256i pt0 = _mm256_loadu_si256((__m256i*)(in + b*8));
        __m256i pt1 = _mm256_loadu_si256((__m256i*)(in + (b+4)*8));
        _mm256_storeu_si256((__m256i*)(out + b*8), _mm256_xor_si256(pt0, _mm256_load_si256((__m256i*)ks)));
        _mm256_storeu_si256((__m256i*)(out + (b+4)*8), _mm256_xor_si256(pt1, _mm256_load_si256((__m256i*)(ks+4))));
    }
}
#endif

#ifdef __BMI2__
static const uint32_t BMI2_MASKS[8] = {0xF<<(4*5), 0xF<<(4*0), 0xF<<(4*1), 0xF<<(4*4),
                                       0xF<<(4*7), 0, 0xF<<(4*3), 0};

static void twine_encrypt_bmi2_2x(const uint8_t in0[8], const uint8_t in1[8],
                                  uint8_t out0[8], uint8_t out1[8], const uint64_t rk[ROUNDS]) {
    uint64_t x0 = 0, x1 = 0;
    for (int i = 0; i < 8; i++) {
        x0 |= ((uint64_t)in0[i]) << (8*i);
        x1 |= ((uint64_t)in1[i]) << (8*i);
    }
    for (int r = 0; r < ROUNDS; r++) {
        uint32_t L0 = (uint32_t)(x0 >> 32), R0 = (uint32_t)x0;
        uint32_t L1 = (uint32_t)(x1 >> 32), R1 = (uint32_t)x1;
        uint32_t rk32 = (uint32_t)rk[r];
        uint32_t F0 = R0 ^ rk32, F1 = R1 ^ rk32;

        uint32_t nR0 = _pdep_u32(SBOX[F0 & 0xF], BMI2_MASKS[0]);
        nR0 |= _pdep_u32(SBOX[(F0>>4)&0xF], BMI2_MASKS[1]);
        nR0 |= _pdep_u32(SBOX[(F0>>8)&0xF], BMI2_MASKS[2]);
        nR0 |= _pdep_u32(SBOX[(F0>>12)&0xF], BMI2_MASKS[3]);
        nR0 |= _pdep_u32(SBOX[(F0>>16)&0xF], BMI2_MASKS[4]);
        nR0 |= _pdep_u32(SBOX[(F0>>24)&0xF], BMI2_MASKS[6]);

        uint32_t nR1 = _pdep_u32(SBOX[F1 & 0xF], BMI2_MASKS[0]);
        nR1 |= _pdep_u32(SBOX[(F1>>4)&0xF], BMI2_MASKS[1]);
        nR1 |= _pdep_u32(SBOX[(F1>>8)&0xF], BMI2_MASKS[2]);
        nR1 |= _pdep_u32(SBOX[(F1>>12)&0xF], BMI2_MASKS[3]);
        nR1 |= _pdep_u32(SBOX[(F1>>16)&0xF], BMI2_MASKS[4]);
        nR1 |= _pdep_u32(SBOX[(F1>>24)&0xF], BMI2_MASKS[6]);

        x0 = ((uint64_t)R0 << 32) | (L0 ^ nR0);
        x1 = ((uint64_t)R1 << 32) | (L1 ^ nR1);
    }
    for (int i = 0; i < 8; i++) {
        out0[i] = (uint8_t)(x0 >> (8*i));
        out1[i] = (uint8_t)(x1 >> (8*i));
    }
}

static void twine_ctr_bmi2_8x(const uint8_t *in, uint8_t *out, size_t nblocks,
                               const uint8_t *ctr_init, const uint64_t rk[ROUNDS]) {
    uint64_t base = 0;
    for (int i = 0; i < 8; i++) base |= ((uint64_t)ctr_init[i]) << (8*i);
    for (size_t b = 0; b < nblocks; b += 8) {
        uint8_t ctrs[8][8], ks[8][8] __attribute__((aligned(32)));
        for (int k = 0; k < 8; k++) {
            uint64_t ctr = base + b + k;
            for (int i = 0; i < 8; i++) ctrs[k][i] = (uint8_t)(ctr >> (8*i));
        }
        twine_encrypt_bmi2_2x(ctrs[0], ctrs[1], ks[0], ks[1], rk);
        twine_encrypt_bmi2_2x(ctrs[2], ctrs[3], ks[2], ks[3], rk);
        twine_encrypt_bmi2_2x(ctrs[4], ctrs[5], ks[4], ks[5], rk);
        twine_encrypt_bmi2_2x(ctrs[6], ctrs[7], ks[6], ks[7], rk);
#ifdef __AVX2__
        __m256i pt0 = _mm256_loadu_si256((__m256i*)(in + b*8));
        __m256i pt1 = _mm256_loadu_si256((__m256i*)(in + (b+4)*8));
        _mm256_storeu_si256((__m256i*)(out + b*8), _mm256_xor_si256(pt0, _mm256_load_si256((__m256i*)ks)));
        _mm256_storeu_si256((__m256i*)(out + (b+4)*8), _mm256_xor_si256(pt1, _mm256_load_si256((__m256i*)(ks+4))));
#else
        for (int k = 0; k < 8; k += 2) {
            __m128i pt = _mm_loadu_si128((__m128i*)(in + (b+k)*8));
            _mm_storeu_si128((__m128i*)(out + (b+k)*8), _mm_xor_si128(pt, _mm_load_si128((__m128i*)(ks+k))));
        }
#endif
    }
}
#endif

static void twine_xts_encrypt_2x(const uint8_t *in, uint8_t *out, size_t nblocks,
                                  const uint8_t iv[8], const uint64_t rk[ROUNDS],
                                  void (*enc2)(const uint8_t*,const uint8_t*,uint8_t*,uint8_t*,const uint64_t*)) {
    uint8_t tweak0[8], tweak1[8];
    {
        uint8_t raw[8];
        twine_encrypt_ttable(iv, raw, rk);
        memcpy(tweak0, raw, 8);
        uint8_t carry = 0;
        for (int i = 0; i < 8; i++) {
            uint8_t nc = tweak0[i] >> 7;
            tweak1[i] = (tweak0[i] << 1) | carry;
            carry = nc;
        }
        if (carry) tweak1[0] ^= 0x1B;
    }

    for (size_t b = 0; b < nblocks; b += 2) {
        if (b + 1 < nblocks) {
            uint8_t buf0[8], buf1[8];
            for (int i = 0; i < 8; i++) {
                buf0[i] = in[b*8 + i] ^ tweak0[i];
                buf1[i] = in[(b+1)*8 + i] ^ tweak1[i];
            }
            enc2(buf0, buf1, buf0, buf1, rk);
            for (int i = 0; i < 8; i++) {
                out[b*8 + i] = buf0[i] ^ tweak0[i];
                out[(b+1)*8 + i] = buf1[i] ^ tweak1[i];
            }
            for (int t = 0; t < 2; t++) {
                uint8_t *tw = (t==0) ? tweak0 : tweak1;
                for (int mul = 0; mul < 2; mul++) {
                    uint8_t c = 0;
                    for (int i = 0; i < 8; i++) {
                        uint8_t nc = tw[i] >> 7;
                        tw[i] = (tw[i] << 1) | c;
                        c = nc;
                    }
                    if (c) tw[0] ^= 0x1B;
                }
            }
        } else {
            uint8_t buf[8];
            for (int i = 0; i < 8; i++) buf[i] = in[b*8 + i] ^ tweak0[i];
            twine_encrypt_ttable(buf, buf, rk);
            for (int i = 0; i < 8; i++) out[b*8 + i] = buf[i] ^ tweak0[i];
        }
    }
}

typedef void (*mode_fn)(const uint8_t*, uint8_t*, size_t,
                        const uint8_t*, const uint64_t*, block_enc_fn);

void twine_ctr_crypt_base(const uint8_t *in, uint8_t *out, size_t len,
                          const uint8_t iv[8], const uint64_t rk[ROUNDS], block_enc_fn enc) {
    uint8_t ctr[8];
    memcpy(ctr, iv, 8);
    for (size_t b = 0; b < len/8; b++) {
        uint8_t ks[8];
        enc(ctr, ks, rk);
        for (int i = 0; i < 8; i++) out[b*8+i] = in[b*8+i] ^ ks[i];
        for (int i = 7; i >= 0; i--) { ctr[i]++; if (ctr[i] != 0) break; }
    }
}

void twine_ctr_crypt_ssse3(const uint8_t *in, uint8_t *out, size_t len,
                           const uint8_t iv[8], const uint64_t rk[ROUNDS], block_enc_fn enc) {
    (void)enc;
    uint8_t ctr[8]; memcpy(ctr, iv, 8);
    twine_ctr_ssse3_4x(in, out, len/8, ctr, rk);
}

void twine_ctr_crypt_avx2(const uint8_t *in, uint8_t *out, size_t len,
                          const uint8_t iv[8], const uint64_t rk[ROUNDS], block_enc_fn enc) {
    (void)enc;
    uint8_t ctr[8]; memcpy(ctr, iv, 8);
#ifdef __AVX2__
    twine_ctr_avx2_8x(in, out, len/8, ctr, rk);
#else
    twine_ctr_ssse3_4x(in, out, len/8, ctr, rk);
#endif
}

void twine_ctr_crypt_bmi2(const uint8_t *in, uint8_t *out, size_t len,
                          const uint8_t iv[8], const uint64_t rk[ROUNDS], block_enc_fn enc) {
    (void)enc;
    uint8_t ctr[8]; memcpy(ctr, iv, 8);
#ifdef __BMI2__
    twine_ctr_bmi2_8x(in, out, len/8, ctr, rk);
#else
    twine_ctr_crypt_base(in, out, len, iv, rk, twine_encrypt_ttable);
#endif
}

void twine_gcm_crypt_base(const uint8_t *in, uint8_t *out, size_t len,
                          const uint8_t iv[8], const uint64_t rk[ROUNDS], block_enc_fn enc) {
    twine_ctr_crypt_base(in, out, len, iv, rk, enc);
}

void twine_gcm_crypt_ssse3(const uint8_t *in, uint8_t *out, size_t len,
                           const uint8_t iv[8], const uint64_t rk[ROUNDS], block_enc_fn enc) {
    twine_ctr_crypt_ssse3(in, out, len, iv, rk, enc);
}

void twine_gcm_crypt_avx2(const uint8_t *in, uint8_t *out, size_t len,
                          const uint8_t iv[8], const uint64_t rk[ROUNDS], block_enc_fn enc) {
    twine_ctr_crypt_avx2(in, out, len, iv, rk, enc);
}

void twine_gcm_crypt_bmi2(const uint8_t *in, uint8_t *out, size_t len,
                          const uint8_t iv[8], const uint64_t rk[ROUNDS], block_enc_fn enc) {
    twine_ctr_crypt_bmi2(in, out, len, iv, rk, enc);
}

void twine_xts_crypt_base(const uint8_t *in, uint8_t *out, size_t len,
                          const uint8_t iv[8], const uint64_t rk[ROUNDS], block_enc_fn enc) {
    uint8_t tweak[8];
    enc(iv, tweak, rk);
    for (size_t b = 0; b < len/8; b++) {
        for (int i = 0; i < 8; i++) out[b*8+i] = in[b*8+i] ^ tweak[i];
        enc(out + b*8, out + b*8, rk);
        for (int i = 0; i < 8; i++) out[b*8+i] ^= tweak[i];
        uint8_t carry = 0;
        for (int i = 0; i < 8; i++) {
            uint8_t nc = tweak[i] >> 7;
            tweak[i] = (tweak[i] << 1) | carry;
            carry = nc;
        }
        if (carry) tweak[0] ^= 0x1B;
    }
}

void twine_xts_crypt_ssse3(const uint8_t *in, uint8_t *out, size_t len,
                           const uint8_t iv[8], const uint64_t rk[ROUNDS], block_enc_fn enc) {
    (void)enc;
    twine_xts_encrypt_2x(in, out, len/8, iv, rk, twine_encrypt_2x_ssse3);
}

void twine_xts_crypt_avx2(const uint8_t *in, uint8_t *out, size_t len,
                          const uint8_t iv[8], const uint64_t rk[ROUNDS], block_enc_fn enc) {
    (void)enc;
    twine_xts_encrypt_2x(in, out, len/8, iv, rk, twine_encrypt_2x_avx2);
}

void twine_xts_crypt_bmi2(const uint8_t *in, uint8_t *out, size_t len,
                          const uint8_t iv[8], const uint64_t rk[ROUNDS], block_enc_fn enc) {
    (void)enc;
#ifdef __BMI2__
    twine_xts_encrypt_2x(in, out, len/8, iv, rk, twine_encrypt_bmi2_2x);
#else
    twine_xts_crypt_base(in, out, len, iv, rk, twine_encrypt_ttable);
#endif
}

typedef void (*mode_fn)(const uint8_t*, uint8_t*, size_t,
                        const uint8_t*, const uint64_t*, block_enc_fn);

void benchmark(const char *mode_name, const char *impl_name,
               mode_fn mode_func, block_enc_fn enc,
               uint8_t *in, uint8_t *out, size_t len,
               const uint8_t *iv, const uint64_t *rk) {
    clock_t start = clock();
    for (int iter = 0; iter < 10; iter++) {
        uint8_t cur_iv[8];
        memcpy(cur_iv, iv, 8);
        cur_iv[7] = iter;
        mode_func(in, out, len, cur_iv, rk, enc);
    }
    double sec = (double)(clock() - start) / CLOCKS_PER_SEC;
    double mb = len * 10.0 / (1024 * 1024);
    printf("  %-6s %-8s | %8.3f 秒 | %10.2f MB/s\n", mode_name, impl_name, sec, mb/sec);
}

int main(void) {
    twine_init_ttable();
    init_ssse3_tables();

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║      TWINE 多方案 & 多模式 性能对比测试             ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    uint8_t key[10] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99};
    uint8_t iv[8] = {0};
    uint64_t rk[ROUNDS];
    twine_key_schedule(key, rk);

    block_enc_fn enc_funcs[] = {
        twine_encrypt_base,
        twine_encrypt_ttable,
        twine_encrypt_ssse3,
        twine_encrypt_avx2,
#ifdef __BMI2__
        NULL
#else
        twine_encrypt_ttable
#endif
    };
    const char *names[] = {"Base", "T-Table", "SSSE3", "AVX2", "BMI2"};

    size_t len = 100UL * 1024 * 1024;
    uint8_t *in = (uint8_t*)aligned_alloc(64, len);
    uint8_t *out = (uint8_t*)aligned_alloc(64, len);
    memset(in, 0xAA, len);

    mode_fn ctr_funcs[] = { twine_ctr_crypt_base, twine_ctr_crypt_base,
                            twine_ctr_crypt_ssse3, twine_ctr_crypt_avx2, twine_ctr_crypt_bmi2 };
    mode_fn gcm_funcs[] = { twine_gcm_crypt_base, twine_gcm_crypt_base,
                            twine_gcm_crypt_ssse3, twine_gcm_crypt_avx2, twine_gcm_crypt_bmi2 };
    mode_fn xts_funcs[] = { twine_xts_crypt_base, twine_xts_crypt_base,
                            twine_xts_crypt_ssse3, twine_xts_crypt_avx2, twine_xts_crypt_bmi2 };

    printf("\n═══════ CTR 模式 (%luMB × 10次) ═══════\n", len/(1024*1024));
    for (int i = 0; i < 5; i++)
        benchmark("CTR", names[i], ctr_funcs[i], enc_funcs[i], in, out, len, iv, rk);

    printf("\n═══════ GCM 模式 (%luMB × 10次) ═══════\n", len/(1024*1024));
    for (int i = 0; i < 5; i++)
        benchmark("GCM", names[i], gcm_funcs[i], enc_funcs[i], in, out, len, iv, rk);

    printf("\n═══════ XTS 模式 (%luMB × 10次) ═══════\n", len/(1024*1024));
    for (int i = 0; i < 5; i++)
        benchmark("XTS", names[i], xts_funcs[i], enc_funcs[i], in, out, len, iv, rk);

    free(in); free(out);
    printf("\n═══════ 测试完成 ═══════\n");
    return 0;
}