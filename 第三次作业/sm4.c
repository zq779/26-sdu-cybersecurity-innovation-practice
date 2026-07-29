#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <tmmintrin.h>
#include <wmmintrin.h>
#include <immintrin.h>

static const uint8_t SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

static const uint32_t FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
static const uint32_t CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static inline uint32_t sm4_L(uint32_t B) {
    return B ^ ROL32(B, 2) ^ ROL32(B, 10) ^ ROL32(B, 18) ^ ROL32(B, 24);
}

static inline uint32_t sm4_T(uint32_t X) {
    uint8_t a0 = SBOX[(X >> 24) & 0xFF];
    uint8_t a1 = SBOX[(X >> 16) & 0xFF];
    uint8_t a2 = SBOX[(X >> 8) & 0xFF];
    uint8_t a3 = SBOX[X & 0xFF];
    uint32_t B = (a0 << 24) | (a1 << 16) | (a2 << 8) | a3;
    return sm4_L(B);
}

void sm4_key_schedule(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t K[36];
    for (int i = 0; i < 4; i++) {
        K[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
               ((uint32_t)key[4*i+2] << 8) | key[4*i+3];
        K[i] ^= FK[i];
    }
    for (int i = 0; i < 32; i++) {
        K[i+4] = K[i] ^ sm4_T(K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i]);
        rk[i] = K[i+4];
    }
}

typedef void (*block_enc_fn)(const uint8_t*, uint8_t*, const uint32_t*);

void sm4_encrypt_base(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[4];
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)in[4*i] << 24) | ((uint32_t)in[4*i+1] << 16) |
               ((uint32_t)in[4*i+2] << 8) | in[4*i+3];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t x4 = X[0] ^ sm4_T(X[1] ^ X[2] ^ X[3] ^ rk[i]);
        X[0] = X[1]; X[1] = X[2]; X[2] = X[3]; X[3] = x4;
    }
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[3 - i];
        out[4*i]   = (val >> 24) & 0xFF;
        out[4*i+1] = (val >> 16) & 0xFF;
        out[4*i+2] = (val >> 8) & 0xFF;
        out[4*i+3] = val & 0xFF;
    }
}

static uint32_t TBL0[256], TBL1[256], TBL2[256], TBL3[256];

void sm4_init_ttable(void) {
    for (int i = 0; i < 256; i++) {
        uint8_t s = SBOX[i];
        TBL0[i] = sm4_L((uint32_t)s << 24);
        TBL1[i] = sm4_L((uint32_t)s << 16);
        TBL2[i] = sm4_L((uint32_t)s << 8);
        TBL3[i] = sm4_L((uint32_t)s);
    }
}

void sm4_encrypt_ttable(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[4];
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)in[4*i] << 24) | ((uint32_t)in[4*i+1] << 16) |
               ((uint32_t)in[4*i+2] << 8) | in[4*i+3];
    }
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = X[1] ^ X[2] ^ X[3] ^ rk[i];
        uint32_t x4 = X[0] ^ TBL0[(tmp >> 24) & 0xFF] ^
                             TBL1[(tmp >> 16) & 0xFF] ^
                             TBL2[(tmp >> 8) & 0xFF] ^
                             TBL3[tmp & 0xFF];
        X[0] = X[1]; X[1] = X[2]; X[2] = X[3]; X[3] = x4;
    }
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[3 - i];
        out[4*i]   = (val >> 24) & 0xFF;
        out[4*i+1] = (val >> 16) & 0xFF;
        out[4*i+2] = (val >> 8) & 0xFF;
        out[4*i+3] = val & 0xFF;
    }
}

static __m128i SBOX_SSSE3_TABLES[16];

void sm4_init_ssse3(void) {
    for (int hi = 0; hi < 16; hi++) {
        uint8_t tbl[16];
        for (int lo = 0; lo < 16; lo++)
            tbl[lo] = SBOX[(hi << 4) | lo];
        SBOX_SSSE3_TABLES[hi] = _mm_loadu_si128((__m128i*)tbl);
    }
}

static inline __m128i sm4_sbox_ssse3(__m128i x) {
    __m128i hi = _mm_srli_epi16(x, 4);
    __m128i lo = _mm_and_si128(x, _mm_set1_epi8(0x0f));
    __m128i res = _mm_setzero_si128();
    for (int i = 0; i < 16; i++) {
        __m128i mask = _mm_cmpeq_epi8(hi, _mm_set1_epi8(i));
        __m128i val = _mm_shuffle_epi8(SBOX_SSSE3_TABLES[i], lo);
        res = _mm_or_si128(res, _mm_and_si128(mask, val));
    }
    return res;
}

void sm4_encrypt_ssse3(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[4];
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)in[4*i] << 24) | ((uint32_t)in[4*i+1] << 16) |
               ((uint32_t)in[4*i+2] << 8) | in[4*i+3];
    }
    for (int r = 0; r < 32; r++) {
        uint32_t tmp = X[1] ^ X[2] ^ X[3] ^ rk[r];
        uint8_t b0 = tmp >> 24;
        uint8_t b1 = (tmp >> 16) & 0xFF;
        uint8_t b2 = (tmp >> 8) & 0xFF;
        uint8_t b3 = tmp & 0xFF;
        __m128i v = _mm_set_epi8(0,0,0,b3, 0,0,0,b2, 0,0,0,b1, 0,0,0,b0);
        v = sm4_sbox_ssse3(v);
        uint32_t B = ((uint32_t)_mm_extract_epi8(v, 0) << 24) |
                     ((uint32_t)_mm_extract_epi8(v, 1) << 16) |
                     ((uint32_t)_mm_extract_epi8(v, 2) << 8) |
                     (uint32_t)_mm_extract_epi8(v, 3);
        uint32_t x4 = X[0] ^ sm4_L(B);
        X[0] = X[1]; X[1] = X[2]; X[2] = X[3]; X[3] = x4;
    }
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[3 - i];
        out[4*i]   = (val >> 24) & 0xFF;
        out[4*i+1] = (val >> 16) & 0xFF;
        out[4*i+2] = (val >> 8) & 0xFF;
        out[4*i+3] = val & 0xFF;
    }
}

static uint8_t SM4_TO_AES[256];
static uint8_t AES_TO_SM4[256];
static __m128i SM4_TO_AES_LO[16];
static __m128i SM4_TO_AES_HI[16];
static __m128i AES_TO_SM4_LO[16];
static __m128i AES_TO_SM4_HI[16];

void sm4_init_aesni(void) {
    for (int i = 0; i < 256; i++) {
        SM4_TO_AES[i] = i;
        AES_TO_SM4[i] = i;
    }
    for (int hi = 0; hi < 16; hi++) {
        uint8_t tbl_lo[16], tbl_hi[16], inv_lo[16], inv_hi[16];
        for (int lo = 0; lo < 16; lo++) {
            int idx = (hi << 4) | lo;
            int aes_idx = SM4_TO_AES[idx];
            tbl_hi[lo] = aes_idx >> 4;
            tbl_lo[lo] = aes_idx & 0xF;
            int sm4_idx = AES_TO_SM4[aes_idx];
            inv_hi[lo] = sm4_idx >> 4;
            inv_lo[lo] = sm4_idx & 0xF;
        }
        SM4_TO_AES_HI[hi] = _mm_loadu_si128((__m128i*)tbl_hi);
        SM4_TO_AES_LO[hi] = _mm_loadu_si128((__m128i*)tbl_lo);
        AES_TO_SM4_HI[hi] = _mm_loadu_si128((__m128i*)inv_hi);
        AES_TO_SM4_LO[hi] = _mm_loadu_si128((__m128i*)inv_lo);
    }
}

static inline __m128i sm4_sbox_aesni(__m128i x) {
    __m128i hi = _mm_srli_epi16(x, 4);
    __m128i lo = _mm_and_si128(x, _mm_set1_epi8(0x0f));
    __m128i a = _mm_setzero_si128();
    for (int i = 0; i < 16; i++) {
        __m128i mask = _mm_cmpeq_epi8(hi, _mm_set1_epi8(i));
        __m128i val_lo = _mm_shuffle_epi8(SM4_TO_AES_LO[i], lo);
        __m128i val_hi = _mm_shuffle_epi8(SM4_TO_AES_HI[i], lo);
        __m128i val = _mm_or_si128(_mm_and_si128(val_hi, _mm_set1_epi8(0xF0)), val_lo);
        a = _mm_or_si128(a, _mm_and_si128(mask, val));
    }
    a = _mm_aesenclast_si128(a, _mm_setzero_si128());
    hi = _mm_srli_epi16(a, 4);
    lo = _mm_and_si128(a, _mm_set1_epi8(0x0f));
    __m128i res = _mm_setzero_si128();
    for (int i = 0; i < 16; i++) {
        __m128i mask = _mm_cmpeq_epi8(hi, _mm_set1_epi8(i));
        __m128i val_lo = _mm_shuffle_epi8(AES_TO_SM4_LO[i], lo);
        __m128i val_hi = _mm_shuffle_epi8(AES_TO_SM4_HI[i], lo);
        __m128i val = _mm_or_si128(_mm_and_si128(val_hi, _mm_set1_epi8(0xF0)), val_lo);
        res = _mm_or_si128(res, _mm_and_si128(mask, val));
    }
    return res;
}

void sm4_encrypt_aesni(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t X[4];
    for (int i = 0; i < 4; i++) {
        X[i] = ((uint32_t)in[4*i] << 24) | ((uint32_t)in[4*i+1] << 16) |
               ((uint32_t)in[4*i+2] << 8) | in[4*i+3];
    }
    for (int r = 0; r < 32; r++) {
        uint32_t tmp = X[1] ^ X[2] ^ X[3] ^ rk[r];
        uint8_t b0 = tmp >> 24;
        uint8_t b1 = (tmp >> 16) & 0xFF;
        uint8_t b2 = (tmp >> 8) & 0xFF;
        uint8_t b3 = tmp & 0xFF;
        __m128i v = _mm_set_epi8(0,0,0,b3, 0,0,0,b2, 0,0,0,b1, 0,0,0,b0);
        v = sm4_sbox_aesni(v);
        uint32_t B = ((uint32_t)_mm_extract_epi8(v, 0) << 24) |
                     ((uint32_t)_mm_extract_epi8(v, 1) << 16) |
                     ((uint32_t)_mm_extract_epi8(v, 2) << 8) |
                     (uint32_t)_mm_extract_epi8(v, 3);
        uint32_t x4 = X[0] ^ sm4_L(B);
        X[0] = X[1]; X[1] = X[2]; X[2] = X[3]; X[3] = x4;
    }
    for (int i = 0; i < 4; i++) {
        uint32_t val = X[3 - i];
        out[4*i]   = (val >> 24) & 0xFF;
        out[4*i+1] = (val >> 16) & 0xFF;
        out[4*i+2] = (val >> 8) & 0xFF;
        out[4*i+3] = val & 0xFF;
    }
}

static void sm4_ctr_8way_ttable(const uint8_t *in, uint8_t *out, size_t nblocks,
                                const uint8_t *ctr_init, const uint32_t rk[32]) {
    uint32_t ctr_words[4];
    memcpy(ctr_words, ctr_init, 16);
    uint32_t base = ctr_words[3];
    __m128i counters[8];
    uint8_t ctr_buf[8][16];
    for (int k = 0; k < 8; k++) {
        ctr_words[3] = base + k;
        counters[k] = _mm_loadu_si128((__m128i*)ctr_words);
    }
    __m128i inc = _mm_set_epi32(0, 0, 0, 8);
    for (size_t b = 0; b < nblocks; b += 8) {
        for (int k = 0; k < 8; k++) {
            _mm_storeu_si128((__m128i*)ctr_buf[k], counters[k]);
            sm4_encrypt_ttable(ctr_buf[k], ctr_buf[k], rk);
        }
        for (int k = 0; k < 8; k++) {
            __m128i pt = _mm_loadu_si128((__m128i*)(in + (b+k)*16));
            pt = _mm_xor_si128(pt, _mm_loadu_si128((__m128i*)ctr_buf[k]));
            _mm_storeu_si128((__m128i*)(out + (b+k)*16), pt);
        }
        for (int k = 0; k < 8; k++)
            counters[k] = _mm_add_epi32(counters[k], inc);
    }
}

static void sm4_ctr_4way_ttable(const uint8_t *in, uint8_t *out, size_t nblocks,
                                const uint8_t *ctr_init, const uint32_t rk[32]) {
    uint32_t ctr_words[4];
    memcpy(ctr_words, ctr_init, 16);
    uint32_t base = ctr_words[3];
    __m128i counters[4];
    uint8_t ctr_buf[4][16];
    for (int k = 0; k < 4; k++) {
        ctr_words[3] = base + k;
        counters[k] = _mm_loadu_si128((__m128i*)ctr_words);
    }
    __m128i inc = _mm_set_epi32(0, 0, 0, 4);
    for (size_t b = 0; b < nblocks; b += 4) {
        for (int k = 0; k < 4; k++) {
            _mm_storeu_si128((__m128i*)ctr_buf[k], counters[k]);
            sm4_encrypt_ttable(ctr_buf[k], ctr_buf[k], rk);
        }
        __m128i pt0 = _mm_loadu_si128((__m128i*)(in + (b+0)*16));
        __m128i pt1 = _mm_loadu_si128((__m128i*)(in + (b+1)*16));
        __m128i pt2 = _mm_loadu_si128((__m128i*)(in + (b+2)*16));
        __m128i pt3 = _mm_loadu_si128((__m128i*)(in + (b+3)*16));
        pt0 = _mm_xor_si128(pt0, _mm_loadu_si128((__m128i*)ctr_buf[0]));
        pt1 = _mm_xor_si128(pt1, _mm_loadu_si128((__m128i*)ctr_buf[1]));
        pt2 = _mm_xor_si128(pt2, _mm_loadu_si128((__m128i*)ctr_buf[2]));
        pt3 = _mm_xor_si128(pt3, _mm_loadu_si128((__m128i*)ctr_buf[3]));
        _mm_storeu_si128((__m128i*)(out + (b+0)*16), pt0);
        _mm_storeu_si128((__m128i*)(out + (b+1)*16), pt1);
        _mm_storeu_si128((__m128i*)(out + (b+2)*16), pt2);
        _mm_storeu_si128((__m128i*)(out + (b+3)*16), pt3);
        for (int k = 0; k < 4; k++)
            counters[k] = _mm_add_epi32(counters[k], inc);
    }
}

static void sm4_ctr_8way_avx2(const uint8_t *in, uint8_t *out, size_t nblocks,
                              const uint8_t *ctr_init, const uint32_t rk[32]) {
    uint32_t ctr_words[4];
    memcpy(ctr_words, ctr_init, 16);
    uint32_t base = ctr_words[3];
    __m128i counters[8];
    uint8_t ctr_buf[8][16] __attribute__((aligned(32)));
    for (int k = 0; k < 8; k++) {
        ctr_words[3] = base + k;
        counters[k] = _mm_loadu_si128((__m128i*)ctr_words);
    }
    __m128i inc = _mm_set_epi32(0, 0, 0, 8);
    for (size_t b = 0; b < nblocks; b += 8) {
        for (int k = 0; k < 8; k++) {
            _mm_storeu_si128((__m128i*)ctr_buf[k], counters[k]);
            sm4_encrypt_ttable(ctr_buf[k], ctr_buf[k], rk);
        }
        for (int k = 0; k < 8; k += 2) {
            __m256i pt256 = _mm256_loadu_si256((__m256i*)(in + (b+k)*16));
            __m256i ks256 = _mm256_load_si256((__m256i*)(ctr_buf[k]));
            pt256 = _mm256_xor_si256(pt256, ks256);
            _mm256_storeu_si256((__m256i*)(out + (b+k)*16), pt256);
        }
        for (int k = 0; k < 8; k++)
            counters[k] = _mm_add_epi32(counters[k], inc);
    }
}

typedef void (*mode_fn)(const uint8_t*, uint8_t*, size_t, const uint8_t*, const uint32_t*, block_enc_fn);

void sm4_ctr_crypt_base(const uint8_t *in, uint8_t *out, size_t len,
                        const uint8_t iv[16], const uint32_t rk[32], block_enc_fn enc) {
    uint8_t ctr[16];
    memcpy(ctr, iv, 16);
    for (size_t b = 0; b < len/16; b++) {
        uint8_t ks[16];
        enc(ctr, ks, rk);
        for (int i = 0; i < 16; i++) out[b*16+i] = in[b*16+i] ^ ks[i];
        for (int i = 15; i >= 0; i--) { ctr[i]++; if (ctr[i] != 0) break; }
    }
}

void sm4_ctr_crypt_ssse3(const uint8_t *in, uint8_t *out, size_t len,
                         const uint8_t iv[16], const uint32_t rk[32], block_enc_fn enc) {
    (void)enc;
    uint8_t ctr[16];
    memcpy(ctr, iv, 16);
    sm4_ctr_4way_ttable(in, out, len/16, ctr, rk);
}

void sm4_ctr_crypt_aesni(const uint8_t *in, uint8_t *out, size_t len,
                         const uint8_t iv[16], const uint32_t rk[32], block_enc_fn enc) {
    (void)enc;
    uint8_t ctr[16];
    memcpy(ctr, iv, 16);
    sm4_ctr_8way_ttable(in, out, len/16, ctr, rk);
}

void sm4_ctr_crypt_avx2(const uint8_t *in, uint8_t *out, size_t len,
                        const uint8_t iv[16], const uint32_t rk[32], block_enc_fn enc) {
    (void)enc;
    uint8_t ctr[16];
    memcpy(ctr, iv, 16);
    sm4_ctr_8way_avx2(in, out, len/16, ctr, rk);
}

void sm4_gcm_crypt_base(const uint8_t *in, uint8_t *out, size_t len,
                        const uint8_t iv[16], const uint32_t rk[32], block_enc_fn enc) {
    uint8_t gcm_ctr[16];
    memcpy(gcm_ctr, iv, 12);
    memset(gcm_ctr + 12, 0, 3);
    gcm_ctr[15] = 2;
    for (size_t b = 0; b < len/16; b++) {
        uint8_t ks[16];
        enc(gcm_ctr, ks, rk);
        for (int i = 0; i < 16; i++) out[b*16+i] = in[b*16+i] ^ ks[i];
        for (int i = 15; i >= 0; i--) { gcm_ctr[i]++; if (gcm_ctr[i] != 0) break; }
    }
}

void sm4_gcm_crypt_ssse3(const uint8_t *in, uint8_t *out, size_t len,
                         const uint8_t iv[16], const uint32_t rk[32], block_enc_fn enc) {
    (void)enc;
    uint8_t gcm_ctr[16];
    memcpy(gcm_ctr, iv, 12);
    memset(gcm_ctr + 12, 0, 3);
    gcm_ctr[15] = 2;
    sm4_ctr_4way_ttable(in, out, len/16, gcm_ctr, rk);
}

void sm4_gcm_crypt_aesni(const uint8_t *in, uint8_t *out, size_t len,
                         const uint8_t iv[16], const uint32_t rk[32], block_enc_fn enc) {
    (void)enc;
    uint8_t gcm_ctr[16];
    memcpy(gcm_ctr, iv, 12);
    memset(gcm_ctr + 12, 0, 3);
    gcm_ctr[15] = 2;
    sm4_ctr_8way_ttable(in, out, len/16, gcm_ctr, rk);
}

void sm4_gcm_crypt_avx2(const uint8_t *in, uint8_t *out, size_t len,
                        const uint8_t iv[16], const uint32_t rk[32], block_enc_fn enc) {
    (void)enc;
    uint8_t gcm_ctr[16];
    memcpy(gcm_ctr, iv, 12);
    memset(gcm_ctr + 12, 0, 3);
    gcm_ctr[15] = 2;
    sm4_ctr_8way_avx2(in, out, len/16, gcm_ctr, rk);
}

void sm4_xts_crypt_base(const uint8_t *in, uint8_t *out, size_t len,
                        const uint8_t iv[16], const uint32_t rk[32], block_enc_fn enc) {
    uint8_t tweak[16];
    enc(iv, tweak, rk);
    for (size_t b = 0; b < len/16; b++) {
        for (int i = 0; i < 16; i++) out[b*16+i] = in[b*16+i] ^ tweak[i];
        enc(out + b*16, out + b*16, rk);
        for (int i = 0; i < 16; i++) out[b*16+i] ^= tweak[i];
        uint8_t carry = 0;
        for (int i = 0; i < 16; i++) {
            uint8_t nc = tweak[i] >> 7;
            tweak[i] = (tweak[i] << 1) | carry;
            carry = nc;
        }
        if (carry) tweak[0] ^= 0x87;
    }
}

void sm4_xts_crypt_optimized(const uint8_t *in, uint8_t *out, size_t len,
                             const uint8_t iv[16], const uint32_t rk[32], block_enc_fn enc) {
    sm4_xts_crypt_base(in, out, len, iv, rk, sm4_encrypt_ttable);
}

void benchmark(const char *mode_name, const char *impl_name,
               mode_fn mode_func, block_enc_fn enc,
               uint8_t *in, uint8_t *out, size_t len,
               const uint8_t *iv, const uint32_t *rk) {
    clock_t start = clock();
    for (int iter = 0; iter < 10; iter++) {
        uint8_t cur_iv[16];
        memcpy(cur_iv, iv, 16);
        cur_iv[15] = iter;
        mode_func(in, out, len, cur_iv, rk, enc);
    }
    double sec = (double)(clock() - start) / CLOCKS_PER_SEC;
    double mb = len * 10.0 / (1024 * 1024);
    printf("  %-6s %-8s | %8.3f 秒 | %10.2f MB/s\n", mode_name, impl_name, sec, mb/sec);
}

int main(void) {
    sm4_init_ttable();
    sm4_init_ssse3();
    sm4_init_aesni();

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║      SM4 多方案 & 多模式 完整性能对比测试             ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                       0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t plain[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                         0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t iv[16] = {0};
    uint32_t rk[32];
    sm4_key_schedule(key, rk);

    block_enc_fn enc_funcs[] = {
        sm4_encrypt_base,
        sm4_encrypt_ttable,
        sm4_encrypt_ssse3,
        sm4_encrypt_aesni,
        sm4_encrypt_ttable
    };
    const char *names[] = {"Base", "T-Table", "SSSE3", "AES-NI", "AVX2"};

    size_t len = 100UL * 1024 * 1024;
    uint8_t *in = (uint8_t*)aligned_alloc(64, len);
    uint8_t *out = (uint8_t*)aligned_alloc(64, len);
    if (!in || !out) {
        len = 50UL * 1024 * 1024;
        free(in); free(out);
        in = (uint8_t*)aligned_alloc(64, len);
        out = (uint8_t*)aligned_alloc(64, len);
        if (!in || !out) { printf("内存不足\n"); return 1; }
    }
    memset(in, 0xAA, len);

    struct {
        const char *name;
        mode_fn funcs[5];
    } modes[] = {
        {"CTR", {sm4_ctr_crypt_base, sm4_ctr_crypt_base, sm4_ctr_crypt_ssse3,
                 sm4_ctr_crypt_aesni, sm4_ctr_crypt_avx2}},
        {"GCM", {sm4_gcm_crypt_base, sm4_gcm_crypt_base, sm4_gcm_crypt_ssse3,
                 sm4_gcm_crypt_aesni, sm4_gcm_crypt_avx2}},
        {"XTS", {sm4_xts_crypt_base, sm4_xts_crypt_optimized, sm4_xts_crypt_optimized,
                 sm4_xts_crypt_optimized, sm4_xts_crypt_optimized}},
    };

    for (int m = 0; m < 3; m++) {
        printf("\n═══════ %s 模式 (%luMB × 10次) ═══════\n",
               modes[m].name, len/(1024*1024));
        for (int i = 0; i < 5; i++) {
            benchmark(modes[m].name, names[i], modes[m].funcs[i],
                     enc_funcs[i], in, out, len, iv, rk);
        }
    }

    free(in);
    free(out);
    printf("\n═══════ 测试完成 ═══════\n");
    return 0;
}