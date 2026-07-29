#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <tmmintrin.h>
#include <wmmintrin.h>
#include <immintrin.h>

static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0);
}

static uint32_t sub_word(uint32_t w) {
    uint32_t r = 0;
    for (int i = 0; i < 4; i++)
        r |= (uint32_t)AES_SBOX[(w >> (8 * i)) & 0xFF] << (8 * i);
    return r;
}

static uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

void aes128_key_schedule(const uint8_t key[16], uint8_t rk[176]) {
    static const uint8_t Rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
    memcpy(rk, key, 16);
    for (int i = 4; i < 44; i++) {
        uint32_t t = *(uint32_t*)(rk + (i-1)*4);
        if (i % 4 == 0)
            t = sub_word(rot_word(t)) ^ ((uint32_t)Rcon[i/4] << 24);
        *(uint32_t*)(rk + i*4) = *(uint32_t*)(rk + (i-4)*4) ^ t;
    }
}

typedef void (*block_enc_fn)(const uint8_t*, uint8_t*, const uint8_t*);

void aes_encrypt_base(const uint8_t in[16], uint8_t out[16], const uint8_t rk[176]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
    for (int r = 1; r < 10; r++) {
        for (int i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
        uint8_t t;
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
        t = s[2]; s[2] = s[10]; s[10] = t;
        t = s[6]; s[6] = s[14]; s[14] = t;
        t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
        for (int c = 0; c < 4; c++) {
            int i = c * 4;
            uint8_t a = s[i], b = s[i+1], c0 = s[i+2], d = s[i+3];
            s[i]   = xtime(a) ^ (xtime(b) ^ b) ^ c0 ^ d;
            s[i+1] = a ^ xtime(b) ^ (xtime(c0) ^ c0) ^ d;
            s[i+2] = a ^ b ^ xtime(c0) ^ (xtime(d) ^ d);
            s[i+3] = (xtime(a) ^ a) ^ b ^ c0 ^ xtime(d);
        }
        for (int i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
    }
    for (int i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
    uint8_t t;
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t;
    for (int i = 0; i < 16; i++) s[i] ^= rk[160 + i];
    memcpy(out, s, 16);
}

static uint32_t T0[256], T1[256], T2[256], T3[256];

void init_ttable(void) {
    for (int i = 0; i < 256; i++) {
        uint8_t s = AES_SBOX[i];
        uint32_t a = s, b = xtime(s), c = b ^ s;
        T0[i] = ((uint32_t)b << 24) | ((uint32_t)a << 16) | ((uint32_t)a << 8) | c;
        T1[i] = ((uint32_t)c << 24) | ((uint32_t)b << 16) | ((uint32_t)a << 8) | a;
        T2[i] = ((uint32_t)a << 24) | ((uint32_t)c << 16) | ((uint32_t)b << 8) | a;
        T3[i] = ((uint32_t)a << 24) | ((uint32_t)a << 16) | ((uint32_t)c << 8) | b;
    }
}

void aes_encrypt_ttable(const uint8_t in[16], uint8_t out[16], const uint8_t rk[176]) {
    uint32_t s[4];
    for (int i = 0; i < 4; i++)
        s[i] = ((uint32_t)in[4*i] << 24) | ((uint32_t)in[4*i+1] << 16) |
               ((uint32_t)in[4*i+2] << 8) | in[4*i+3];
    for (int i = 0; i < 4; i++) s[i] ^= ((uint32_t*)rk)[i];
    for (int r = 1; r < 10; r++) {
        uint32_t t0 = T0[s[0] >> 24] ^ T1[(s[1] >> 16) & 0xFF] ^ T2[(s[2] >> 8) & 0xFF] ^ T3[s[3] & 0xFF];
        uint32_t t1 = T0[s[1] >> 24] ^ T1[(s[2] >> 16) & 0xFF] ^ T2[(s[3] >> 8) & 0xFF] ^ T3[s[0] & 0xFF];
        uint32_t t2 = T0[s[2] >> 24] ^ T1[(s[3] >> 16) & 0xFF] ^ T2[(s[0] >> 8) & 0xFF] ^ T3[s[1] & 0xFF];
        uint32_t t3 = T0[s[3] >> 24] ^ T1[(s[0] >> 16) & 0xFF] ^ T2[(s[1] >> 8) & 0xFF] ^ T3[s[2] & 0xFF];
        s[0] = t0 ^ ((uint32_t*)rk)[r*4];
        s[1] = t1 ^ ((uint32_t*)rk)[r*4+1];
        s[2] = t2 ^ ((uint32_t*)rk)[r*4+2];
        s[3] = t3 ^ ((uint32_t*)rk)[r*4+3];
    }
    uint32_t out0 = ((uint32_t)AES_SBOX[s[0] >> 24] << 24) ^
                    ((uint32_t)AES_SBOX[(s[1] >> 16) & 0xFF] << 16) ^
                    ((uint32_t)AES_SBOX[(s[2] >> 8) & 0xFF] << 8) ^
                    AES_SBOX[s[3] & 0xFF];
    uint32_t out1 = ((uint32_t)AES_SBOX[s[1] >> 24] << 24) ^
                    ((uint32_t)AES_SBOX[(s[2] >> 16) & 0xFF] << 16) ^
                    ((uint32_t)AES_SBOX[(s[3] >> 8) & 0xFF] << 8) ^
                    AES_SBOX[s[0] & 0xFF];
    uint32_t out2 = ((uint32_t)AES_SBOX[s[2] >> 24] << 24) ^
                    ((uint32_t)AES_SBOX[(s[3] >> 16) & 0xFF] << 16) ^
                    ((uint32_t)AES_SBOX[(s[0] >> 8) & 0xFF] << 8) ^
                    AES_SBOX[s[1] & 0xFF];
    uint32_t out3 = ((uint32_t)AES_SBOX[s[3] >> 24] << 24) ^
                    ((uint32_t)AES_SBOX[(s[0] >> 16) & 0xFF] << 16) ^
                    ((uint32_t)AES_SBOX[(s[1] >> 8) & 0xFF] << 8) ^
                    AES_SBOX[s[2] & 0xFF];
    out0 ^= ((uint32_t*)rk)[40];
    out1 ^= ((uint32_t*)rk)[41];
    out2 ^= ((uint32_t*)rk)[42];
    out3 ^= ((uint32_t*)rk)[43];
    ((uint32_t*)out)[0] = out0;
    ((uint32_t*)out)[1] = out1;
    ((uint32_t*)out)[2] = out2;
    ((uint32_t*)out)[3] = out3;
}

void aes_encrypt_shuffle(const uint8_t in[16], uint8_t out[16], const uint8_t rk[176]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
    __m128i mask = _mm_set_epi8(3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14);
    for (int r = 1; r < 10; r++) {
        for (int i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
        __m128i state = _mm_loadu_si128((__m128i*)s);
        state = _mm_shuffle_epi8(state, mask);
        _mm_storeu_si128((__m128i*)s, state);
        for (int c = 0; c < 4; c++) {
            int i = c * 4;
            uint8_t a = s[i], b = s[i+1], c0 = s[i+2], d = s[i+3];
            s[i]   = xtime(a) ^ (xtime(b) ^ b) ^ c0 ^ d;
            s[i+1] = a ^ xtime(b) ^ (xtime(c0) ^ c0) ^ d;
            s[i+2] = a ^ b ^ xtime(c0) ^ (xtime(d) ^ d);
            s[i+3] = (xtime(a) ^ a) ^ b ^ c0 ^ xtime(d);
        }
        for (int i = 0; i < 16; i++) s[i] ^= rk[r * 16 + i];
    }
    for (int i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
    __m128i state = _mm_loadu_si128((__m128i*)s);
    state = _mm_shuffle_epi8(state, mask);
    _mm_storeu_si128((__m128i*)s, state);
    for (int i = 0; i < 16; i++) s[i] ^= rk[160 + i];
    memcpy(out, s, 16);
}

void aes_encrypt_aesni(const uint8_t in[16], uint8_t out[16], const uint8_t rk[176]) {
    __m128i state = _mm_loadu_si128((const __m128i*)in);
    const __m128i *rk128 = (const __m128i*)rk;
    state = _mm_xor_si128(state, rk128[0]);
    for (int i = 1; i < 10; i++)
        state = _mm_aesenc_si128(state, rk128[i]);
    state = _mm_aesenclast_si128(state, rk128[10]);
    _mm_storeu_si128((__m128i*)out, state);
}

static void aes_ctr_4way(const uint8_t *in, uint8_t *out, size_t nblocks,
                         const uint8_t *ctr_init, const uint8_t rk[176],
                         block_enc_fn enc) {
    uint32_t ctr[4];
    memcpy(ctr, ctr_init, 16);
    uint32_t base = ctr[3];
    __m128i counters[4];
    uint8_t ctr_buf[4][16] __attribute__((aligned(16)));
    for (int k = 0; k < 4; k++) {
        ctr[3] = base + k;
        counters[k] = _mm_loadu_si128((__m128i*)ctr);
    }
    __m128i inc = _mm_set_epi32(0, 0, 0, 4);
    for (size_t b = 0; b < nblocks; b += 4) {
        for (int k = 0; k < 4; k++) {
            _mm_store_si128((__m128i*)ctr_buf[k], counters[k]);
            enc(ctr_buf[k], ctr_buf[k], rk);
        }
        __m128i p0 = _mm_loadu_si128((__m128i*)(in + (b+0)*16));
        __m128i p1 = _mm_loadu_si128((__m128i*)(in + (b+1)*16));
        __m128i p2 = _mm_loadu_si128((__m128i*)(in + (b+2)*16));
        __m128i p3 = _mm_loadu_si128((__m128i*)(in + (b+3)*16));
        p0 = _mm_xor_si128(p0, _mm_load_si128((__m128i*)ctr_buf[0]));
        p1 = _mm_xor_si128(p1, _mm_load_si128((__m128i*)ctr_buf[1]));
        p2 = _mm_xor_si128(p2, _mm_load_si128((__m128i*)ctr_buf[2]));
        p3 = _mm_xor_si128(p3, _mm_load_si128((__m128i*)ctr_buf[3]));
        _mm_storeu_si128((__m128i*)(out + (b+0)*16), p0);
        _mm_storeu_si128((__m128i*)(out + (b+1)*16), p1);
        _mm_storeu_si128((__m128i*)(out + (b+2)*16), p2);
        _mm_storeu_si128((__m128i*)(out + (b+3)*16), p3);
        for (int k = 0; k < 4; k++)
            counters[k] = _mm_add_epi32(counters[k], inc);
    }
}

static void aes_ctr_8way(const uint8_t *in, uint8_t *out, size_t nblocks,
                         const uint8_t *ctr_init, const uint8_t rk[176],
                         block_enc_fn enc) {
    uint32_t ctr[4];
    memcpy(ctr, ctr_init, 16);
    uint32_t base = ctr[3];
    __m128i counters[8];
    uint8_t ctr_buf[8][16] __attribute__((aligned(16)));
    for (int k = 0; k < 8; k++) {
        ctr[3] = base + k;
        counters[k] = _mm_loadu_si128((__m128i*)ctr);
    }
    __m128i inc = _mm_set_epi32(0, 0, 0, 8);
    for (size_t b = 0; b < nblocks; b += 8) {
        for (int k = 0; k < 8; k++) {
            _mm_store_si128((__m128i*)ctr_buf[k], counters[k]);
            enc(ctr_buf[k], ctr_buf[k], rk);
        }
        for (int k = 0; k < 8; k++) {
            __m128i pt = _mm_loadu_si128((__m128i*)(in + (b+k)*16));
            pt = _mm_xor_si128(pt, _mm_load_si128((__m128i*)ctr_buf[k]));
            _mm_storeu_si128((__m128i*)(out + (b+k)*16), pt);
        }
        for (int k = 0; k < 8; k++)
            counters[k] = _mm_add_epi32(counters[k], inc);
    }
}

static void aes_ctr_8way_avx2(const uint8_t *in, uint8_t *out, size_t nblocks,
                              const uint8_t *ctr_init, const uint8_t rk[176],
                              block_enc_fn enc) {
    uint32_t ctr[4];
    memcpy(ctr, ctr_init, 16);
    uint32_t base = ctr[3];
    __m128i counters[8];
    uint8_t ctr_buf[8][16] __attribute__((aligned(32)));
    for (int k = 0; k < 8; k++) {
        ctr[3] = base + k;
        counters[k] = _mm_loadu_si128((__m128i*)ctr);
    }
    __m128i inc = _mm_set_epi32(0, 0, 0, 8);
    for (size_t b = 0; b < nblocks; b += 8) {
        for (int k = 0; k < 8; k++) {
            _mm_store_si128((__m128i*)ctr_buf[k], counters[k]);
            enc(ctr_buf[k], ctr_buf[k], rk);
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

typedef void (*mode_fn)(const uint8_t*, uint8_t*, size_t,
                        const uint8_t*, const uint8_t*, block_enc_fn);

void aes_ctr_base(const uint8_t *in, uint8_t *out, size_t len,
                  const uint8_t iv[16], const uint8_t rk[176], block_enc_fn enc) {
    uint8_t ctr[16];
    memcpy(ctr, iv, 16);
    for (size_t b = 0; b < len / 16; b++) {
        uint8_t ks[16];
        enc(ctr, ks, rk);
        for (int i = 0; i < 16; i++) out[b*16+i] = in[b*16+i] ^ ks[i];
        for (int i = 15; i >= 0; i--) { ctr[i]++; if (ctr[i] != 0) break; }
    }
}

void aes_ctr_4way_wrapper(const uint8_t *in, uint8_t *out, size_t len,
                          const uint8_t iv[16], const uint8_t rk[176],
                          block_enc_fn enc) {
    uint8_t ctr[16];
    memcpy(ctr, iv, 16);
    aes_ctr_4way(in, out, len / 16, ctr, rk, enc);
}

void aes_ctr_8way_wrapper(const uint8_t *in, uint8_t *out, size_t len,
                          const uint8_t iv[16], const uint8_t rk[176],
                          block_enc_fn enc) {
    uint8_t ctr[16];
    memcpy(ctr, iv, 16);
    aes_ctr_8way(in, out, len / 16, ctr, rk, enc);
}

void aes_ctr_8way_avx2_wrapper(const uint8_t *in, uint8_t *out, size_t len,
                               const uint8_t iv[16], const uint8_t rk[176],
                               block_enc_fn enc) {
    uint8_t ctr[16];
    memcpy(ctr, iv, 16);
    aes_ctr_8way_avx2(in, out, len / 16, ctr, rk, enc);
}

void aes_gcm_base(const uint8_t *in, uint8_t *out, size_t len,
                  const uint8_t iv[16], const uint8_t rk[176], block_enc_fn enc) {
    uint8_t gcm_ctr[16];
    memcpy(gcm_ctr, iv, 12);
    memset(gcm_ctr + 12, 0, 3);
    gcm_ctr[15] = 2;
    for (size_t b = 0; b < len / 16; b++) {
        uint8_t ks[16];
        enc(gcm_ctr, ks, rk);
        for (int i = 0; i < 16; i++) out[b*16+i] = in[b*16+i] ^ ks[i];
        for (int i = 15; i >= 0; i--) { gcm_ctr[i]++; if (gcm_ctr[i] != 0) break; }
    }
}

void aes_gcm_4way(const uint8_t *in, uint8_t *out, size_t len,
                  const uint8_t iv[16], const uint8_t rk[176], block_enc_fn enc) {
    uint8_t gcm_ctr[16];
    memcpy(gcm_ctr, iv, 12);
    memset(gcm_ctr + 12, 0, 3);
    gcm_ctr[15] = 2;
    aes_ctr_4way(in, out, len / 16, gcm_ctr, rk, enc);
}

void aes_gcm_8way(const uint8_t *in, uint8_t *out, size_t len,
                  const uint8_t iv[16], const uint8_t rk[176], block_enc_fn enc) {
    uint8_t gcm_ctr[16];
    memcpy(gcm_ctr, iv, 12);
    memset(gcm_ctr + 12, 0, 3);
    gcm_ctr[15] = 2;
    aes_ctr_8way(in, out, len / 16, gcm_ctr, rk, enc);
}

void aes_gcm_8way_avx2(const uint8_t *in, uint8_t *out, size_t len,
                       const uint8_t iv[16], const uint8_t rk[176], block_enc_fn enc) {
    uint8_t gcm_ctr[16];
    memcpy(gcm_ctr, iv, 12);
    memset(gcm_ctr + 12, 0, 3);
    gcm_ctr[15] = 2;
    aes_ctr_8way_avx2(in, out, len / 16, gcm_ctr, rk, enc);
}

void aes_xts_base(const uint8_t *in, uint8_t *out, size_t len,
                  const uint8_t iv[16], const uint8_t rk[176], block_enc_fn enc) {
    uint8_t tweak[16];
    enc(iv, tweak, rk);
    for (size_t b = 0; b < len / 16; b++) {
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

void benchmark(const char *mode_name, const char *impl_name,
               mode_fn mode_func, block_enc_fn enc,
               uint8_t *in, uint8_t *out, size_t len,
               const uint8_t *iv, const uint8_t *rk) {
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
    init_ttable();

    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║      AES-128 多方案 & 多模式 完整性能对比测试         ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                       0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    uint8_t pt[16] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
                      0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    uint8_t iv[16] = {0};
    uint8_t rk[176];
    aes128_key_schedule(key, rk);

    block_enc_fn enc_funcs[] = {
        aes_encrypt_base,
        aes_encrypt_ttable,
        aes_encrypt_shuffle,
        aes_encrypt_aesni,
        aes_encrypt_aesni
    };
    const char *names[] = {"Base", "T-Table", "Shuffle", "AES-NI", "AVX2"};

    size_t len = 100UL * 1024 * 1024;
    uint8_t *in = (uint8_t*)aligned_alloc(64, len);
    uint8_t *out = (uint8_t*)aligned_alloc(64, len);
    if (!in || !out) {
        len = 50UL * 1024 * 1024;
        free(in); free(out);
        in = (uint8_t*)aligned_alloc(64, len);
        out = (uint8_t*)aligned_alloc(64, len);
    }
    memset(in, 0xAA, len);

    mode_fn ctr_funcs[] = {
        aes_ctr_base,
        aes_ctr_base,
        aes_ctr_4way_wrapper,
        aes_ctr_8way_wrapper,
        aes_ctr_8way_avx2_wrapper
    };
    mode_fn gcm_funcs[] = {
        aes_gcm_base,
        aes_gcm_base,
        aes_gcm_4way,
        aes_gcm_8way,
        aes_gcm_8way_avx2
    };
    mode_fn xts_funcs[] = {
        aes_xts_base,
        aes_xts_base,
        aes_xts_base,
        aes_xts_base,
        aes_xts_base
    };

    printf("\n═══════ CTR 模式 (%luMB × 10次) ═══════\n", len / (1024*1024));
    for (int i = 0; i < 5; i++)
        benchmark("CTR", names[i], ctr_funcs[i], enc_funcs[i], in, out, len, iv, rk);

    printf("\n═══════ GCM 模式 (%luMB × 10次) ═══════\n", len / (1024*1024));
    for (int i = 0; i < 5; i++)
        benchmark("GCM", names[i], gcm_funcs[i], enc_funcs[i], in, out, len, iv, rk);

    printf("\n═══════ XTS 模式 (%luMB × 10次) ═══════\n", len / (1024*1024));
    for (int i = 0; i < 5; i++)
        benchmark("XTS", names[i], xts_funcs[i], enc_funcs[i], in, out, len, iv, rk);

    free(in);
    free(out);
    printf("\n═══════ 测试完成 ═══════\n");
    return 0;
}