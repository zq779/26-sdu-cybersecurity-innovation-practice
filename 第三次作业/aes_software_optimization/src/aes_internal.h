#ifndef AES_INTERNAL_H
#define AES_INTERNAL_H
#include "aeslab.h"
#include <string.h>

extern const uint8_t aes_sbox[256];
extern const uint8_t aes_inv_sbox[256];

static inline uint8_t aes_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) * 0x1b));
}

static inline uint8_t aes_gfmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        p ^= (uint8_t)(-(int)(b & 1) & a);
        a = aes_xtime(a);
        b >>= 1;
    }
    return p;
}

static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline void store32_le(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)x; p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16); p[3] = (uint8_t)(x >> 24);
}

void aes_generic_encrypt_blocks(void (*fn)(const aes_key_t *, const uint8_t[16], uint8_t[16]),
                                const aes_key_t *, const uint8_t *, uint8_t *, size_t);
void aes_generic_decrypt_blocks(void (*fn)(const aes_key_t *, const uint8_t[16], uint8_t[16]),
                                const aes_key_t *, const uint8_t *, uint8_t *, size_t);

int aes_shuffle_available(void);
int aes_aesni_available(void);
int aes_vaes_available(void);
void aes_aesni_encrypt_blocks(const aes_key_t *, const uint8_t *, uint8_t *, size_t);
void aes_aesni_decrypt_blocks(const aes_key_t *, const uint8_t *, uint8_t *, size_t);
void aes_vaes_encrypt_blocks(const aes_key_t *, const uint8_t *, uint8_t *, size_t);
void aes_vaes_decrypt_blocks(const aes_key_t *, const uint8_t *, uint8_t *, size_t);

#endif
