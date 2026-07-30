#ifndef AESLAB_H
#define AESLAB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AES_BLOCK_SIZE 16
#define AES_MAX_ROUNDS 14

typedef struct {
    uint8_t round_keys[(AES_MAX_ROUNDS + 1) * AES_BLOCK_SIZE];
    int rounds;
    int key_bits;
} aes_key_t;

typedef enum {
    AES_BACKEND_BASELINE = 0,
    AES_BACKEND_TTABLE,
    AES_BACKEND_SHUFFLE,
    AES_BACKEND_AESNI,
    AES_BACKEND_VAES,
    AES_BACKEND_COUNT
} aes_backend_id_t;

typedef struct aes_backend {
    aes_backend_id_t id;
    const char *name;
    int (*available)(void);
    void (*encrypt_block)(const aes_key_t *, const uint8_t in[16], uint8_t out[16]);
    void (*decrypt_block)(const aes_key_t *, const uint8_t in[16], uint8_t out[16]);
    void (*encrypt_blocks)(const aes_key_t *, const uint8_t *in, uint8_t *out, size_t blocks);
    void (*decrypt_blocks)(const aes_key_t *, const uint8_t *in, uint8_t *out, size_t blocks);
} aes_backend_t;

int aes_set_encrypt_key(aes_key_t *ctx, const uint8_t *key, int key_bits);
const aes_backend_t *aes_get_backend(aes_backend_id_t id);
const aes_backend_t *aes_get_backend_by_name(const char *name);
const aes_backend_t *aes_get_fastest_backend(void);
void aes_list_backends(void);

void aes_baseline_encrypt_block(const aes_key_t *, const uint8_t[16], uint8_t[16]);
void aes_baseline_decrypt_block(const aes_key_t *, const uint8_t[16], uint8_t[16]);
void aes_ttable_encrypt_block(const aes_key_t *, const uint8_t[16], uint8_t[16]);
void aes_ttable_decrypt_block(const aes_key_t *, const uint8_t[16], uint8_t[16]);
void aes_shuffle_encrypt_block(const aes_key_t *, const uint8_t[16], uint8_t[16]);
void aes_shuffle_decrypt_block(const aes_key_t *, const uint8_t[16], uint8_t[16]);
void aes_aesni_encrypt_block(const aes_key_t *, const uint8_t[16], uint8_t[16]);
void aes_aesni_decrypt_block(const aes_key_t *, const uint8_t[16], uint8_t[16]);
void aes_vaes_encrypt_block(const aes_key_t *, const uint8_t[16], uint8_t[16]);
void aes_vaes_decrypt_block(const aes_key_t *, const uint8_t[16], uint8_t[16]);

/* CTR: increments the complete 128-bit counter in big-endian order. */
void aes_ctr_crypt(const aes_backend_t *be, const aes_key_t *key,
                   uint8_t counter[16], const uint8_t *in, uint8_t *out, size_t len);

/* GCM: supports the standard 96-bit IV fast path and arbitrary AAD/plaintext lengths. */
int aes_gcm_encrypt(const aes_backend_t *be, const aes_key_t *key,
                    const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
                    const uint8_t *plaintext, uint8_t *ciphertext, size_t len,
                    uint8_t tag[16]);
int aes_gcm_decrypt(const aes_backend_t *be, const aes_key_t *key,
                    const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
                    const uint8_t *ciphertext, uint8_t *plaintext, size_t len,
                    const uint8_t tag[16]);

/* XTS: key1 encrypts data, key2 encrypts the tweak. Supports ciphertext stealing. */
int aes_xts_encrypt(const aes_backend_t *be, const aes_key_t *key1, const aes_key_t *key2,
                    const uint8_t tweak[16], const uint8_t *in, uint8_t *out, size_t len);
int aes_xts_decrypt(const aes_backend_t *be, const aes_key_t *key1, const aes_key_t *key2,
                    const uint8_t tweak[16], const uint8_t *in, uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif
#endif
