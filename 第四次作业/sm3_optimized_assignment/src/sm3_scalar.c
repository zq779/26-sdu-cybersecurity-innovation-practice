#include "sm3.h"
#include "sm3_internal.h"

static void sm3_compress_scalar(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[68];
    uint32_t wp[64];

    for (unsigned j = 0; j < 16u; ++j) {
        w[j] = sm3_load_be32(block + 4u * j);
    }
    for (unsigned j = 16u; j < 68u; ++j) {
        const uint32_t x = w[j - 16u] ^ w[j - 9u] ^ sm3_rotl32(w[j - 3u], 15u);
        w[j] = sm3_p1(x) ^ sm3_rotl32(w[j - 13u], 7u) ^ w[j - 6u];
    }
    for (unsigned j = 0; j < 64u; ++j) {
        wp[j] = w[j] ^ w[j + 4u];
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (unsigned j = 0; j < 64u; ++j) {
        const uint32_t a12 = sm3_rotl32(a, 12u);
        const uint32_t ss1 = sm3_rotl32(a12 + e + sm3_t_rot(j), 7u);
        const uint32_t ss2 = ss1 ^ a12;
        const uint32_t ff = (j < 16u)
            ? (a ^ b ^ c)
            : ((a & b) | (a & c) | (b & c));
        const uint32_t gg = (j < 16u)
            ? (e ^ f ^ g)
            : ((e & f) | ((~e) & g));
        const uint32_t tt1 = ff + d + ss2 + wp[j];
        const uint32_t tt2 = gg + h + ss1 + w[j];

        d = c;
        c = sm3_rotl32(b, 9u);
        b = a;
        a = tt1;
        h = g;
        g = sm3_rotl32(f, 19u);
        f = e;
        e = sm3_p0(tt2);
    }

    state[0] ^= a;
    state[1] ^= b;
    state[2] ^= c;
    state[3] ^= d;
    state[4] ^= e;
    state[5] ^= f;
    state[6] ^= g;
    state[7] ^= h;
}

void sm3_digest(const uint8_t *msg, size_t len, uint8_t out[SM3_DIGEST_SIZE])
{
    uint32_t state[8] = {
        SM3_IV0, SM3_IV1, SM3_IV2, SM3_IV3,
        SM3_IV4, SM3_IV5, SM3_IV6, SM3_IV7
    };

    const size_t full_blocks = len / 64u;
    for (size_t i = 0; i < full_blocks; ++i) {
        sm3_compress_scalar(state, msg + i * 64u);
    }

    uint8_t tail[128];
    const size_t tail_blocks = sm3_build_tail(msg, len, tail);
    for (size_t i = 0; i < tail_blocks; ++i) {
        sm3_compress_scalar(state, tail + i * 64u);
    }

    for (unsigned i = 0; i < 8u; ++i) {
        sm3_store_be32(out + i * 4u, state[i]);
    }
}
